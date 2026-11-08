"""Certificate expiry dashboard: every certificate stored in a mount (or two), by expiry.

Values are read and analysed on the server; only certificate metadata is returned (subject,
issuer, dates, where it lives), never secret values. Keystores that need a password are
opened only with a password stored in a sibling key of the same secret (names like
*pass*, *pwd*), which the user can already read; the result says which key was used.
"""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from cryptography import x509

from ..analyze import certs
from ..analyze.detect import Analysis, Node, analyze
from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultError
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api", tags=["expiry"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

PASSWORD_HINT = re.compile(r"pass|pwd|pin|secret", re.I)
MAX_VALUE = 1024 * 1024
READS = 16
LOCKED_KINDS = {"pkcs12", "jks", "jceks", "encrypted_private_key"}


class ScanSide(BaseModel):
    side: Literal["left", "right"]
    conn_id: str
    mount: str = Field(min_length=1)
    prefix: str = ""


class ExpiryRequest(BaseModel):
    sides: list[ScanSide] = Field(min_length=1, max_length=2)


class CertRow(BaseModel):
    side: Literal["left", "right"]
    conn_id: str
    mount: str
    path: str  # full path within the mount
    key: str
    container: str  # e.g. "PEM (2 blocks)", "PKCS#12 keystore", "Java keystore (JKS)"
    opened_with: str | None = None  # sibling key whose value opened the keystore
    alias: str | None = None
    subject: str
    subject_cn: str
    issuer_cn: str
    not_before: str
    not_after: str
    days_left: int
    status: str  # valid | expiring | expired | not_yet_valid
    is_ca: bool
    self_signed: bool
    serial: str
    sha256: str


class LockedRow(BaseModel):
    side: Literal["left", "right"]
    path: str
    key: str
    container: str
    reason: str


class SideStats(BaseModel):
    side: Literal["left", "right"]
    mount: str
    prefix: str
    secrets: int
    values: int
    denied: list[str]
    truncated: bool
    unreadable: int  # secrets that couldn't be read (permissions)


class ExpiryOut(BaseModel):
    certificates: list[CertRow]
    locked: list[LockedRow]
    sides: list[SideStats]


def _cn(name: x509.Name) -> str:
    cn = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(cn[0].value) if cn else name.rfc4514_string()


def _container(a: Analysis) -> Node:
    node = a.root
    while node.kind == "base64" and node.children:
        node = node.children[0]
    return node


def _needs_password(node: Node) -> bool:
    return (node.kind in LOCKED_KINDS and node.needs_password) or any(_needs_password(c) for c in node.children)


def _find(node: Node, nid: str) -> Node | None:
    if node.id == nid:
        return node
    for c in node.children:
        if (hit := _find(c, nid)) is not None:
            return hit
    return None


def scan_value(value: str, siblings: dict[str, str]) -> tuple[Analysis, str | None]:
    """Analyse a value; if it's a locked keystore, try passwords from sibling keys."""
    a = analyze(value)
    if _needs_password(a.root):
        for k, pw in siblings.items():
            try:
                b = analyze(value, password=pw)
            except Exception:  # noqa: BLE001
                continue
            if b.password_used and not _needs_password(b.root):
                return b, k
    return a, None


@router.post("/expiry", response_model=ExpiryOut)
async def expiry(body: ExpiryRequest, session: Sess, settings: Conf):
    rows: list[CertRow] = []
    locked: list[LockedRow] = []
    stats: list[SideStats] = []

    for s in body.sides:
        conn = get_connection(session, s.conn_id)
        mount = s.mount.strip("/")
        prefix = s.prefix.strip("/")
        prefix = f"{prefix}/" if prefix else ""
        async with client_for(conn, settings) as v:
            try:
                tree = await v.kv_tree(mount, prefix, max_secrets=settings.max_tree_secrets)
            except VaultError as e:
                raise vault_http_error(e) from e
            sem = asyncio.Semaphore(READS)

            async def read(path: str):
                async with sem:
                    try:
                        sec = await v.kv_read(mount, path)
                        return path, (sec.data if sec.state == "present" else {}), None
                    except VaultError as e:
                        return path, None, e

            results = await asyncio.gather(*(read(p) for p in tree.secrets))

        n_values = unreadable = 0
        for path, data, err in results:
            if err is not None:
                unreadable += 1
                continue
            data = data or {}
            siblings = {k: v for k, v in data.items()
                        if isinstance(v, str) and len(v) < 256 and PASSWORD_HINT.search(k)}
            for key, value in data.items():
                if not isinstance(value, str) or len(value) > MAX_VALUE or len(value) < 16:
                    continue
                n_values += 1
                try:
                    a, used = await asyncio.to_thread(scan_value, value, {k: p for k, p in siblings.items() if k != key})
                except Exception:  # noqa: BLE001 (one odd value must not break the scan)
                    continue
                container = _container(a)
                for nid, cert in a.certificates:
                    node = _find(a.root, nid)
                    st, days = certs.validity(cert)
                    rows.append(CertRow(
                        side=s.side, conn_id=conn.id, mount=mount, path=path, key=key,
                        container=container.label, opened_with=used,
                        alias=(node.details.get("alias") if node else None),
                        subject=cert.subject.rfc4514_string(), subject_cn=_cn(cert.subject), issuer_cn=_cn(cert.issuer),
                        not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat(),
                        days_left=days, status=st, is_ca=certs.is_ca(cert), self_signed=certs.is_self_signed(cert),
                        serial=format(cert.serial_number, "x"), sha256=certs.fingerprint(cert)))
                if _needs_password(a.root):
                    reason = ("certificates listed, but the keystore's integrity couldn't be checked without a password"
                              if a.certificates else "needs a password; no sibling key opened it")
                    locked.append(LockedRow(side=s.side, path=path, key=key, container=container.label, reason=reason))
        stats.append(SideStats(side=s.side, mount=mount, prefix=prefix.rstrip("/"), secrets=len(tree.secrets),
                               values=n_values, denied=tree.denied, truncated=tree.truncated, unreadable=unreadable))

    rows.sort(key=lambda r: (r.not_after, r.side, r.path, r.key))
    return ExpiryOut(certificates=rows, locked=locked, sides=stats)
