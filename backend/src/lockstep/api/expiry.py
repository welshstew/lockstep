"""Certificate expiry dashboard: every certificate stored in a mount (or two), by expiry.

Values are read and analysed on the server; only certificate metadata is returned (subject,
issuer, dates, where it lives), never secret values. Keystores that need a password are
opened with a password stored in a sibling key of the same secret (names like *pass*, *pwd*),
or else with the best candidates the password finder ranks from the rest of the scanned tree
(see analyze/passwords.py). The user can already read those keys; the result says which was used.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import AsyncIterator
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from cryptography import x509

from ..analyze import certs, passwords
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
    opened_with: str | None = None  # the key ("path · key" if in another secret) whose value opened the keystore
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


_needs_password = passwords.needs_password


def _find(node: Node, nid: str) -> Node | None:
    if node.id == nid:
        return node
    for c in node.children:
        if (hit := _find(c, nid)) is not None:
            return hit
    return None


FINDER_TRIES = 10  # candidates from elsewhere in the scanned tree, per locked keystore


def scan_value(value: str, siblings: dict[str, str],
               elsewhere: list[passwords.Candidate] = ()) -> tuple[Analysis, str | None]:
    """Analyse a value; if it's a locked keystore, try passwords from sibling keys, then the
    best candidates the password finder ranked from the rest of the scanned tree."""
    a = analyze(value)
    if _needs_password(a.root):
        tries = [(k, pw) for k, pw in siblings.items()] + [(c.label, c.value) for c in elsewhere[:FINDER_TRIES]]
        for label, pw in tries:
            try:
                b = analyze(value, password=pw)
            except Exception:  # noqa: BLE001
                continue
            if b.password_used and not _needs_password(b.root):
                return b, label
    return a, None


HEARTBEAT = 5.0  # seconds: the longest a streamed scan goes without sending a line
PROGRESS_EVERY = 0.5


async def _waiting(task: asyncio.Task, beat: dict) -> AsyncIterator[dict]:
    """Yield `beat` every HEARTBEAT seconds until the task is done."""
    while True:
        done, _ = await asyncio.wait({task}, timeout=HEARTBEAT)
        if done:
            return
        yield beat


async def scan(body: ExpiryRequest, session: SessionData, settings: Settings) -> AsyncIterator[dict]:
    """The scan, as a stream of events: {"progress": {...}} now and then, {"result": ExpiryOut} last.
    Vault errors are raised (as HTTPException) wherever they happen."""
    rows: list[CertRow] = []
    locked: list[LockedRow] = []
    stats: list[SideStats] = []
    conns = [get_connection(session, s.conn_id) for s in body.sides]  # fail fast, before any output

    for s, conn in zip(body.sides, conns):
        mount = s.mount.strip("/")
        prefix = s.prefix.strip("/")
        prefix = f"{prefix}/" if prefix else ""

        def progress(stage: str, done: int = 0, total: int = 0) -> dict:
            return {"progress": {"side": s.side, "stage": stage, "done": done, "total": total,
                                 "certificates": len(rows)}}

        async with client_for(conn, settings) as v:
            listing = asyncio.create_task(v.kv_tree(mount, prefix, max_secrets=settings.max_tree_secrets))
            try:
                yield progress("listing")
                async for beat in _waiting(listing, progress("listing")):
                    yield beat
                tree = listing.result()
            except VaultError as e:
                raise vault_http_error(e) from e
            finally:
                listing.cancel()  # if the client went away mid-listing
            sem = asyncio.Semaphore(READS)

            async def read(path: str):
                async with sem:
                    try:
                        sec = await v.kv_read(mount, path)
                        return path, (sec.data if sec.state == "present" else {}), None
                    except VaultError as e:
                        return path, None, e

            total = len(tree.secrets)
            results = []
            last = time.monotonic()
            for fut in asyncio.as_completed([read(p) for p in tree.secrets]):
                results.append(await fut)
                if time.monotonic() - last > PROGRESS_EVERY:
                    last = time.monotonic()
                    yield progress("reading", len(results), total)
            order = {p: i for i, p in enumerate(tree.secrets)}
            results.sort(key=lambda r: order[r[0]])

        tree_data = {p: d for p, d, err in results if err is None and d}
        n_values = unreadable = 0
        for i, (path, data, err) in enumerate(results):
            if time.monotonic() - last > PROGRESS_EVERY:
                last = time.monotonic()
                yield progress("scanning", i, total)
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
                    sib = {k: p for k, p in siblings.items() if k != key}
                    a, used = await asyncio.to_thread(scan_value, value, sib)
                    if used is None and _needs_password(a.root):
                        root = passwords.search_root(path)  # same area the inspector's finder searches
                        near = {p: d for p, d in tree_data.items() if p.startswith(root)}
                        far = [c for c in passwords.rank(path, key, near) if c.path != path]
                        a, used = await asyncio.to_thread(scan_value, value, {}, far)
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
                              if a.certificates else "needs a password; no nearby password key opened it")
                    locked.append(LockedRow(side=s.side, path=path, key=key, container=container.label, reason=reason))
        stats.append(SideStats(side=s.side, mount=mount, prefix=prefix.rstrip("/"), secrets=len(tree.secrets),
                               values=n_values, denied=tree.denied, truncated=tree.truncated, unreadable=unreadable))

        yield progress("done", total, total)

    rows.sort(key=lambda r: (r.not_after, r.side, r.path, r.key))
    yield {"result": ExpiryOut(certificates=rows, locked=locked, sides=stats)}


@router.post("/expiry", response_model=ExpiryOut)
async def expiry(body: ExpiryRequest, session: Sess, settings: Conf):
    async for event in scan(body, session, settings):
        if "result" in event:
            return event["result"]
    raise HTTPException(500, detail={"message": "The scan ended without a result."})


@router.post("/expiry/stream")
async def expiry_stream(body: ExpiryRequest, session: Sess, settings: Conf):
    """The same scan, streamed as NDJSON: progress lines, then {"result": ...} or {"error": ...}.
    A big scan can take minutes; a steady trickle of lines keeps proxies from timing it out."""
    events = scan(body, session, settings)
    first = await anext(events)  # connection errors become a normal HTTP error, not a stream

    async def lines():
        event = first
        while True:
            if "result" in event:
                yield json.dumps({"result": event["result"].model_dump(mode="json")}) + "\n"
                return
            yield json.dumps(event) + "\n"
            try:
                event = await anext(events)
            except HTTPException as e:
                detail = e.detail if isinstance(e.detail, dict) else {"message": str(e.detail)}
                yield json.dumps({"error": {"status": e.status_code, **detail}}) + "\n"
                return
            except StopAsyncIteration:
                return

    return StreamingResponse(lines(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
