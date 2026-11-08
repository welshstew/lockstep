"""Value tools: identify and analyse one key's value, and serve its decoded content.

The server reads the value from Vault itself (like Reveal); the browser never sends
secret values back. Keystore passwords are used for this request only, never stored or logged.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..analyze import certs
from ..analyze.detect import Analysis, Node, analyze
from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultError
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api/analyze", tags=["analyze"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

PASSWORD_HINT = re.compile(r"pass|pwd|pin|secret", re.I)
MAX_SIBLING_BYTES = 1024 * 1024


class Locator(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    path: str = Field(min_length=1)
    key: str = Field(min_length=1)


class AnalyzeRequest(Locator):
    password: str | None = None  # typed by the user
    password_key: str | None = None  # or: take it from this key in the same secret
    trust: list[Locator] = Field(default_factory=list, max_length=20)  # extra trust anchors
    # Trust specific certificates seen in this value or its secret ("Trust this root"), by SHA-256
    trust_sha256: list[str] = Field(default_factory=list, max_length=20)
    system_roots: bool = True


class ContentRequest(AnalyzeRequest):
    node_id: str = Field(min_length=1)


class AnalyzeOut(BaseModel):
    root: dict[str, Any]
    password_used: bool
    password_suggestions: list[str]
    siblings: list[dict[str, Any]]  # other keys in the secret that contributed certificates
    trust_anchors: dict[str, int]


async def _read(loc: Locator, session: SessionData, settings: Settings) -> dict:
    conn = get_connection(session, loc.conn_id)
    async with client_for(conn, settings) as v:
        try:
            s = await v.kv_read(loc.mount.strip("/"), loc.path.strip("/"))
        except VaultError as e:
            raise vault_http_error(e) from e
    if s.state != "present" or not s.data:
        raise HTTPException(404, detail={"message": f"No current data at {loc.mount}/{loc.path}"})
    return s.data


def _value(data: dict, key: str) -> Any:
    if key not in data:
        raise HTTPException(404, detail={"message": f"Key '{key}' not found"})
    return data[key]


def _password(req: AnalyzeRequest, data: dict) -> str | None:
    if req.password is not None:
        return req.password
    if req.password_key:
        pw = data.get(req.password_key)
        if not isinstance(pw, str):
            raise HTTPException(400, detail={"message": f"'{req.password_key}' isn't a text value in this secret"})
        return pw
    return None


def _find(node: Node, nid: str) -> Node | None:
    if node.id == nid:
        return node
    for c in node.children:
        if (hit := _find(c, nid)) is not None:
            return hit
    return None


async def run(req: AnalyzeRequest, session: SessionData, settings: Settings) -> tuple[Analysis, dict, AnalyzeOut]:
    data = await _read(req, session, settings)
    value = _value(data, req.key)
    a = analyze(value, _password(req, data))

    # Certificates in sibling keys: intermediates for chain building, and key ↔ cert matching.
    sibling_certs: list[tuple[str, Any]] = []
    siblings = []
    for k, v in data.items():
        if k == req.key or not isinstance(v, str) or len(v) > MAX_SIBLING_BYTES:
            continue
        try:
            sa = analyze(v)
        except Exception:  # noqa: BLE001
            continue
        if sa.certificates:
            sibling_certs += [(k, c) for _, c in sa.certificates]
            siblings.append({"key": k, "certificates": len(sa.certificates)})

    anchors = list(certs.system_roots()) if req.system_roots else []
    explicit = []
    for loc in req.trust:
        try:
            tv = _value(await _read(loc, session, settings), loc.key)
            explicit += [c for _, c in analyze(tv).certificates]
        except HTTPException:
            continue
    anchors += explicit

    own = [c for _, c in a.certificates]
    pool = own + [c for _, c in sibling_certs]
    wanted = {f.lower() for f in req.trust_sha256}
    picked = [c for c in pool if certs.fingerprint(c) in wanted]
    anchors += picked
    explicit += picked
    for nid, cert in a.certificates:
        node = _find(a.root, nid)
        if node is not None:
            node.details["chain"] = certs.chain(cert, pool, anchors)

    for nid, key in a.private_keys:
        node = _find(a.root, nid)
        if node is None:
            continue
        mine = certs.spki(key.public_key())
        node.details["matches"] = (
            [_find(a.root, cid).label for cid, c in a.certificates if certs.spki(c.public_key()) == mine]
            + [f"certificate in key '{k}'" for k, c in sibling_certs if certs.spki(c.public_key()) == mine])

    suggestions = [k for k, v in data.items()
                   if k != req.key and isinstance(v, str) and len(v) < 256 and PASSWORD_HINT.search(k)]
    out = AnalyzeOut(root=a.root.to_dict(), password_used=a.password_used, password_suggestions=suggestions,
                     siblings=siblings,
                     trust_anchors={"system": len(anchors) - len(explicit), "selected": len(explicit)})
    return a, data, out


@router.post("", response_model=AnalyzeOut)
async def analyze_value(body: AnalyzeRequest, session: Sess, settings: Conf):
    return (await run(body, session, settings))[2]


@router.post("/content")
async def content(body: ContentRequest, session: Sess, settings: Conf):
    """Raw bytes of one node, for download or image preview."""
    data = await _read(body, session, settings)
    a = analyze(_value(data, body.key), _password(body, data))
    node = _find(a.root, body.node_id)
    blob = a.blobs.get(body.node_id)
    if node is None or blob is None or not node.downloadable:
        raise HTTPException(404, detail={"message": "Nothing to download for that part of the value"})
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", body.key).strip("._") or "value"
    name = base if base.lower().endswith("." + node.ext) else f"{base}.{node.ext}"
    return Response(blob, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "X-Filename": name,
        "X-Mime": node.mime,
        "X-Content-Type-Options": "nosniff",
        "Access-Control-Expose-Headers": "X-Filename, X-Mime",
    })
