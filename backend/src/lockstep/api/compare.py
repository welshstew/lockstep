"""Comparing two KV v2 locations, and reading single secrets on demand (Reveal)."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..analyze.detect import badge
from ..diff import SecretDiff, SideInfo, diff_secret, summarize
from ..rules import Rules, pair_paths
from ..session import SessionData, load_session
from ..vault import TreeResult, VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api", tags=["compare"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

READ_CONCURRENCY = 16


class Side(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    prefix: str = ""

    def norm(self) -> tuple[str, str]:
        p = self.prefix.strip("/")
        return self.mount.strip("/"), f"{p}/" if p else ""


class CompareRequest(BaseModel):
    left: Side
    right: Side
    rules: Rules | None = None  # a comparison profile's mappings and ignore rules


class SideSummary(BaseModel):
    conn_id: str
    mount: str
    prefix: str
    denied: list[str]  # folders (relative to the prefix) that couldn't be listed
    truncated: bool
    secret_count: int


class CompareOut(BaseModel):
    left: SideSummary
    right: SideSummary
    secrets: list[SecretDiff]
    summary: dict[str, int]


class SecretOut(BaseModel):
    path: str
    state: str
    version: int | None
    updated: str | None
    data: dict[str, Any] | None


def _hidden(denied: list[str], full_path: str) -> bool:
    return any(full_path.startswith(d) for d in denied)


async def _read_side(v: VaultClient, sem: asyncio.Semaphore, mount: str, full_path: str,
                     listed: bool, tree: TreeResult) -> tuple[SideInfo, dict | None]:
    if not listed:
        if _hidden(tree.denied, full_path):
            return SideInfo(state="no_access"), None
        return SideInfo(state="absent"), None
    try:
        async with sem:
            s = await v.kv_read(mount, full_path)
    except VaultError as e:
        if e.denied:
            return SideInfo(state="no_access"), None
        return SideInfo(state="error", error=e.message), None
    return SideInfo(state=s.state, version=s.version, updated=s.updated), s.data


@router.post("/compare", response_model=CompareOut)
async def compare(body: CompareRequest, session: Sess, settings: Conf):
    lconn = get_connection(session, body.left.conn_id)
    rconn = get_connection(session, body.right.conn_id)
    lmount, lprefix = body.left.norm()
    rmount, rprefix = body.right.norm()

    async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
        try:
            ltree, rtree = await asyncio.gather(
                lv.kv_tree(lmount, lprefix, max_secrets=settings.max_tree_secrets),
                rv.kv_tree(rmount, rprefix, max_secrets=settings.max_tree_secrets))
        except VaultError as e:
            raise vault_http_error(e) from e

        lrel = {s[len(lprefix):] for s in ltree.secrets}
        rrel = {s[len(rprefix):] for s in rtree.secrets}
        rules = body.rules or Rules()
        pairs, collisions, ignored_paths = pair_paths(lrel, rrel, rules)
        lsem, rsem = asyncio.Semaphore(READ_CONCURRENCY), asyncio.Semaphore(READ_CONCURRENCY)

        async def one(key: str) -> SecretDiff:
            lp, rp = pairs[key]
            if key in collisions:
                none = SideInfo(state="error", error="mapping collision")
                d = diff_secret(key, none, None, none, None, left_path=lp, right_path=rp)
                d.note = (f"The mappings send several left paths here ({', '.join(collisions[key])}). "
                          f"Fix the profile so each target has one source.")
                return d
            (li, ld), (ri, rd) = await asyncio.gather(
                _read_side(lv, lsem, lmount, lprefix + lp, lp in lrel, ltree),
                _read_side(rv, rsem, rmount, rprefix + rp, rp in rrel, rtree))
            d = diff_secret(key, li, ld, ri, rd, ignored=lambda k: rules.key_ignored(k, lp, rp),
                            left_path=lp, right_path=rp)
            for name in (kd.key for kd in d.keys):
                lb = badge(ld[name]) if ld and name in ld else None
                rb = badge(rd[name]) if rd and name in rd else None
                if lb or rb:
                    d.badges[name] = {"left": lb, "right": rb}
            return d  # values are dropped once this returns

        diffs = await asyncio.gather(*(one(k) for k in sorted(pairs)))

    def summary(conn_id, mount, prefix, tree):
        return SideSummary(conn_id=conn_id, mount=mount, prefix=prefix.rstrip("/"),
                           denied=[d[len(prefix):] for d in tree.denied], truncated=tree.truncated,
                           secret_count=len(tree.secrets))

    totals = summarize(list(diffs))
    totals["ignored_paths"] = ignored_paths
    totals["ignored_keys"] = sum(d.ignored_keys for d in diffs)
    totals["mapped"] = sum(d.left_path != d.right_path for d in diffs)
    return CompareOut(
        left=summary(lconn.id, lmount, lprefix, ltree),
        right=summary(rconn.id, rmount, rprefix, rtree),
        secrets=list(diffs),
        summary=totals,
    )


MAX_HISTORY_VERSIONS = 25


class KeyChange(BaseModel):
    version: int  # the version in which this key got its current value
    time: str | None
    exact: bool  # False: history ran out (oldest kept, deleted or destroyed), so it's "at least this old"


class HistoryOut(BaseModel):
    path: str
    current_version: int | None
    updated: str | None  # when the current version was written
    keys: dict[str, KeyChange]


@router.get("/connections/{conn_id}/history", response_model=HistoryOut)
async def key_history(conn_id: str, session: Sess, settings: Conf,
                      mount: str = Query(min_length=1), path: str = Query(min_length=1)):
    """When did each key last change? KV v2 only timestamps whole versions, so walk back
    through the versions and find, per key, the oldest version still holding its current
    value. Returns version numbers and times only, never values."""
    conn = get_connection(session, conn_id)
    mount, path = mount.strip("/"), path.strip("/")
    async with client_for(conn, settings) as v:
        try:
            meta = await v.kv_metadata(mount, path)
            cur = await v.kv_read(mount, path)
        except VaultError as e:
            raise vault_http_error(e) from e
        versions = meta.get("versions") or {}
        current = meta.get("current_version") or cur.version
        when = lambda n: (versions.get(str(n)) or {}).get("created_time")  # noqa: E731
        if cur.state != "present" or not current:
            return HistoryOut(path=path, current_version=current, updated=when(current), keys={})

        data = cur.data or {}
        canon = lambda x: json.dumps(x, sort_keys=True)  # noqa: E731
        result = {k: KeyChange(version=current, time=when(current), exact=False) for k in data}
        open_keys = set(data)
        n = current - 1
        oldest = max(1, current - MAX_HISTORY_VERSIONS)
        while open_keys and n >= oldest:
            info = versions.get(str(n)) or {}
            if not info or info.get("deletion_time") or info.get("destroyed"):
                break  # can't see past a missing, deleted or destroyed version
            try:
                older = (await v.kv_read(mount, path, version=n)).data or {}
            except VaultError:
                break
            for k in list(open_keys):
                if k not in older or canon(older[k]) != canon(data[k]):
                    result[k].exact = True  # changed between n and n+1
                    open_keys.discard(k)
                else:
                    result[k] = KeyChange(version=n, time=when(n), exact=False)
            n -= 1
        if n < 1:  # walked back to version 1: unchanged since the secret was created
            for k in open_keys:
                result[k].exact = True
    return HistoryOut(path=path, current_version=current, updated=when(current), keys=result)


@router.get("/connections/{conn_id}/secret", response_model=SecretOut)
async def read_secret(conn_id: str, session: Sess, settings: Conf,
                      mount: str = Query(min_length=1), path: str = Query(min_length=1)):
    """Return the plain values of one secret. The UI calls this only when Reveal is on,
    or when a value tool (base64/cert/PKCS12) needs the raw content."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            s = await v.kv_read(mount.strip("/"), path.strip("/"))
        except VaultError as e:
            raise vault_http_error(e) from e
    if s.state == "absent":
        raise HTTPException(404, detail={"message": f"No secret at {mount}/{path}"})
    return SecretOut(path=path.strip("/"), state=s.state, version=s.version, updated=s.updated, data=s.data)
