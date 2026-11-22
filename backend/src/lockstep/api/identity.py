"""Identity: whose policies are whose. Read-only.

  GET  /api/identity/groups?conn_id=   identity groups with their policies and members
  POST /api/identity/compare-groups    two Vaults' groups compared (policies, type, metadata, members)

and `resolve()`, used by Explain to gather someone else's policies: an entity's own policies and
those of every group it's in (directly or through parent groups), a group's (with its parents'),
or a token's (by accessor, plus its entity's).
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..policy.compare import PolicyProfile
from ..policy.roles import map_name, rewrite
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api/identity", tags=["identity"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
MAX_GROUPS = 500


class IdentityRef(BaseModel):
    kind: Literal["entity", "group", "token"]  # token: by accessor
    name: str = Field(min_length=1, max_length=512)


async def _get(v: VaultClient, path: str, missing: list[str], method: str = "GET", json: dict | None = None) -> dict | None:
    try:
        return (await v.request(method, path, json=json)).get("data")
    except VaultError as e:
        if e.denied:
            missing.append(f"{'update' if method == 'POST' else 'read'} on {path.rsplit('/', 1)[0] if '/id/' in path else path}")
            return None
        if e.status == 404:
            return None
        raise


async def _group_policies(v: VaultClient, group_ids: list[str], missing: list[str]) -> tuple[list[str], list[str]]:
    """Policies of these groups and their parents, and the groups' names."""
    seen: set[str] = set()
    policies: list[str] = []
    names: list[str] = []
    todo = list(group_ids)
    while todo:
        gid = todo.pop()
        if gid in seen:
            continue
        seen.add(gid)
        g = await _get(v, f"identity/group/id/{gid}", missing)
        if not g:
            continue
        names.append(g.get("name") or gid)
        policies += g.get("policies") or []
        todo += g.get("parent_group_ids") or []
    return policies, names


async def resolve(v: VaultClient, ref: IdentityRef) -> dict:
    """Someone's policies: {"policies", "from": [(source, names)], "missing", "found"}."""
    missing: list[str] = []
    sources: list[dict] = []
    policies: list[str] = []
    found = True
    if ref.kind == "token":
        t = await _get(v, "auth/token/lookup-accessor", missing, "POST", {"accessor": ref.name.strip()})
        if t is None:
            return {"policies": [], "sources": [], "missing": missing or ["a token with that accessor"], "found": False,
                    "label": ref.name}
        sources.append({"from": f"token ({t.get('display_name') or 'no name'})", "policies": t.get("policies") or []})
        policies += t.get("policies") or []
        entity_id = t.get("entity_id")
        label = t.get("display_name") or ref.name
        if entity_id:
            e = await _get(v, f"identity/entity/id/{entity_id}", missing)
            if e:
                sources.append({"from": f"entity {e.get('name')}", "policies": e.get("policies") or []})
                policies += e.get("policies") or []
                gp, gn = await _group_policies(v, e.get("group_ids") or e.get("direct_group_ids") or [], missing)
                if gn:
                    sources.append({"from": f"groups {', '.join(gn)}", "policies": gp})
                policies += gp
    elif ref.kind == "entity":
        e = await _get(v, f"identity/entity/name/{ref.name}", missing)
        found, label = e is not None, ref.name
        if e:
            sources.append({"from": f"entity {e.get('name')}", "policies": e.get("policies") or []})
            policies += e.get("policies") or []
            gp, gn = await _group_policies(v, e.get("group_ids") or e.get("direct_group_ids") or [], missing)
            if gn:
                sources.append({"from": f"groups {', '.join(gn)}", "policies": gp})
            policies += gp
            # Tokens from logins also carry their auth role's policies, which depend on how they log in
            sources.append({"from": "note", "policies": [],
                            "note": "Logins also get their auth role's policies (and usually default), which depend on how they sign in."})
    else:
        g = await _get(v, f"identity/group/name/{ref.name}", missing)
        found, label = g is not None, ref.name
        if g:
            policies += g.get("policies") or []
            sources.append({"from": f"group {g.get('name')}", "policies": g.get("policies") or []})
            gp, gn = await _group_policies(v, g.get("parent_group_ids") or [], missing)
            if gn:
                sources.append({"from": f"parent groups {', '.join(gn)}", "policies": gp})
            policies += gp
    return {"policies": [p for p in dict.fromkeys(policies) if p != "root"], "root": "root" in policies,
            "sources": sources, "missing": list(dict.fromkeys(missing)), "found": found, "label": label}


async def read_groups(v: VaultClient) -> tuple[dict[str, dict], list[str]]:
    missing: list[str] = []
    try:
        names = ((await v.request("LIST", "identity/group/name")).get("data") or {}).get("keys") or []
    except VaultError as e:
        if e.status == 404:
            return {}, []
        if e.denied:
            return {}, ["list on identity/group/name"]
        raise
    sem = asyncio.Semaphore(16)
    groups: dict[str, dict] = {}
    entity_names: dict[str, str] = {}

    async def entity_name(eid: str) -> str:
        if eid not in entity_names:
            e = await _get(v, f"identity/entity/id/{eid}", missing)
            entity_names[eid] = (e or {}).get("name") or eid
        return entity_names[eid]

    async def one(n: str):
        async with sem:
            g = await _get(v, f"identity/group/name/{n}", missing)
            if not g:
                return
            members = sorted([await entity_name(e) for e in g.get("member_entity_ids") or []])
            alias = g.get("alias") or {}
            groups[n] = {k: x for k, x in {
                "type": g.get("type"), "policies": sorted(g.get("policies") or []),
                "metadata": g.get("metadata") or None, "members": members or None,
                "member_groups": len(g.get("member_group_ids") or []) or None,
                "alias": alias.get("name") or None,
            }.items() if x not in (None, [], {})}
    await asyncio.gather(*(one(n) for n in names[:MAX_GROUPS]))
    return groups, list(dict.fromkeys(missing))


@router.get("/groups")
async def groups(session: Sess, settings: Conf, conn_id: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            gs, missing = await read_groups(v)
        except VaultError as e:
            raise vault_http_error(e) from e
    return {"groups": [{"name": n, **g} for n, g in sorted(gs.items())], "missing": missing}


class CompareGroups(BaseModel):
    left: str
    right: str
    profile: PolicyProfile | None = None


@router.post("/compare-groups")
async def compare_groups(body: CompareGroups, session: Sess, settings: Conf):
    out = {}
    for side, cid in (("left", body.left), ("right", body.right)):
        async with client_for(get_connection(session, cid), settings) as v:
            try:
                out[side] = await read_groups(v)
            except VaultError as e:
                raise vault_http_error(e) from e
    (left, lmiss), (right, rmiss) = out["left"], out["right"]
    pairs, taken = [], set()
    for n in sorted(left):
        target = map_name(n, body.profile)
        rn = target if target in right else (n if target is None and n in right else None)
        if rn:
            taken.add(rn)
        a = {k: rewrite(x, body.profile) for k, x in left[n].items()}
        b = right.get(rn) if rn else None
        fields = [{"field": k, "left": left[n].get(k), "right": b.get(k)} for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)] if b is not None else []
        pairs.append({"left": n, "right": rn, "status": "left_only" if b is None else "different" if fields else "equal",
                      "fields": fields})
    pairs += [{"left": None, "right": n, "status": "right_only", "fields": []} for n in sorted(right) if n not in taken]
    return {"pairs": pairs, "summary": {s: sum(p["status"] == s for p in pairs) for s in ("equal", "different", "left_only", "right_only")},
            "missing": {"left": lmiss, "right": rmiss}}
