"""Explaining Vault ACL policies on a KV v2 mount (read-only).

  GET  /api/policies?conn_id=…          policy names the token may list
  GET  /api/policies/{name}?conn_id=…   one policy's text
  POST /api/policies/explain            what a set of policies allows on each secret of a mount
  GET  /api/policies/profiles           shared policy profiles (LOCKSTEP_POLICY_PROFILES)
  GET  /api/policies/patterns           shared suggestion patterns (LOCKSTEP_POLICY_PATTERNS)
  POST /api/policies/compare            every policy on two Vaults, compared by meaning
  POST /api/policies/compare-access     two policies' effect on two mounts, secret by secret
  POST /api/policies/build              HCL from plain rules ("who can do what, where")
  POST /api/policies/suggest            policies suggested from a mount's layout (or a user's pattern)
  POST /api/policies/bundle             a zip for an admin: HCL, apply.sh, optional Terraform/OpenTofu

Nothing here writes to Vault or reads secret values: only policy texts, the tree of names,
and (for the signed-in token, when its policies can't be read) sys/capabilities-self.
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Literal

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError

from ..config import Settings, get_settings
from ..policy.build import Rule, build_hcl
from ..policy.bundle import BundlePolicy, TerraformOptions, build_bundle
from ..policy.roles import RoleSpec
from .identity import IdentityRef, resolve
from ..policy.acl import behaviour_for
from ..policy.compare import PolicyProfile, compare_texts, pair_names, summary
from ..policy.suggest import SuggestPattern, Suggestion, apply_pattern, compare_profile, detect
from ..policy.explain import COLUMNS, explain, request_path
from ..policy.hcl import Policy, PolicyParseError, parse_policy
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api/policies", tags=["policies"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

MAX_TEXT = 256 * 1024
CAPS_BATCH = 400


class PastedPolicy(BaseModel):
    name: str = Field(default="pasted", min_length=1, max_length=128)
    text: str = Field(max_length=MAX_TEXT)


class ExplainRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    prefix: str = ""
    names: list[str] = Field(default=[], max_length=50)  # policies to read from Vault
    pasted: list[PastedPolicy] = Field(default=[], max_length=10)
    token: Literal["self"] | None = None  # also: the signed-in token's own policies
    identity: IdentityRef | None = None  # also: someone else's (an entity, a group, or a token by accessor)


class PolicySource(BaseModel):
    name: str
    origin: Literal["vault", "pasted", "token", "identity"]
    rules: int = 0
    error: str | None = None  # couldn't be read or parsed: left out of the matrix


class ExplainOut(BaseModel):
    mount: str
    prefix: str
    policies: list[PolicySource]
    missing: list[str]  # rights the signed-in token lacks, in plain words
    complete: bool  # False: some policies couldn't be read, so the answer may be incomplete
    mode: Literal["policies", "vault"]  # "vault": cells come from Vault itself (sys/capabilities-self)
    root: bool
    vault_version: str | None = None  # the Vault's version, which decides some matching details
    evaluation: str = ""  # which evaluation rules were used
    columns: list[dict]
    rules: list[dict]
    rows: list[dict]
    findings: list[dict]
    denied: list[str]  # folders the signed-in token couldn't list
    truncated: bool
    identity: dict | None = None  # whose policies these are, and where each came from


@router.get("")
async def list_policies(session: Sess, settings: Conf, conn_id: str = Query()):
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            return {"names": await v.policy_names()}
        except VaultError as e:
            if e.denied:
                raise HTTPException(403, detail={"message": "This token can't list policies (needs list on sys/policies/acl). "
                                                            "Type policy names instead."}) from e
            raise vault_http_error(e) from e


@router.get("/patterns")
def shared_patterns(settings: Conf):
    """Shared suggestion patterns, as YAML to load into the pattern editor."""
    return [{"name": p.name, "yaml": yaml.safe_dump(p.model_dump(exclude_defaults=True) | {"name": p.name},
                                                    sort_keys=False, allow_unicode=True)}
            for p in settings.policy_patterns]


@router.get("/profiles", response_model=list[PolicyProfile])
def shared_profiles(settings: Conf):
    return settings.policy_profiles


# --------------------------------------------------------------------------- compare


class CompareRequest(BaseModel):
    left: str  # connection ids
    right: str
    profile: PolicyProfile | None = None


class SidePolicies(BaseModel):
    count: int = 0
    error: str | None = None  # couldn't list policies at all


class PolicyPair(BaseModel):
    left: str | None
    right: str | None
    status: Literal["equal", "different", "left_only", "right_only", "error"]
    mapped: bool  # paired by the profile's name mapping
    formatting: bool  # equal in meaning, but the texts differ
    note: str
    rules: list[dict]
    left_text: str | None = None
    right_text: str | None = None


class CompareOut(BaseModel):
    left: SidePolicies
    right: SidePolicies
    pairs: list[PolicyPair]
    summary: dict[str, int]
    missing: list[str]


async def _read_all(v: VaultClient, side: str, missing: list[str]) -> tuple[dict[str, str | None], dict[str, str], SidePolicies]:
    """Every policy's text on one side. Unreadable ones map to None with the reason in errors."""
    try:
        names = await v.policy_names()
    except VaultError as e:
        if e.denied:
            missing.append(f"{side}: list on sys/policies/acl")
            return {}, {}, SidePolicies(error="can't list policies (needs list on sys/policies/acl)")
        return {}, {}, SidePolicies(error=e.message)
    sem = asyncio.Semaphore(16)
    errors: dict[str, str] = {}

    async def one(n: str) -> str | None:
        async with sem:
            try:
                return await v.policy_text(n)
            except VaultError as e:
                errors[n] = "can't read it" if e.denied else e.message
                if e.denied:
                    missing.append(f"{side}: read on sys/policies/acl/{n}")
                return None

    texts = await asyncio.gather(*(one(n) for n in names))
    return dict(zip(names, texts)), errors, SidePolicies(count=len(names))


async def run_compare(lv: VaultClient, rv: VaultClient, profile: PolicyProfile | None) -> dict:
    """Read every policy on both sides, pair them and compare. Used by the API and the CLI."""
    missing: list[str] = []
    (ltexts, lerr, lside), (rtexts, rerr, rside) = await asyncio.gather(
        _read_all(lv, "left", missing), _read_all(rv, "right", missing))
    pairs = []
    for ln, rn, mapped, note in pair_names(list(ltexts), list(rtexts), profile):
        if (ln and ln in lerr) or (rn and rn in rerr):
            why = "; ".join(f"{side} {n}: {err[n]}" for side, n, err in (("left", ln, lerr), ("right", rn, rerr))
                            if n and n in err)
            pairs.append(PolicyPair(left=ln, right=rn, status="error", mapped=mapped, formatting=False,
                                    note=why, rules=[]))
            continue
        lt, rt = ltexts.get(ln) if ln else None, rtexts.get(rn) if rn else None
        res = compare_texts(lt, rt, profile.rewrites if profile else None, (ln or "left", rn or "right"))
        pairs.append(PolicyPair(left=ln, right=rn, mapped=mapped, left_text=lt, right_text=rt,
                                **(res | {"note": "; ".join(x for x in (note, res["note"]) if x)})))
    return dict(left=lside, right=rside, pairs=pairs, summary=summary([p.model_dump() for p in pairs]),
                missing=missing)


@router.post("/compare", response_model=CompareOut)
async def compare_policies(body: CompareRequest, session: Sess, settings: Conf):
    lconn, rconn = get_connection(session, body.left), get_connection(session, body.right)
    async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
        try:
            return CompareOut(**await run_compare(lv, rv, body.profile))
        except VaultError as e:
            raise vault_http_error(e) from e


class AccessSide(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    prefix: str = ""
    name: str | None = None  # a policy in that Vault
    text: str | None = Field(default=None, max_length=MAX_TEXT)  # or a policy's text


@router.post("/compare-access")
async def compare_access(left: AccessSide, right: AccessSide, session: Sess, settings: Conf):
    """Each side's policy explained on its own mount, joined by path relative to each prefix."""
    out = {}
    for side, s in (("left", left), ("right", right)):
        if not (s.name or s.text):
            raise HTTPException(400, detail={"message": f"{side}: name a policy or give its text"})
        conn = get_connection(session, s.conn_id)
        async with client_for(conn, settings) as v:
            try:
                out[side] = await run_explain(
                    v, s.mount, s.prefix, names=[s.name] if s.name and s.text is None else [],
                    pasted=[PastedPolicy(name=s.name or "policy", text=s.text)] if s.text is not None else [],
                    token=False, max_secrets=settings.max_tree_secrets)
            except ExplainError as e:
                raise HTTPException(e.status, detail={"message": f"{side}: {e.message}"}) from e
            except VaultError as e:
                raise vault_http_error(e) from e
    rows: dict[str, dict] = {}
    for side in ("left", "right"):
        res = out[side]
        cut = len(res["prefix"]) + 1 if res["prefix"] else 0
        for r in res["rows"]:
            rel = r["path"][cut:]
            rows.setdefault(rel, {"path": rel, "left": None, "right": None})[side] = {
                c: {"ok": v["ok"], "deny": v["deny"]} for c, v in r["cells"].items()}
    for r in rows.values():
        r["differs"] = (r["left"] is None or r["right"] is None
                        or any(r["left"][c]["ok"] != r["right"][c]["ok"] for c in r["left"]))
    return {"columns": out["left"]["columns"], "rows": sorted(rows.values(), key=lambda r: r["path"]),
            "left": {k: out["left"][k] for k in ("mount", "prefix", "policies", "missing", "denied", "truncated")},
            "right": {k: out["right"][k] for k in ("mount", "prefix", "policies", "missing", "denied", "truncated")}}


# --------------------------------------------------------------------------- build, suggest, bundle


class BuildRequest(BaseModel):
    mount: str = Field(min_length=1)
    name: str = Field(default="", max_length=128)
    rules: list[Rule] = Field(min_length=1, max_length=200)


@router.post("/build")
def build_policy(body: BuildRequest):
    from ..policy.explain import lint
    hcl = build_hcl(body.mount, body.rules, name=body.name)
    return {"hcl": hcl, "findings": [f.out() for f in lint([parse_policy(hcl, body.name or "policy")], body.mount.strip("/"))]}


class SuggestRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    prefix: str = ""
    pattern: str | None = Field(default=None, max_length=64 * 1024)  # a suggestion pattern, YAML or JSON


class SuggestOut(BaseModel):
    layout: str
    why: list[str]
    notes: list[str]
    secrets: int
    truncated: bool
    suggestions: list[Suggestion]
    profile: PolicyProfile | None
    pattern_yaml: str  # the pattern used, to edit and send back


def parse_pattern(text: str) -> SuggestPattern:
    try:
        raw = yaml.safe_load(text)
        return SuggestPattern.model_validate(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"isn't valid YAML or JSON: {e}") from e
    except ValidationError as e:
        err = e.errors()[0]
        raise ValueError(f"{'.'.join(map(str, err['loc']))}: {err['msg']}") from e


async def run_suggest(v: VaultClient, mount: str, prefix: str, pattern_text: str | None, max_secrets: int) -> dict:
    mount, prefix = mount.strip("/"), prefix.strip("/")
    tree = await v.kv_tree(mount, prefix, max_secrets=max_secrets)
    cut = len(prefix) + 1 if prefix else 0
    rel = [s[cut:] for s in tree.secrets]
    if pattern_text:
        pattern, why = parse_pattern(pattern_text), ["Using your pattern."]
    else:
        pattern, why = detect(rel)
    suggestions, notes = apply_pattern(pattern, rel, mount, prefix)
    dumped = pattern.model_dump(exclude_defaults=True)
    dumped = {"name": pattern.name, **{k: x for k, x in dumped.items() if k != "name"}}
    return dict(layout=pattern.layout, why=why, notes=notes, secrets=len(rel), truncated=tree.truncated,
                suggestions=suggestions, profile=compare_profile(pattern),
                pattern_yaml=yaml.safe_dump(dumped, sort_keys=False, allow_unicode=True))


@router.post("/suggest", response_model=SuggestOut)
async def suggest_policies(body: SuggestRequest, session: Sess, settings: Conf):
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            return SuggestOut(**await run_suggest(v, body.mount, body.prefix, body.pattern, settings.max_tree_secrets))
        except ValueError as e:
            raise HTTPException(400, detail={"message": f"The pattern {e}"}) from e
        except VaultError as e:
            raise vault_http_error(e) from e


class BundleRequest(BaseModel):
    policies: list[BundlePolicy] = Field(default=[], max_length=200)
    roles: list[RoleSpec] = Field(default=[], max_length=200)  # Kubernetes and JWT/OIDC roles
    terraform: TerraformOptions | None = None
    conn_id: str | None = None  # look up which policies and roles exist already (import blocks, README)


@router.post("/bundle")
async def bundle(body: BundleRequest, session: Sess, settings: Conf):
    if not body.policies and not body.roles:
        raise HTTPException(400, detail={"message": "Nothing to bundle"})
    names = [p.name for p in body.policies]
    if len(set(names)) != len(names):
        raise HTTPException(400, detail={"message": "Two policies have the same name"})
    keys = [(r.mount.strip("/"), r.name) for r in body.roles]
    if len(set(keys)) != len(keys):
        raise HTTPException(400, detail={"message": "Two roles have the same mount and name"})
    for p in body.policies:
        try:
            parse_policy(p.text, p.name)
        except PolicyParseError as e:
            raise HTTPException(400, detail={"message": f"{p.name} can't be parsed: {e}"}) from e
    existing, source, existing_roles = None, "", None
    if body.conn_id:
        conn = get_connection(session, body.conn_id)
        source = conn.name
        async with client_for(conn, settings) as v:
            try:
                existing = await v.policy_names()
            except VaultError:
                existing = None  # can't tell: no import blocks
            existing_roles = set()
            for m, n in keys:
                try:
                    await v.request("GET", f"auth/{m}/role/{n}")
                    existing_roles.add((m, n))
                except VaultError:
                    pass
    from importlib.metadata import PackageNotFoundError, version
    try:
        ver = version("lockstep")
    except PackageNotFoundError:
        ver = "dev"
    data = build_bundle(body.policies, version=ver, terraform=body.terraform, existing=existing, source=source,
                        roles=body.roles, existing_roles=existing_roles)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="lockstep-policies-{stamp}.zip"'})


@router.get("/{name}")
async def get_policy(name: str, session: Sess, settings: Conf, conn_id: str = Query()):
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            return {"name": name, "text": await v.policy_text(name)}
        except VaultError as e:
            raise vault_http_error(e) from e


class ExplainError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


async def run_explain(v: VaultClient, mount: str, prefix: str, *, names: list[str], pasted: list[PastedPolicy],
                      token: bool, max_secrets: int, identity: IdentityRef | None = None) -> dict:
    """Read the policies and the tree, and explain them. Used by the API and the CLI."""
    mount, prefix = mount.strip("/"), prefix.strip("/")
    sources: list[PolicySource] = []
    parsed: list[Policy] = []
    missing: list[str] = []
    root = False
    m = await v.describe_mount(mount)
    if m is None:
        raise ExplainError(400, f"'{mount}' is not a KV v2 mount")
    vault_version = await v.server_version()

    wanted: list[tuple[str, str]] = [(n, "vault") for n in dict.fromkeys(names)]
    who = None
    if identity is not None:
        who = await resolve(v, identity)
        if not who["found"] and not who["missing"]:
            raise ExplainError(404, f"No {identity.kind} {identity.name!r} on this Vault")
        root = root or who.get("root", False)
        missing += [f"{m} (to see all of {who['label']}'s policies)" for m in who["missing"]]
        wanted += [(n, "identity") for n in who["policies"] if n not in names]
    if token:
        me = await v.lookup_self()
        mine = list(dict.fromkeys([*(me.get("policies") or []), *(me.get("identity_policies") or [])]))
        root = "root" in mine
        wanted += [(n, "token") for n in mine if n != "root" and n not in names]

    async def read(name: str) -> tuple[str | None, str | None]:
        try:
            return await v.policy_text(name), None
        except VaultError as e:
            if e.status == 404:
                return None, "no such policy"
            if e.denied:
                return None, f"can't read it (needs read on sys/policies/acl/{name})"
            return None, e.message

    texts = await asyncio.gather(*(read(n) for n, _ in wanted))
    for (name, origin), (text, err) in zip(wanted, texts):
        src = PolicySource(name=name, origin=origin)  # type: ignore[arg-type]
        if err:
            src.error = err
            if "needs read" in err:
                missing.append(f"read on sys/policies/acl/{name}")
        else:
            _parse(text or "", name, src, parsed)
        sources.append(src)
    for p in pasted:
        src = PolicySource(name=p.name, origin="pasted")
        _parse(p.text, p.name, src, parsed)
        sources.append(src)

    tree = await v.kv_tree(mount, prefix, max_secrets=max_secrets)
    if tree.denied:
        missing.append(f"list on {mount}/metadata/ for {len(tree.denied)} folder(s): their secrets aren't shown")

    result = explain(parsed if not root else [*parsed, Policy("root", [])], mount, tree.secrets,
                     behaviour_for(vault_version))
    mode = "policies"
    if token and any(s.origin == "token" and s.error for s in sources) and not names and not pasted:
        # Can't see all of the token's policies: ask Vault for the answer instead
        await _from_vault(v, mount, result)
        mode = "vault"
    return dict(mount=mount, prefix=prefix, policies=sources, missing=missing, vault_version=vault_version,
                complete=not any(s.error for s in sources) or mode == "vault", mode=mode,
                denied=tree.denied, truncated=tree.truncated,
                identity={"label": who["label"], "sources": who["sources"]} if who else None, **result)


@router.post("/explain", response_model=ExplainOut)
async def explain_policies(body: ExplainRequest, session: Sess, settings: Conf):
    if not (body.names or body.pasted or body.token or body.identity):
        raise HTTPException(400, detail={"message": "Choose policies to explain: names, pasted text or your token"})
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            out = await run_explain(v, body.mount, body.prefix, names=body.names, pasted=body.pasted,
                                    token=bool(body.token), max_secrets=settings.max_tree_secrets, identity=body.identity)
        except ExplainError as e:
            raise HTTPException(e.status, detail={"message": e.message}) from e
        except VaultError as e:
            raise vault_http_error(e) from e
    return ExplainOut(**out)


def _parse(text: str, name: str, src: PolicySource, parsed: list[Policy]) -> None:
    try:
        pol = parse_policy(text, name)
    except PolicyParseError as e:
        src.error = f"can't be parsed: {e}"
        return
    src.rules = len(pol.rules)
    parsed.append(pol)


async def _from_vault(v: VaultClient, mount: str, result: dict, token: str | None = None) -> None:
    """Fill the matrix from sys/capabilities-self: always right, but without the deciding rule."""
    paths = sorted({request_path(mount, r["path"], where) for r in result["rows"] for _, _, where, _ in COLUMNS})
    caps: dict[str, list[str]] = {}
    for i in range(0, len(paths), CAPS_BATCH):
        caps |= await v.capabilities(paths[i:i + CAPS_BATCH], token=token)
    for r in result["rows"]:
        for col, _, where, need in COLUMNS:
            got = caps.get(request_path(mount, r["path"], where)) or ["deny"]
            r["cells"][col] = {"ok": "root" in got or any(c in got for c in need), "rule": None,
                               "deny": False, "caps": got}
    result["rules"] = []
    result["findings"] = [f for f in result["findings"] if "listed here" not in f["message"]
                          and "overridden" not in f["message"]]

