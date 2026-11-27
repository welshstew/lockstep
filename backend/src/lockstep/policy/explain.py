"""Explaining policies on a KV v2 mount: what they allow on each secret, and what looks wrong.

Each secret gets six plain-language columns. Each column is one Vault request path and the
capabilities it needs (KV v2 keeps values under data/ and everything else under metadata/):

  names    list   on <mount>/metadata/<folder>/   the secret shows up when listing its folder
  read     read   on <mount>/data/<path>          read its values
  write    create or update on <mount>/data/<path>
  delete   delete on <mount>/data/<path>          soft-delete the latest version
  destroy  delete on <mount>/metadata/<path>      every version and the metadata
  history  read   on <mount>/metadata/<path>      versions and dates
"""

from __future__ import annotations

from dataclasses import dataclass

from .acl import ACL, CURRENT, Behaviour, Entry
from .hcl import Policy

COLUMNS: list[tuple[str, str, str, tuple[str, ...]]] = [
    # (id, label, where: "list" | "data" | "metadata", capabilities: any of)
    ("names", "See names", "list", ("list",)),
    ("read", "Read", "data", ("read",)),
    ("write", "Write", "data", ("create", "update")),
    ("delete", "Delete", "data", ("delete",)),
    ("destroy", "Destroy", "metadata", ("delete",)),
    ("history", "History", "metadata", ("read",)),
]
KV2_PARTS = ("data/", "metadata/", "delete/", "undelete/", "destroy/", "subkeys/", "config")
KV2_ROOTS = ("data", "metadata", "delete", "undelete", "destroy", "subkeys")  # the bare folders
ADMIN_PREFIXES = ("sys/", "auth/", "identity/")


@dataclass
class Finding:
    level: str  # error | warn | info
    message: str
    policy: str | None = None
    path: str | None = None
    line: int | None = None

    def out(self) -> dict:
        return {"level": self.level, "message": self.message, "policy": self.policy, "path": self.path,
                "line": self.line}


def request_path(mount: str, secret: str, where: str) -> str:
    if where == "list":
        folder = secret.rsplit("/", 1)[0] + "/" if "/" in secret else ""
        return f"{mount}/metadata/{folder}"
    return f"{mount}/{where}/{secret}"


def explain(policies: list[Policy], mount: str, secrets: list[str], behaviour: Behaviour = CURRENT) -> dict:
    """The matrix for `secrets` (paths inside the mount) and the findings, evaluated with the
    rules of the Vault version `behaviour` describes."""
    acl = ACL(policies, behaviour)
    entries: list[Entry] = []
    index: dict[int, int] = {}  # id(entry) -> position in `entries`
    used: set[int] = set()  # entries that decided at least one cell
    matched: set[int] = set()  # entries that matched at least one request path

    def ref(e: Entry | None) -> int | None:
        if e is None:
            return None
        if id(e) not in index:
            index[id(e)] = len(entries)
            entries.append(e)
        return index[id(e)]

    rows = []
    seen_paths: dict[str, tuple] = {}
    for s in secrets:
        cells = {}
        for col, _, where, caps in COLUMNS:
            rp = request_path(mount, s, where)
            if rp not in seen_paths:
                d = acl.decide(rp)
                for e in acl.matching(rp):
                    matched.add(id(e))
                seen_paths[rp] = (d, ref(d.entry))
                if d.entry is not None:
                    used.add(id(d.entry))
            d, r = seen_paths[rp]
            cells[col] = {"ok": d.allows(*caps), "rule": r, "deny": "deny" in d.capabilities and d.entry is not None,
                          "caps": d.capabilities}
        rows.append({"path": s, "cells": cells})

    # Listing a folder shows its subfolders too: those listings count as using a rule
    folders = {""} | {s.rsplit("/", i)[0] + "/" for s in secrets for i in range(1, s.count("/") + 1)}
    for f in folders:
        rp = f"{mount}/metadata/{f}"
        d = acl.decide(rp)
        matched.update(id(e) for e in acl.matching(rp))
        if d.entry is not None:
            used.add(id(d.entry))

    findings = lint(policies, mount)
    if secrets and not acl.root:
        findings += _unused(acl, mount, used, matched)
    return {
        "columns": [{"id": c, "label": label} for c, label, _, _ in COLUMNS],
        "evaluation": behaviour.label,
        "evaluation_known": behaviour.known,
        "root": acl.root,
        "rules": [{"key": e.key, "kind": e.kind, "capabilities": sorted(e.caps),
                   "sources": [{"policy": s.policy, "path": s.path, "line": s.line, "capabilities": s.capabilities}
                               for s in e.sources]} for e in entries],
        "rows": rows,
        "findings": [f.out() for f in findings],
    }


def _unused(acl: ACL, mount: str, used: set[int], matched: set[int]) -> list[Finding]:
    out = []
    for tree in (acl.exact, acl.prefix, acl.segment):
        for e in tree.values():
            in_mount = e.key.startswith(f"{mount}/") or (e.kind != "exact" and f"{mount}/".startswith(e.key))
            if not in_mount or id(e) in used:
                continue
            msg = ("is always overridden by a more specific rule for the secrets here"
                   if id(e) in matched else "doesn't match any secret listed here")
            for s in e.sources:
                if s.policy != "default":  # Vault's built-in policy: not the user's to tidy
                    out.append(Finding("info", f'path "{s.path}" {msg}', s.policy, s.path, s.line))
    return out


def lint(policies: list[Policy], mount: str | None = None) -> list[Finding]:
    """Mistakes and risky grants that can be seen from the policies alone."""
    out: list[Finding] = []
    for pol in policies:
        seen: dict[str, int | None] = {}
        for r in pol.rules:
            f = lambda level, msg: out.append(Finding(level, msg, pol.name, r.path, r.line))  # noqa: E731
            p = r.path
            if r.unknown:
                f("error", f"Vault doesn't know the capabilit{'y' if len(r.unknown) == 1 else 'ies'} "
                           f"{', '.join(r.unknown)}: Vault will refuse this policy")
            if not r.capabilities:
                f("warn", "grants nothing: no capabilities")
            if p in seen:
                f("info", f"the same path appears earlier (line {seen[p]}): Vault merges them")
            seen[p] = r.line
            if "+*" in p:
                f("error", "Vault refuses '+*': use '+/*' (one segment, then anything) or a name before the *")
            if "*" in p[:-1]:
                f("warn", "only a * at the very end is a wildcard: this * matches a literal *")
            if any("+" in seg and seg != "+" for seg in p.split("/")):
                f("warn", "+ is a wildcard only as a whole segment (a/+/b): here it's a literal +")
            if "deny" in r.capabilities and len(r.capabilities) > 1:
                f("info", "deny overrides the other capabilities listed with it")
            if "sudo" in r.capabilities:
                f("warn", "sudo allows root-protected operations: grant it only where needed")
            if p in ("*", "+", "+/*") or p == "":
                f("warn", "applies to every path in Vault")
            elif p.startswith(ADMIN_PREFIXES) and "deny" not in r.capabilities and pol.name != "default":
                if set(r.capabilities) <= {"read", "list"}:
                    f("info", f"reads Vault configuration ({p.split('/')[0]}/)")
                else:
                    f("warn", f"can change Vault's own configuration ({p.split('/')[0]}/)")
            if mount and (p.startswith(f"{mount}/") or p == mount):
                _lint_kv2(f, p, r.capabilities, mount)
    return out


def _lint_kv2(f, p: str, caps: list[str], mount: str) -> None:
    rest = p[len(mount) + 1:]
    if rest in ("*", "+/*", ""):
        if "deny" not in caps and rest:
            f("warn", f"covers everything in {mount}: values, metadata, deletes and destroys")
        return
    if rest.startswith("+"):
        return  # data/, metadata/, ... picked by a wildcard: deliberate
    if rest in KV2_ROOTS or rest.rstrip("/") in KV2_ROOTS:
        return
    if not rest.startswith(KV2_PARTS):
        f("warn", f"{mount} is KV v2: secrets are under {mount}/data/ (values) and {mount}/metadata/ "
                  f"(listing, history). Did you mean {mount}/data/{rest} ?")
    elif rest.startswith("data/") and "list" in caps:
        f("info", f"list does nothing on data/: listing uses {mount}/metadata/")
    elif rest.startswith("metadata/") and "delete" in caps:
        f("warn", "delete on metadata/ allows destroying secrets: every version, with no undo")
