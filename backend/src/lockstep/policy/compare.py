"""Comparing ACL policies across two Vaults, by meaning rather than by text.

Each policy is parsed and reduced to what Vault acts on: path → capabilities (rules with the same
path added up, deny winning) plus any other fields. Comments, whitespace, rule order and how the
capabilities are listed don't count. A *policy profile* pairs names that differ between the
Vaults (`*-dev` ⇄ `*-prod`), rewrites the left policy's paths before comparing (`/dev/` → `/prod/`),
and leaves policies out.
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .hcl import Policy, PolicyParseError, parse_policy

Status = Literal["equal", "different", "left_only", "right_only", "error"]


class NameMapping(BaseModel):
    left: str = Field(min_length=1, max_length=256)  # a name, or a pattern with * (e.g. "*-dev")
    right: str = Field(min_length=1, max_length=256)  # the same number of *s (e.g. "*-prod")

    @field_validator("right")
    @classmethod
    def _stars(cls, v, info):
        left = info.data.get("left", "")
        if v.count("*") != left.count("*"):
            raise ValueError(f"'{left}' and '{v}' need the same number of *")
        return v


class Rewrite(BaseModel):
    find: str = Field(min_length=1, max_length=512)
    replace: str = Field(default="", max_length=512)


class PolicyProfile(BaseModel):
    """How to line up two Vaults' policies. Kept by users, or shared by the server."""

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1000)
    mappings: list[NameMapping] = Field(default=[], max_length=100)
    rewrites: list[Rewrite] = Field(default=[], max_length=100)  # on the left policy's paths, before comparing
    ignore: list[str] = Field(default=["root"], max_length=200)  # policy names (or * patterns) to leave out


def _regex(pattern: str) -> re.Pattern:
    return re.compile("^" + "(.*)".join(re.escape(p) for p in pattern.split("*")) + "$")


def pair_names(left: list[str], right: list[str], profile: PolicyProfile | None) -> list[tuple[str | None, str | None, bool, str]]:
    """(left name, right name, mapped by the profile, note). Mapped pairs first, then same names."""
    ignore = profile.ignore if profile else ["root"]
    left = [n for n in left if not any(fnmatchcase(n, g) for g in ignore)]
    right = [n for n in right if not any(fnmatchcase(n, g) for g in ignore)]
    rset = set(right)
    taken: set[str] = set()
    out: list[tuple[str | None, str | None, bool, str]] = []
    unpaired: list[str] = []
    for n in left:
        target = None
        for m in profile.mappings if profile else []:
            hit = _regex(m.left).match(n)
            if hit:
                parts = iter(hit.groups())
                target = "".join(p + (next(parts) if i < m.right.count("*") else "")
                                 for i, p in enumerate(m.right.split("*")))
                break
        if target is not None:
            if target in rset and target not in taken:
                taken.add(target)
                out.append((n, target, True, ""))
            else:
                out.append((n, None, True, f"expected {target} on the right"))
        else:
            unpaired.append(n)
    for n in unpaired:
        if n in rset and n not in taken:
            taken.add(n)
            out.append((n, n, False, ""))
        else:
            out.append((n, None, False, ""))
    out += [(None, n, False, "") for n in right if n not in taken]
    return sorted(out, key=lambda x: (x[0] or x[1] or "").lower())


def normalise(policy: Policy, rewrites: list[Rewrite] | None = None) -> dict[str, dict[str, Any]]:
    """path → {"caps": sorted list, "extra": fields}, merged the way Vault merges."""
    out: dict[str, dict[str, Any]] = {}
    for r in policy.rules:
        path = r.path
        for rw in rewrites or []:
            path = path.replace(rw.find, rw.replace)
        e = out.setdefault(path, {"caps": set(), "extra": {}})
        caps = set(r.capabilities)
        e["caps"] = {"deny"} if "deny" in caps or "deny" in e["caps"] else e["caps"] | caps
        e["extra"].update(r.extra)
    return {p: {"caps": sorted(e["caps"]), "extra": e["extra"]} for p, e in out.items()}


def compare_texts(left: str | None, right: str | None, rewrites: list[Rewrite] | None = None,
                  names: tuple[str, str] = ("left", "right")) -> dict:
    """Compare two policy texts (either may be missing)."""
    if left is None or right is None:
        return {"status": "left_only" if right is None else "right_only", "rules": [], "formatting": False, "note": ""}
    try:
        lp, rp = parse_policy(left, names[0]), parse_policy(right, names[1])
    except PolicyParseError as e:
        same = " ".join(left.split()) == " ".join(right.split())
        return {"status": "equal" if same else "error", "rules": [], "formatting": False,
                "note": f"can't be parsed ({e}): compared as text" + ("" if same else " and they differ")}
    ln, rn = normalise(lp, rewrites), normalise(rp)
    rules = []
    for path in sorted(set(ln) | set(rn)):
        a, b = ln.get(path), rn.get(path)
        change = ("left_only" if b is None else "right_only" if a is None
                  else "same" if a == b else "changed")
        rules.append({"path": path, "left": a["caps"] if a else None, "right": b["caps"] if b else None,
                      "left_extra": a["extra"] if a and a["extra"] else None,
                      "right_extra": b["extra"] if b and b["extra"] else None, "change": change})
    differs = any(r["change"] != "same" for r in rules)
    return {"status": "different" if differs else "equal", "rules": rules,
            "formatting": not differs and left != right, "note": ""}


def summary(pairs: list[dict]) -> dict[str, int]:
    return {s: sum(p["status"] == s for p in pairs) for s in ("equal", "different", "left_only", "right_only", "error")}


def profile_schema() -> dict:
    s = PolicyProfile.model_json_schema()
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    s["title"] = "Lockstep policy profile"
    return s

