"""Pure comparison logic. No I/O, and nothing here ever returns secret values.

Only value differences count. Key order, versions, timestamps and other metadata
are ignored. KV v2 values can be any JSON type, so values are compared in canonical
JSON form: {"a":1,"b":2} equals {"b":2,"a":1}, but 5432 does not equal "5432"
(flagged as a type difference).
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel

KeyStatus = Literal["equal", "different", "left_only", "right_only", "unknown"]
SecretStatus = Literal["equal", "different", "left_only", "right_only", "no_access", "error"]
SideState = Literal["present", "absent", "deleted", "no_access", "error"]


class KeyDiff(BaseModel):
    key: str
    status: KeyStatus
    type_differs: bool = False
    ignored: bool = False  # matched an ignore rule: shown, but doesn't make the secret differ


class SideInfo(BaseModel):
    state: SideState
    version: int | None = None
    updated: str | None = None
    error: str | None = None


class SecretDiff(BaseModel):
    path: str  # identifies the pair (relative to the prefixes; the right side's form when mapped)
    status: SecretStatus
    left: SideInfo
    right: SideInfo
    keys: list[KeyDiff]
    left_path: str = ""  # actual path on each side (differs from `path` only under a mapping)
    right_path: str = ""
    ignored_keys: int = 0
    note: str = ""
    # What each side's value is (e.g. PKCS#12, certificate expiring in 12 days). No values.
    badges: dict[str, dict[str, dict | None]] = {}


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _type(v: Any) -> str:
    return type(v).__name__


def diff_keys(left: dict, right: dict, ignored=None) -> list[KeyDiff]:
    out: list[KeyDiff] = []
    for k in sorted(left.keys() | right.keys()):
        if k not in right:
            out.append(KeyDiff(key=k, status="left_only"))
        elif k not in left:
            out.append(KeyDiff(key=k, status="right_only"))
        elif _canon(left[k]) == _canon(right[k]):
            out.append(KeyDiff(key=k, status="equal"))
        else:
            out.append(KeyDiff(key=k, status="different", type_differs=_type(left[k]) != _type(right[k])))
    if ignored:
        for kd in out:
            kd.ignored = kd.status != "equal" and ignored(kd.key)
    return out


def diff_secret(path: str, left: SideInfo, left_data: dict | None,
                right: SideInfo, right_data: dict | None, ignored=None,
                left_path: str | None = None, right_path: str | None = None) -> SecretDiff:
    """Compare one secret. `*_data` is only used when that side's state is "present".
    `ignored(key)` says whether a key's difference should be disregarded."""
    d = _diff_secret(path, left, left_data, right, right_data, ignored)
    d.left_path = left_path if left_path is not None else path
    d.right_path = right_path if right_path is not None else path
    d.ignored_keys = sum(k.ignored for k in d.keys)
    return d


def _diff_secret(path, left, left_data, right, right_data, ignored) -> SecretDiff:
    states = {left.state, right.state}

    if "error" in states or "no_access" in states:
        # One side can't be seen. Never claim one-sided keys from the side we can see;
        # list them as unknown so nobody copies blindly over data they couldn't check.
        status: SecretStatus = "error" if "error" in states else "no_access"
        visible = left_data if left.state == "present" else right_data if right.state == "present" else {}
        keys = [KeyDiff(key=k, status="unknown") for k in sorted(visible or {})]
        return SecretDiff(path=path, status=status, left=left, right=right, keys=keys)

    lp = left.state == "present"
    rp = right.state == "present"
    l, r = (left_data or {}) if lp else {}, (right_data or {}) if rp else {}
    keys = diff_keys(l, r, ignored)
    if lp and not rp:
        status = "left_only"
    elif rp and not lp:
        status = "right_only"
    elif all(k.status == "equal" or k.ignored for k in keys):
        status = "equal"  # includes both sides absent or deleted
    else:
        status = "different"
    return SecretDiff(path=path, status=status, left=left, right=right, keys=keys)


def summarize(diffs: list[SecretDiff]) -> dict[str, int]:
    counts = {s: 0 for s in ("equal", "different", "left_only", "right_only", "no_access", "error")}
    for d in diffs:
        counts[d.status] += 1
    counts["total"] = len(diffs)
    return counts
