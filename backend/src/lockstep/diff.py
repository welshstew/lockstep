"""Pure comparison logic. No I/O, and nothing here ever returns secret values.

Only value differences count. Key order, versions, timestamps and other metadata
are ignored. KV v2 values can be any JSON type, so values are compared in canonical
JSON form: {"a":1,"b":2} equals {"b":2,"a":1}, but 5432 does not equal "5432"
(flagged as a type difference).

Each key also gets a `reason`: why it has its status, in a few words. For a key that differs
and holds structured data on both sides (a JSON object or array, or a string holding JSON or
YAML), `paths` names the fields inside that differ ("config.db.host", "hosts[2]"). Paths are
field names only, never values.

Texts that hold the same certificate, PEM or wrapped base64 data but are written differently
(line endings, line wrapping) are equal, with the reason saying so (see comparators). A
profile's `exact_keys` rule turns that off for the keys it names.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Literal

import yaml
from pydantic import BaseModel

from . import comparators
from .analyze.passwords import DEFAULTS, HINT, MAX_PASSWORD_LEN

MAX_CANDIDATES = 5  # passwords tried per keystore, from keys next to it

# not_compared: both sides are there but the values can't be compared (a keystore whose password
# isn't in the secret). Not called different, and not equal either.
KeyStatus = Literal["equal", "different", "left_only", "right_only", "not_compared", "unknown"]
SecretStatus = Literal["equal", "different", "left_only", "right_only", "not_compared", "no_access", "error"]
SideState = Literal["present", "absent", "deleted", "no_access", "error"]


class KeyDiff(BaseModel):
    key: str
    status: KeyStatus
    type_differs: bool = False
    ignored: bool = False  # matched an ignore rule: shown, but doesn't make the secret differ
    rewritten: bool = False  # equal only once the profile's rewrites are applied (e.g. test → dev)
    reason: str = ""  # why it has this status, in a few words (never a value)
    paths: list[str] = []  # fields inside a structured value that differ (not counting ignored ones)


class MetaDiff(BaseModel):
    """A custom metadata key that differs. Custom metadata isn't secret (Vault returns it to
    anyone who may read the metadata), so the values are shown."""
    key: str
    status: Literal["different", "left_only", "right_only"]
    left: str | None = None
    right: str | None = None


def diff_metadata(left: dict, right: dict) -> list[MetaDiff]:
    out = []
    for k in sorted(left.keys() | right.keys()):
        if k not in right:
            out.append(MetaDiff(key=k, status="left_only", left=str(left[k])))
        elif k not in left:
            out.append(MetaDiff(key=k, status="right_only", right=str(right[k])))
        elif str(left[k]) != str(right[k]):
            out.append(MetaDiff(key=k, status="different", left=str(left[k]), right=str(right[k])))
    return out


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
    rewritten_keys: int = 0
    note: str = ""
    # What each side's value is (e.g. PKCS#12, certificate expiring in 12 days). No values.
    badges: dict[str, dict[str, dict | None]] = {}
    # Custom metadata keys that differ, when the comparison was asked to include them
    metadata: list[MetaDiff] = []
    metadata_note: str = ""


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _type(v: Any) -> str:
    return type(v).__name__


# Structured values: how deep and how many leaves are walked, and the biggest text parsed
MAX_DEPTH = 8
MAX_LEAVES = 1000
MAX_PARSE = 256 * 1024
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
TYPE_NAMES = {"str": "text", "int": "number", "float": "number", "bool": "true/false", "NoneType": "null",
              "dict": "object", "list": "list"}


def structured(v: Any) -> dict | list | None:
    """The value as an object or list: itself, or a string holding JSON or YAML (one document)."""
    if isinstance(v, (dict, list)):
        return v
    if not isinstance(v, str) or len(v) > MAX_PARSE:
        return None
    s = v.strip()
    if s[:1] in ("{", "["):
        try:
            x = json.loads(s)
        except ValueError:
            x = None
        if isinstance(x, (dict, list)):
            return x
    if "\n" in s and ":" in s and not s.startswith("-----BEGIN"):
        try:
            x = yaml.safe_load(s)
        except yaml.YAMLError:
            return None
        if isinstance(x, (dict, list)) and x:
            return x
    return None


def _join(base: str, key: Any) -> str:
    k = str(key)
    if _IDENT.fullmatch(k):
        return f"{base}.{k}" if base else k
    return f"{base}[{json.dumps(k, ensure_ascii=False)}]"


def changed_paths(a: Any, b: Any) -> tuple[list[str], bool]:
    """The fields that differ between two structured values, and whether that's all of them
    (False past MAX_DEPTH or MAX_LEAVES: the deepest differing field found is listed instead)."""
    out: list[str] = []
    seen = 0
    complete = True

    def walk(x: Any, y: Any, path: str, depth: int) -> None:
        nonlocal seen, complete
        if seen >= MAX_LEAVES:
            complete = False
            return
        if isinstance(x, dict) and isinstance(y, dict) or isinstance(x, list) and isinstance(y, list):
            if depth >= MAX_DEPTH:
                complete = False
                if _canon(x) != _canon(y):
                    out.append(path)
                return
            if isinstance(x, dict):
                for k in sorted(x.keys() | y.keys(), key=str):
                    p = _join(path, k)
                    if k not in x or k not in y:
                        seen += 1
                        out.append(p)
                    else:
                        walk(x[k], y[k], p, depth + 1)
            else:
                for i in range(max(len(x), len(y))):
                    p = f"{path}[{i}]"
                    if i >= len(x) or i >= len(y):
                        seen += 1
                        out.append(p)
                    else:
                        walk(x[i], y[i], p, depth + 1)
            return
        seen += 1
        if _canon(x) != _canon(y):
            out.append(path)

    walk(a, b, "", 0)
    return out, complete


def _text_hint(a: Any, b: Any) -> str:
    """For two texts that differ only in a way people miss."""
    if not (isinstance(a, str) and isinstance(b, str)):
        return ""
    if a.replace("\r\n", "\n") == b.replace("\r\n", "\n"):
        return "differs only in line endings (CRLF and LF)"
    if a.strip() == b.strip():
        return "differs only in spaces or newlines at the start or end"
    if a.casefold() == b.casefold():
        return "differs only in upper and lower case"
    return ""


def _rule(r) -> str:
    where = "" if (r.path or "**") == "**" else f" under {r.path}"
    return f"`{r.key}`{f' field `{r.field}`' if getattr(r, 'field', None) else ''}{where}"


def _list(items: list[str], n: int = 3) -> str:
    shown = ", ".join(f"`{x}`" for x in items[:n])
    return shown + (f" and {len(items) - n} more" if len(items) > n else "")


def _words(rules, value, key, paths) -> str:
    words = rules.rewrite_words(value, key, paths) if rules else []
    return ", ".join(f"`{w}`" for w in words) or "of the profile's words"


def _collapse(paths: list[str], lists: list[str]) -> list[str]:
    """Paths inside a list compared regardless of order name the list ("hosts", not "hosts[2]")."""
    out: list[str] = []
    for p in paths:
        for lst in sorted(lists, key=len, reverse=True):
            if p.startswith(lst + "["):
                p = lst
                break
        if p not in out:
            out.append(p)
    return out


def diff_keys(left: dict, right: dict, ignored: Callable[[str], bool] | None = None,
              rules=None, paths: tuple[str, ...] = ()) -> list[KeyDiff]:
    """Compare two secrets' keys. `rules` (rules.Rules) is the comparison profile, applied as it
    applies in the secrets at `paths` (each side's path): rewrites, ignored keys and fields,
    unordered lists, volatile patterns and keys compared as text. `ignored(key)` ignores a whole
    key on top of that."""
    out: list[KeyDiff] = []
    for k in sorted(left.keys() | right.keys()):
        irules = rules.ignore_rules(k, *paths) if rules else []
        whole = [r for r in irules if not getattr(r, "field", None)]
        if ignored and ignored(k) and not whole:
            whole = [None]
        fields = [r for r in irules if getattr(r, "field", None)]
        if k not in right:
            kd = KeyDiff(key=k, status="left_only", reason="only on the left")
        elif k not in left:
            kd = KeyDiff(key=k, status="right_only", reason="only on the right")
        elif _canon(left[k]) == _canon(right[k]):
            kd = KeyDiff(key=k, status="equal", reason="same value")
        else:
            kd = _differing(k, left[k], right[k], rules, paths, fields,
                            lambda: (_passwords(left, k), _passwords(right, k)))
        if whole and kd.status != "equal":
            kd.ignored = True
            kd.reason = (f"{kd.reason}; ignored by profile rule {_rule(whole[0])}" if whole[0] is not None
                         else f"{kd.reason}; ignored")
        out.append(kd)
    return out


def _passwords(data: dict, key: str) -> list[tuple[str, str]]:
    """Passwords to try on a keystore in `key`: the values of the keys next to it whose names
    say password (pass, pwd, pin, secret), then Java's default. Used on the server only."""
    out = [(f"the password in `{k}`", v) for k, v in sorted(data.items())
           if k != key and HINT.search(k) and isinstance(v, str) and 0 < len(v) <= MAX_PASSWORD_LEN]
    return out[:MAX_CANDIDATES] + [("Java's default password", pw) for pw in DEFAULTS]


def _differing(k: str, left: Any, right: Any, rules, paths: tuple[str, ...], fields: list,
               passwords: Callable[[], tuple[list, list]] = lambda: ([], [])) -> KeyDiff:
    """A key whose two values aren't the same JSON: equal after all, or why not."""
    from .rules import normalise

    lv = rules.rewrite(left, key=k, paths=paths) if rules else left
    rewritten = _canon(lv) != _canon(left)
    after = f" after rewrite {_words(rules, left, k, paths)}" if rewritten else ""
    if rewritten and _canon(lv) == _canon(right):
        return KeyDiff(key=k, status="equal", rewritten=True, reason=f"equal{after}")
    kd = KeyDiff(key=k, status="different", type_differs=_type(left) != _type(right))

    # Profile rules on the value: lists compared regardless of order, volatile parts blanked
    unordered = rules.unordered_rules(k, *paths) if rules else []
    volatile = rules.volatile_rules(k, *paths) if rules else []
    lists: list[str] = []
    a = b = None
    if unordered or volatile:
        oa, la = normalise(lv, unordered, [], structured)
        ob, lb = normalise(right, unordered, [], structured)
        if (la or lb) and _canon(oa) == _canon(ob):
            r = unordered[0]
            return KeyDiff(key=k, status="equal", rewritten=rewritten,
                           reason=f"same items in a different order (rule {_rule(r)}){after}")
        va, la = normalise(lv, unordered, volatile, structured)
        vb, lb = normalise(right, unordered, volatile, structured)
        if volatile and _canon(va) == _canon(vb):
            used = [r for r in volatile if any(_canon(normalise(v, [], [r])[0]) != _canon(v) for v in (lv, right))]
            used = used or volatile
            kd.ignored = True
            kd.reason = f"differs only in values matching volatile pattern `{used[0].pattern}` (rule {_rule(used[0])})"
            return kd
        lists = la + lb
        a, b = structured(va), structured(vb)
    else:
        a, b = structured(lv), structured(right)

    verdict = comparators.compare(lv, right, *passwords())
    exact = (rules.exact_rules(k, *paths) if rules else []) if verdict and verdict.equal else []
    if verdict and verdict.equal and not exact:
        kd.status = "equal"
        kd.rewritten = rewritten
        kd.reason = verdict.reason + after
    elif verdict and verdict.equal:
        kd.reason = f"{verdict.noise}; it would be {verdict.reason}, but profile rule {_rule(exact[0])} compares it as text"
    elif verdict:
        kd.reason = verdict.reason
        if not verdict.compared:
            kd.status = "not_compared"
    elif kd.type_differs and not (a is not None and b is not None):
        kd.reason = (f"different type: {TYPE_NAMES.get(_type(left), _type(left))} on the left, "
                     f"{TYPE_NAMES.get(_type(right), _type(right))} on the right")
    elif a is not None and b is not None and type(a) is type(b):
        found, complete = changed_paths(a, b)
        found = _collapse(found, lists)
        skipped = [p for p in found if any(r.covers(p) for r in fields)]
        found = [p for p in found if p not in skipped and p]
        kd.paths = found
        if "" in lists and not found and not skipped:
            kd.reason = f"different items (order ignored by rule {_rule(unordered[0])})"
        elif not found and skipped and complete:
            kd.ignored = True
            kd.reason = f"differs only in ignored fields ({_list(skipped)}; rule {_rule(fields[0])})"
        elif found:
            kd.reason = (f"different at {_list(found)}" + ("" if complete else " (too big to list every field)")
                         + (f"; {len(skipped)} ignored field{'s' if len(skipped) != 1 else ''}" if skipped else ""))
        elif kd.type_differs:
            kd.reason = (f"same content, stored as {TYPE_NAMES.get(_type(left), _type(left))} on the left "
                         f"and {TYPE_NAMES.get(_type(right), _type(right))} on the right")
        else:
            kd.reason = "same content, written differently (spacing, key order or quoting)"
    elif lists:
        kd.reason = f"different items (order ignored by rule {_rule(unordered[0])})"
    else:
        kd.reason = _text_hint(lv, right) or "different value"
    return kd


def diff_secret(path: str, left: SideInfo, left_data: dict | None,
                right: SideInfo, right_data: dict | None, ignored=None,
                left_path: str | None = None, right_path: str | None = None, rules=None) -> SecretDiff:
    """Compare one secret. `*_data` is only used when that side's state is "present".
    `ignored(key)` says whether a key's difference should be disregarded; `rules` is the
    comparison profile (see diff_keys)."""
    d = _diff_secret(path, left, left_data, right, right_data, ignored, rules,
                     (left_path if left_path is not None else path, right_path if right_path is not None else path))
    d.left_path = left_path if left_path is not None else path
    d.right_path = right_path if right_path is not None else path
    d.ignored_keys = sum(k.ignored for k in d.keys)
    d.rewritten_keys = sum(k.rewritten for k in d.keys)
    return d


def _diff_secret(path, left, left_data, right, right_data, ignored, rules, paths) -> SecretDiff:
    states = {left.state, right.state}

    if "error" in states or "no_access" in states:
        # One side can't be seen. Never claim one-sided keys from the side we can see;
        # list them as unknown so nobody copies blindly over data they couldn't check.
        status: SecretStatus = "error" if "error" in states else "no_access"
        visible = left_data if left.state == "present" else right_data if right.state == "present" else {}
        why = "the other side can't be read" if status == "no_access" else "the other side couldn't be read (error)"
        keys = [KeyDiff(key=k, status="unknown", reason=why) for k in sorted(visible or {})]
        return SecretDiff(path=path, status=status, left=left, right=right, keys=keys)

    lp = left.state == "present"
    rp = right.state == "present"
    l, r = (left_data or {}) if lp else {}, (right_data or {}) if rp else {}
    keys = diff_keys(l, r, ignored, rules, paths)
    if lp and not rp:
        status = "left_only"
    elif rp and not lp:
        status = "right_only"
    elif all(k.status == "equal" or k.ignored for k in keys):
        status = "equal"  # includes both sides absent or deleted
    elif all(k.status in ("equal", "not_compared") or k.ignored for k in keys):
        status = "not_compared"  # nothing differs, but not everything could be checked
    else:
        status = "different"
    return SecretDiff(path=path, status=status, left=left, right=right, keys=keys)


def summarize(diffs: list[SecretDiff]) -> dict[str, int]:
    counts = {s: 0 for s in ("equal", "different", "left_only", "right_only", "not_compared", "no_access", "error")}
    for d in diffs:
        counts[d.status] += 1
    counts["total"] = len(diffs)
    return counts
