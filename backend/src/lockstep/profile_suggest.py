"""Suggesting comparison-profile rules from what's actually in the two Vaults.

Two kinds of suggestion, each with the reason it was made:

* **Path mappings**, from the folder trees alone (paths aren't secret). A folder that exists on
  only one side, whose secrets have the same names as a folder that exists only on the other
  side, was probably renamed: `enterprise-logging-app/{values,certs}` against
  `ELP/{values,certs}`. When the renamed segment sits under a varying parent, as in
  `services/billing/prod` against `services/billing/staging`, the mapping uses a wildcard for
  the parent so it covers every service.

* **Value rewrites**, from values that still differ once paths are paired. Only words that
  already appear in a path, or are common environment names (dev, test, staging, prod...), are
  ever considered, so a suggestion never reveals part of a value: it can only name a word the
  user can already see. A set of rewrites is kept when it makes keys equal, and each rewrite in
  it is reported with how many keys depend on it.

* **Unordered lists,** for a key whose two values hold the same items in another order: a JSON or
  YAML list, or text with items separated by commas.

* **Volatile patterns,** for a key whose two values differ only in a timestamp, a date or a UUID.
  Only these fixed patterns are suggested, so a suggestion names a pattern, never part of a value.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .diff import structured
from .rules import _OPAQUE, Mapping, Rewrite, Rules, UnorderedRule, VolatileRule, compile_glob, normalise, pair_paths

ENV_WORDS = ("dev", "develop", "development", "test", "testing", "qa", "uat", "sit", "stage", "stg",
             "staging", "preprod", "pre-prod", "prod", "prd", "production", "sandbox", "perf", "nonprod")
MAX_VALUE_PAIRS = 5000  # differing string values considered for rewrites
MAX_VALUE_LEN = 4096
MAX_SUGGESTIONS = 10
_WORD = re.compile(r"[A-Za-z0-9]")


@dataclass
class MappingSuggestion:
    left: str
    right: str
    pairs: list[tuple[str, str]]  # (left path, right path) it pairs that weren't paired before
    reason: str


@dataclass
class RewriteSuggestion:
    left: str
    right: str
    keys: int  # differing keys that are equal only with this rewrite (in the suggested set)
    secrets: list[str]  # where (pair paths, right-side form), up to 10
    reason: str


@dataclass
class UnorderedSuggestion:
    key: str
    separator: str | None
    keys: int  # differing keys equal with it
    secrets: list[str]
    reason: str


@dataclass
class VolatileSuggestion:
    key: str
    pattern: str
    what: str  # "a timestamp", "a date", "a UUID"
    keys: int  # differing keys that differ only there
    secrets: list[str]
    reason: str


# Fixed patterns for values that change on their own, most specific first
VOLATILE_PATTERNS = [
    ("a timestamp", r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"),
    ("a date", r"\d{4}-\d{2}-\d{2}"),
    ("a UUID", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
]
_GLOB_CHARS = re.compile(r"[*?\[\]]")


@dataclass
class ValuePairs:
    """Differing string values, collected during a comparison and dropped after suggesting."""
    items: list[tuple[str, str, str, str]] = field(default_factory=list)  # (secret, key, left, right)

    def observe(self, d, ld, rd) -> None:
        if not ld or not rd or len(self.items) >= MAX_VALUE_PAIRS:
            return
        for k in d.keys:
            if k.status != "different" or k.ignored:
                continue
            lv, rv = ld.get(k.key), rd.get(k.key)
            if isinstance(lv, (dict, list)) and isinstance(rv, (dict, list)):
                lv, rv = json.dumps(lv, sort_keys=True), json.dumps(rv, sort_keys=True)
            if (isinstance(lv, str) and isinstance(rv, str) and len(lv) <= MAX_VALUE_LEN and len(rv) <= MAX_VALUE_LEN
                    and not _OPAQUE.search(lv) and not _OPAQUE.search(rv)):
                self.items.append((d.path, k.key, lv, rv))


# --------------------------------------------------------------------------- mappings


def _folders(paths: set[str]) -> dict[str, set[str]]:
    """Every folder (at any depth) -> the paths below it, relative to it."""
    out: dict[str, set[str]] = {}
    for p in paths:
        segs = p.split("/")
        for d in range(1, len(segs)):
            out.setdefault("/".join(segs[:d]), set()).add("/".join(segs[d:]))
    return out


def _covered(path: str, chosen: list[str]) -> bool:
    return any(path == c or path.startswith(c + "/") for c in chosen)


def suggest_mappings(left: set[str], right: set[str], rules: Rules) -> list[MappingSuggestion]:
    """Folders renamed between the sides, given the rules already in place."""
    pairs, _, _ = pair_paths(left, right, rules)
    lonly = {lp for lp, rp in pairs.values() if lp in left and rp not in right}
    ronly = {rp for lp, rp in pairs.values() if rp in right and lp not in left}
    if not lonly or not ronly:
        return []
    lf, rf = _folders(lonly), _folders(ronly)
    # Only folders that are wholly one-sided: a folder both sides have isn't a rename.
    lf = {f: s for f, s in lf.items() if f not in _folders(right)}
    rf = {f: s for f, s in rf.items() if f not in _folders(left)}

    candidates = []
    for fl, sl in lf.items():
        dl = fl.count("/")
        for fr, sr in rf.items():
            if fr.count("/") != dl:
                continue
            common = sl & sr
            if not common:
                continue
            score = len(common) / len(sl | sr)
            if score < 0.5 and len(common) < 2:
                continue
            candidates.append((score, len(common), -dl, fl, fr))
    candidates.sort(reverse=True)
    sets = {(fl, fr): (lf[fl], rf[fr]) for *_, fl, fr in candidates}

    out: list[MappingSuggestion] = []
    taken_l: list[str] = []
    taken_r: list[str] = []
    for score, n, _, fl, fr in candidates:
        sl, sr = sets[(fl, fr)]
        if _covered(fl, taken_l) or _covered(fr, taken_r):
            continue
        if any(compile_glob(x.left).match(f"{fl}/{rest}") for x in out for rest in sl):
            continue  # an earlier (wildcard) suggestion already pairs this folder
        lpat, rpat = _generalise(fl, fr, lonly, ronly)
        try:
            m = Mapping(left=f"{lpat}/**", right=f"{rpat}/**")
        except ValueError:
            continue
        trial = Rules(mappings=[m])
        new_pairs = sorted((lp, trial.to_right(lp)) for lp in lonly
                           if compile_glob(m.left).match(lp) and trial.to_right(lp) in ronly)
        if not new_pairs:
            continue
        taken_l.append(lpat if "*" not in lpat else fl)
        taken_r.append(rpat if "*" not in rpat else fr)
        out.append(MappingSuggestion(left=m.left, right=m.right, pairs=new_pairs,
                                     reason=_mapping_reason(fl, fr, lpat, rpat, sl, sr, new_pairs)))
        if len(out) >= MAX_SUGGESTIONS:
            break
    return out


def _generalise(fl: str, fr: str, lonly: set[str], ronly: set[str]) -> tuple[str, str]:
    """`services/billing/prod` vs `services/billing/staging` differ in the last segment only:
    try `services/*/prod` vs `services/*/staging`, and keep it if it pairs more paths."""
    ls, rs = fl.split("/"), fr.split("/")
    diff = [i for i, (a, b) in enumerate(zip(ls, rs)) if a != b]
    if len(diff) != 1 or diff[0] < 2:
        return fl, fr
    i = diff[0]
    gl = "/".join([ls[0], *["*"] * (i - 1), ls[i]])
    gr = "/".join([rs[0], *["*"] * (i - 1), rs[i]])

    def pairs(lp_, rp_):
        t = Rules(mappings=[Mapping(left=f"{lp_}/**", right=f"{rp_}/**")])
        return sum(1 for p in lonly if t.to_right(p) in ronly)
    # The wildcard also covers folders added later, so it wins a tie.
    return (gl, gr) if pairs(gl, gr) >= pairs(fl, fr) else (fl, fr)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _mapping_reason(fl, fr, lpat, rpat, sl, sr, new_pairs) -> str:
    common = sorted(sl & sr)
    shown = ", ".join(common[:4]) + (", …" if len(common) > 4 else "")
    if "*" in lpat:
        return (f"{fl}/ is only on the left and {fr}/ only on the right, with the same secrets ({shown}). "
                f"The folders differ in one name ({lpat.split('/')[-1]} ⇄ {rpat.split('/')[-1]}), so a wildcard "
                f"for the part in between pairs {_plural(len(new_pairs), 'secret')}, and covers folders added later. "
                f"A folder that exists in one environment only still shows as one-sided.")
    extra = [f"{_plural(n, 'secret')} only on the {side}" for n, side in ((len(sl - sr), "left"), (len(sr - sl), "right")) if n]
    tail = f" Once paired, {' and '.join(extra)} remain: real differences to look at." if extra else ""
    return (f"{fl}/ is only on the left and {fr}/ only on the right, but they hold secrets with the same "
            f"names ({shown}). That looks like a rename, so this pairs {_plural(len(new_pairs), 'secret')}.{tail}")


# --------------------------------------------------------------------------- rewrites


def _vocabulary(paths: set[str]) -> set[str]:
    words = set(ENV_WORDS)
    for p in paths:
        for seg in p.split("/"):
            if 2 <= len(seg) <= 100 and _WORD.search(seg):
                words |= {seg, seg.lower()}
                words |= {part for part in re.split(r"[^A-Za-z0-9]+", seg) if len(part) >= 3}
    return words


def _has(word: str, text: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])", text) is not None


def suggest_rewrites(values: ValuePairs, rules: Rules, paths: set[str]) -> list[RewriteSuggestion]:
    """Rewrites that make differing values equal, from words the user can already see."""
    if not values.items:
        return []
    vocab = _vocabulary(paths)
    known_l = {r.left for r in rules.rewrites}
    known_r = {r.right for r in rules.rewrites}
    counts: dict[tuple[str, str], int] = {}
    for _, _, lv, rv in values.items:
        lw = [w for w in vocab if w not in known_l and _has(w, lv) and not _has(w, rv)]
        rw = [w for w in vocab if w not in known_r and _has(w, rv) and not _has(w, lv)]
        for a in lw:
            for b in rw:
                if a != b:
                    counts[(a, b)] = counts.get((a, b), 0) + 1
    if not counts:
        return []
    # One partner per word, most frequent first; drop words that contain one already taken
    # in the same position, so "enterprise-logging-app" wins over "logging" when both fit.
    chosen: list[tuple[str, str]] = []
    used_l, used_r = set(), set()
    for (a, b), _ in sorted(counts.items(), key=lambda kv: (-kv[1], -len(kv[0][0]) - len(kv[0][1]), kv[0])):
        if a in used_l or b in used_r:
            continue
        chosen.append((a, b))
        used_l.add(a)
        used_r.add(b)

    def equal_with(extra: list[tuple[str, str]]) -> set[int]:
        try:
            r = Rules(rewrites=[*rules.rewrites, *(Rewrite(left=a, right=b) for a, b in extra)])
        except ValueError:
            return set()
        return {i for i, (path, key, lv, rv) in enumerate(values.items) if r.rewrite(lv, key=key, paths=(path,)) == rv}

    best = equal_with(chosen)
    if not best:
        return []
    for pair in list(chosen):  # prune rewrites the result doesn't need
        rest = [p for p in chosen if p != pair]
        if equal_with(rest) >= best:
            chosen = rest
    out = []
    for a, b in chosen:
        without = equal_with([p for p in chosen if p != (a, b)])
        needed = sorted(best - without)
        where = sorted({values.items[i][0] for i in needed})
        keys = [f"{values.items[i][0]} › {values.items[i][1]}" for i in needed]
        out.append(RewriteSuggestion(
            left=a, right=b, keys=len(needed), secrets=where[:10],
            reason=(f"Values on the left say {a} where the right says {b}. Reading {a} as {b} makes "
                    f"{_plural(len(needed), 'differing key')} equal ({', '.join(keys[:3])}{', …' if len(keys) > 3 else ''}). "
                    f"Anything else that differs in those values still shows as different.")))
    out.sort(key=lambda s: -s.keys)
    return out[:MAX_SUGGESTIONS]


# --------------------------------------------------------------------------- unordered lists, volatile values


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _where(found: dict, values: "ValuePairs") -> tuple[int, list[str], str]:
    idx = found["items"]
    where = sorted({values.items[i][0] for i in idx})
    keys = f"{_plural(len(idx), 'differing key')} ({', '.join(where[:3])}{', …' if len(where) > 3 else ''})"
    return len(idx), where[:10], keys


def suggest_value_rules(values: ValuePairs, rules: Rules) -> tuple[list[UnorderedSuggestion], list[VolatileSuggestion]]:
    """Keys whose values hold the same items in another order, or differ only in a timestamp,
    date or UUID, after the rules (and their rewrites) are applied. Each suggestion is checked
    with the same code the comparison uses."""
    unordered: dict[tuple[str, str | None], dict] = {}
    volatile: dict[tuple[str, str], dict] = {}
    known_u = {r.key for r in rules.unordered_keys}
    known_v = {(r.key, r.pattern) for r in rules.volatile}
    for i, (path, key, lv, rv) in enumerate(values.items):
        if _GLOB_CHARS.search(key):
            continue  # a key name that would be read as a pattern
        lv = rules.rewrite(lv, key=key, paths=(path,))
        if lv == rv:
            continue
        hit = False
        if key not in known_u:
            for sep in (None, ","):
                rule = [UnorderedRule(key=key, separator=sep)]
                (a, la), (b, lb) = normalise(lv, rule, [], structured), normalise(rv, rule, [], structured)
                if (la or lb) and _canon(a) == _canon(b) and (sep is None or len(a) > 1):
                    unordered.setdefault((key, sep), {"items": []})["items"].append(i)
                    hit = True
                    break
        if hit:
            continue
        for what, pattern in VOLATILE_PATTERNS:
            if (key, pattern) in known_v:
                break
            rule = [VolatileRule(key=key, pattern=pattern)]
            a, b = normalise(lv, [], rule)[0], normalise(rv, [], rule)[0]
            if _canon(a) == _canon(b):
                volatile.setdefault((key, pattern), {"items": [], "what": what})["items"].append(i)
                break
    out_u = []
    for (key, sep), found in unordered.items():
        n, where, keys = _where(found, values)
        how = "a list" if sep is None else "comma-separated items"
        out_u.append(UnorderedSuggestion(
            key=key, separator=sep, keys=n, secrets=where,
            reason=(f"{key} holds {how} with the same items in a different order on each side: "
                    f"{keys}. Compared regardless of order, {'it is' if n == 1 else 'they are'} equal.")))
    out_v = []
    for (key, pattern), found in volatile.items():
        n, where, keys = _where(found, values)
        out_v.append(VolatileSuggestion(
            key=key, pattern=pattern, what=found["what"], keys=n, secrets=where,
            reason=(f"{key} differs only in {found['what']}: {keys}. Ignoring {found['what']} there marks "
                    f"{'it' if n == 1 else 'them'} ignored; any other difference in {key} still counts.")))
    out_u.sort(key=lambda x: -x.keys)
    out_v.sort(key=lambda x: -x.keys)
    return out_u[:MAX_SUGGESTIONS], out_v[:MAX_SUGGESTIONS]
