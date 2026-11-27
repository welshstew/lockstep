"""Comparison profile rules: path mappings and ignore rules. Pure logic, no I/O.

Patterns are globs over secret paths (relative to each side's prefix):
    *    any characters except "/"  (one path segment, or part of one)
    **   any characters including "/" (any depth, possibly empty)

A mapping pairs a left and a right pattern with the same wildcards in the same order.
`services/*/prod/**` <-> `services/*/staging/**` maps `services/billing/prod/db/main`
to `services/billing/staging/db/main` and back. The first matching mapping wins; paths no
mapping matches are compared as they are.

A rewrite pairs a word on the left with a word on the right, for values that name the
environment or the application (`logs.test.internal` vs `logs.dev.internal`). Before values
are compared, each left word is read as its right word; a copy to the right writes the right
word, a copy to the left the left one. Words match whole: `test` matches `logs.test.internal`
and `app-test`, never `latest`. Certificates, keys and base64 data are never rewritten. A rewrite
can be limited to some keys (`key`, a glob over key names) and secrets (`path`): `test` → `dev`
for `*host*` only never touches a `password`.

A rewrite can also be a pattern, with placeholders: `{app}-test-db` ⇄ `{app}-dev-db` reads
`billing-test-db` as `billing-dev-db`. A placeholder stands for one word (letters and digits), and
has to sit next to a character that isn't one, or the end: `{app}-test` but not `{app}test`. That
keeps matching quick on any value, and makes every pattern work in both directions.

Two rules change how a key's values are compared, never what's copied:
  unordered_keys  a list whose order doesn't matter (SANs, scopes, hosts): compared as the same
                  items, duplicates counted. The whole value, a `field` inside JSON or YAML, or a
                  text split on a `separator` ("a.com, b.com").
  volatile        a regex for parts of a value that change on their own (timestamps, build
                  numbers). Matches are blanked on both sides; a key that differs only there is
                  marked ignored, like an ignored field.
"""

from __future__ import annotations

import fnmatch
import json
import re
from functools import cached_property, lru_cache
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

_TOKEN = re.compile(r"\*\*|\*")


def _wildcards(pattern: str) -> list[str]:
    return _TOKEN.findall(pattern)


def compile_glob(pattern: str) -> re.Pattern:
    """Glob -> anchored regex; each wildcard becomes a capture group, in order."""
    out, pos = [], 0
    for m in _TOKEN.finditer(pattern):
        out.append(re.escape(pattern[pos:m.start()]))
        out.append("(.*)" if m.group() == "**" else "([^/]*)")
        pos = m.end()
    out.append(re.escape(pattern[pos:]))
    rx = "".join(out)
    # "a/**" also matches "a" itself, and "**/x" also matches "x"
    rx = rx.replace(re.escape("/") + "(.*)", "(?:/(.*))?") if pattern.endswith("/**") else rx
    return re.compile(rf"^{rx}$")


def _fill(template: str, captures: tuple) -> str:
    it = iter(captures)
    filled = _TOKEN.sub(lambda m: next(it) or "", template)
    return re.sub(r"/{2,}", "/", filled).strip("/")


class Mapping(BaseModel):
    left: str = Field(min_length=1, max_length=512)
    right: str = Field(min_length=1, max_length=512)

    @field_validator("left", "right")
    @classmethod
    def _clean(cls, v: str) -> str:
        return v.strip().strip("/")

    @model_validator(mode="after")
    def _same_wildcards(self):
        if _wildcards(self.left) != _wildcards(self.right):
            raise ValueError(f"mapping '{self.left}' ↔ '{self.right}': both sides need the same wildcards "
                             f"in the same order ({_wildcards(self.left)} vs {_wildcards(self.right)})")
        return self


class IgnoreKey(BaseModel):
    key: str = Field(min_length=1, max_length=256)  # glob over key names, e.g. "*_url", "host"
    path: str = Field(default="**", max_length=512)  # only under these paths (default: everywhere)


class IgnoreRule(IgnoreKey):
    """A comparison profile's ignored key: the whole key, or one field inside its value."""
    # Only this field inside a structured value (JSON or YAML): "db.password", "tls.*", "hosts[0]".
    # None: the whole key. A field rule also covers what's under it ("db" covers "db.password").
    field: str | None = Field(default=None, max_length=256)

    @field_validator("field")
    @classmethod
    def _field(cls, v: str | None) -> str | None:
        v = (v or "").strip().strip(".")
        return v or None

    @cached_property
    def field_rx(self) -> re.Pattern | None:
        if not self.field:
            return None
        body = "".join(".*" if c == "*" else re.escape(c) for c in self.field)
        return re.compile(body + r"(?:[.\[].*)?")

    def covers(self, field_path: str) -> bool:
        return self.field_rx is not None and self.field_rx.fullmatch(field_path) is not None


class Rewrite(BaseModel):
    left: str = Field(min_length=1, max_length=200)  # a word as the left side writes it, e.g. "test"
    right: str = Field(min_length=1, max_length=200)  # the same word on the right, e.g. "dev"
    key: str = Field(default="*", max_length=256)  # only in keys matching this glob ("*host*")
    path: str = Field(default="**", max_length=512)  # only in secrets under this path

    @field_validator("key")
    @classmethod
    def _key(cls, v: str) -> str:
        return v.strip() or "*"

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return v.strip().strip("/") or "**"

    @property
    def scoped(self) -> bool:
        return self.key != "*" or self.path != "**"

    def applies(self, key: str | None, paths: tuple[str, ...]) -> bool:
        """Whether this rewrite applies to `key` in these secrets (key None: everywhere)."""
        if key is None:
            return True
        if not fnmatch.fnmatchcase(key, self.key):
            return False
        return self.path == "**" or any(_glob(self.path).match(p) for p in paths if p)

    @field_validator("left", "right")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a rewrite needs a word on each side")
        return v

    @model_validator(mode="after")
    def _differ(self):
        if self.left == self.right:
            raise ValueError(f"rewrite '{self.left}' ⇄ '{self.right}': the two words are the same")
        pl, pr = _placeholders(self.left), _placeholders(self.right)
        if pl or pr:
            where = f"rewrite '{self.left}' ⇄ '{self.right}'"
            if sorted(pl) != sorted(pr):
                raise ValueError(f"{where}: both sides need the same placeholders")
            if len(set(pl)) != len(pl):
                raise ValueError(f"{where}: each placeholder can appear once on a side")
            for side in (self.left, self.right):
                if not _PLACE_SPLIT.sub("", side):
                    raise ValueError(f"{where}: a pattern needs some text besides placeholders")
                for m in _PLACE.finditer(side):
                    before, after = side[m.start() - 1:m.start()], side[m.end():m.end() + 1]
                    if re.fullmatch(f"[{_WORD}{{}}]", before or "-") or re.fullmatch(f"[{_WORD}{{}}]", after or "-"):
                        raise ValueError(f"{where}: put a character that isn't a letter or digit (like - . _ /) "
                                         f"between {m.group()} and what's next to it")
        return self

    @property
    def pattern(self) -> bool:
        return bool(_placeholders(self.left))


_WORD = "A-Za-z0-9"
_PLACE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,30})\}")
_PLACE_SPLIT = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]{0,30}\}")


def _placeholders(template: str) -> list[str]:
    return _PLACE.findall(template)


def _template_rx(template: str, prefix: str) -> str:
    """A pattern rewrite's side as a regex: placeholders become named groups of one word."""
    out, pos = [], 0
    for m in _PLACE.finditer(template):
        out.append(re.escape(template[pos:m.start()]))
        out.append(f"(?P<{prefix}_{m.group(1)}>[{_WORD}]+)")
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return "".join(out)


def _fill_template(template: str, m: re.Match, prefix: str) -> str:
    return _PLACE.sub(lambda p: m.group(f"{prefix}_{p.group(1)}"), template)
# PEM blocks and long base64 runs (certificates, keys, keystores): never rewritten
_OPAQUE = re.compile(r"-----BEGIN |^[A-Za-z0-9+/=\r\n]{64,}$")


@lru_cache(maxsize=256)
def _glob(pattern: str) -> re.Pattern:
    return compile_glob(pattern)


@lru_cache(maxsize=256)
def _cached_rewriter(pairs: tuple[tuple[str, str], ...]):
    return _rewriter(list(pairs))


def _rewriter(pairs: list[tuple[str, str]]):
    if not pairs:
        return None
    patterns = [(a, b) for a, b in pairs if _placeholders(a)]
    table = {a: b for a, b in pairs if not _placeholders(a)}
    words = sorted(table, key=len, reverse=True)  # longest first: "app-test" before "test"
    # One pass over the text, patterns first: a rewritten part is never rewritten again
    alts = [f"(?P<p{i}>{_template_rx(a, f'p{i}')})" for i, (a, _) in enumerate(patterns)]
    if words:
        alts.append(f"(?P<w>{'|'.join(map(re.escape, words))})")
    rx = re.compile(rf"(?<![{_WORD}])(?:{'|'.join(alts)})(?![{_WORD}])")

    def which(m: re.Match) -> str:
        """The rewrite this match used, by its left side."""
        if words and m.group("w") is not None:
            return m.group("w")
        return next(patterns[i][0] for i in range(len(patterns)) if m.group(f"p{i}") is not None)

    def repl(m: re.Match) -> str:
        if words and m.group("w") is not None:
            return table[m.group("w")]
        i = next(i for i in range(len(patterns)) if m.group(f"p{i}") is not None)
        return _fill_template(patterns[i][1], m, f"p{i}")

    def text(s: str) -> str:
        return s if _OPAQUE.search(s) else rx.sub(repl, s)

    def value(v):
        if isinstance(v, str):
            return text(v)
        if isinstance(v, list):
            return [value(x) for x in v]
        if isinstance(v, dict):
            return {k: value(x) for k, x in v.items()}
        return v  # numbers, booleans, null keep their type and value

    def used(v, found: set) -> set:
        """The rewrites this value would use, by their left side (a word or a pattern)."""
        if isinstance(v, str):
            if not _OPAQUE.search(v):
                found.update(which(m) for m in rx.finditer(v))
        elif isinstance(v, list):
            for x in v:
                used(x, found)
        elif isinstance(v, dict):
            for x in v.values():
                used(x, found)
        return found
    value.used = used  # type: ignore[attr-defined]
    return value


class UnorderedRule(IgnoreKey):
    """A key (or a field inside it) holding a list whose order doesn't matter."""
    field: str | None = Field(default=None, max_length=256)  # a list inside JSON or YAML: "hosts", "tls.sans"
    separator: str | None = Field(default=None, max_length=8)  # for a text list: "," splits "a.com, b.com"

    @field_validator("field", "separator")
    @classmethod
    def _blank(cls, v: str | None) -> str | None:
        return v if v and v.strip() else None

    @cached_property
    def field_rx(self) -> re.Pattern | None:
        if not self.field:
            return None
        return re.compile("".join(".*" if c == "*" else re.escape(c) for c in self.field.strip().strip(".")))


# A group that repeats and holds a repeat itself ("(a+)+", "(\\w*)*"): catastrophic backtracking
_NESTED_REPEAT = re.compile(r"\((?:[^()\\]|\\.)*[*+}](?:[^()\\]|\\.)*\)[*+{]")


class VolatileRule(IgnoreKey):
    """Parts of a key's value that change on their own (timestamps, IDs, build numbers)."""
    pattern: str = Field(min_length=1, max_length=200)  # a regex, matched in text values

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, v: str) -> str:
        try:
            rx = re.compile(v)
        except re.error as e:
            raise ValueError(f"volatile pattern '{v}' isn't a valid regex: {e}") from e
        if rx.fullmatch(""):
            raise ValueError(f"volatile pattern '{v}' matches empty text, so it would match everywhere")
        if _NESTED_REPEAT.search(v):
            raise ValueError(f"volatile pattern '{v}' repeats a group that repeats inside, which can take "
                             "forever to match: write it without the nested repeat")
        return v

    @cached_property
    def rx(self) -> re.Pattern:
        return re.compile(self.pattern)


BLANK = "\u2047"  # what a volatile match is replaced with, on both sides


def _sorted(items: list) -> list:
    return sorted(items, key=lambda x: _json(x))


def _json(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalise(value: Any, unordered: list[UnorderedRule], volatile: list[VolatileRule],
              parse=None) -> tuple[Any, list[str]]:
    """The value as it's compared under these rules, and the field paths of the lists sorted.

    `parse(text)` turns a text holding JSON or YAML into its object or list (diff.structured);
    field rules only reach inside such values. Without rules the value comes back as it is."""
    sorted_at: list[str] = []
    if not (unordered or volatile):
        return value, sorted_at

    def blank(v: Any) -> Any:
        if isinstance(v, str):
            for r in volatile:
                v = r.rx.sub(BLANK, v)
            return v
        if isinstance(v, list):
            return [blank(x) for x in v]
        if isinstance(v, dict):
            return {k: blank(x) for k, x in v.items()}
        return v

    def order(v: Any, path: str, rules: list[UnorderedRule]) -> Any:
        for r in rules:
            if isinstance(v, list):
                sorted_at.append(path)
                return _sorted([order(x, f"{path}[{i}]", [q for q in rules if q is not r]) for i, x in enumerate(v)])
            if isinstance(v, str) and r.separator:
                sorted_at.append(path)
                return _sorted([x.strip() for x in v.split(r.separator)])
        return v

    whole = [r for r in unordered if not r.field]
    fields = [r for r in unordered if r.field]
    v = blank(value) if volatile else value
    if whole:
        if isinstance(v, str) and parse and not any(r.separator for r in whole):
            tree = parse(v)  # a text holding a JSON or YAML list
            v = tree if isinstance(tree, list) else v
        v = order(v, "", whole)
    if fields:
        tree = v if isinstance(v, (dict, list)) else parse(v) if parse else None
        if tree is not None:
            def walk(x: Any, path: str) -> Any:
                hit = [r for r in fields if r.field_rx.fullmatch(path)]
                if hit:
                    x = order(x, path, hit)
                if isinstance(x, dict):
                    return {k: walk(y, _field_join(path, k)) for k, y in x.items()}
                if isinstance(x, list):
                    return [walk(y, f"{path}[{i}]") for i, y in enumerate(x)]
                return x
            v = walk(tree, "")
    return v, sorted_at


def _field_join(base: str, key: Any) -> str:
    k = str(key)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", k):
        return f"{base}.{k}" if base else k
    return f"{base}[{_json(k)}]"


class Rules(BaseModel):
    mappings: list[Mapping] = Field(default_factory=list, max_length=100)
    ignore_paths: list[str] = Field(default_factory=list, max_length=200)
    ignore_keys: list[IgnoreRule] = Field(default_factory=list, max_length=200)
    rewrites: list[Rewrite] = Field(default_factory=list, max_length=50)
    # Keys compared as text only: no certificate, PEM or base64 comparator (diff.py)
    exact_keys: list[IgnoreKey] = Field(default_factory=list, max_length=200)
    # Lists compared regardless of order, and parts of values that change on their own (above)
    unordered_keys: list[UnorderedRule] = Field(default_factory=list, max_length=200)
    volatile: list[VolatileRule] = Field(default_factory=list, max_length=50)

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def _unique_words(self):
        for side in ("left", "right"):
            words = [getattr(r, side) for r in self.rewrites]
            dup = {w for w in words if words.count(w) > 1}
            if dup:
                raise ValueError(f"rewrites: '{sorted(dup)[0]}' is on the {side} of more than one rewrite")
        return self

    @cached_property
    def _to_right(self):
        return _rewriter([(r.left, r.right) for r in self.rewrites])

    @cached_property
    def _to_left(self):
        return _rewriter([(r.right, r.left) for r in self.rewrites])

    def _in_scope(self, key: str | None, paths: tuple[str, ...]) -> list[Rewrite]:
        return [r for r in self.rewrites if r.applies(key, paths)]

    def rewrite(self, value, to: str = "right", key: str | None = None, paths: tuple[str, ...] = ()):
        """A left value as the right side would write it (to="right"), or a right value as the
        left side would (to="left"). Only the rewrites whose scope takes in `key` in these secrets
        apply (with key None, all of them). Unchanged without rewrites."""
        if not self.rewrites:
            return value
        if key is None or not any(r.scoped for r in self.rewrites):
            fn = self._to_right if to == "right" else self._to_left
            return fn(value) if fn else value
        rws = self._in_scope(key, paths)
        if not rws:
            return value
        pairs = tuple((r.left, r.right) if to == "right" else (r.right, r.left) for r in rws)
        return _cached_rewriter(pairs)(value)

    @cached_property
    def _maps(self) -> list[tuple[re.Pattern, str, re.Pattern, str]]:
        return [(compile_glob(m.left), m.right, compile_glob(m.right), m.left) for m in self.mappings]

    @cached_property
    def _ignored_paths(self) -> list[re.Pattern]:
        return [compile_glob(p.strip().strip("/")) for p in self.ignore_paths if p.strip()]

    @cached_property
    def _ignored_keys(self) -> list[tuple[re.Pattern, str]]:
        return [(compile_glob(k.path.strip().strip("/") or "**"), k.key) for k in self.ignore_keys]

    @property
    def empty(self) -> bool:
        return not (self.mappings or self.ignore_paths or self.ignore_keys or self.rewrites or self.exact_keys
                    or self.unordered_keys or self.volatile)

    def to_right(self, left_path: str) -> str:
        for lrx, rtpl, _, _ in self._maps:
            if m := lrx.match(left_path):
                return _fill(rtpl, m.groups())
        return left_path

    def to_left(self, right_path: str) -> str:
        for _, _, rrx, ltpl in self._maps:
            if m := rrx.match(right_path):
                return _fill(ltpl, m.groups())
        return right_path

    def path_ignored(self, *paths: str) -> bool:
        return any(rx.match(p) for rx in self._ignored_paths for p in paths if p)

    def key_ignored(self, key: str, *paths: str) -> bool:
        """Whether a rule ignores the whole key (field rules ignore only part of it)."""
        return any(r.field is None for r in self.ignore_rules(key, *paths))

    def ignore_rules(self, key: str, *paths: str) -> list[IgnoreRule]:
        """The ignore rules that apply to this key in these secrets."""
        return [rule for (prx, kglob), rule in zip(self._ignored_keys, self.ignore_keys)
                if fnmatch.fnmatchcase(key, kglob) and any(prx.match(p) for p in paths if p)]

    @cached_property
    def _exact_keys(self) -> list[tuple[re.Pattern, str]]:
        return [(compile_glob(k.path.strip().strip("/") or "**"), k.key) for k in self.exact_keys]

    def exact_rules(self, key: str, *paths: str) -> list[IgnoreKey]:
        """The rules that compare this key as text only, in these secrets."""
        return [rule for (prx, kglob), rule in zip(self._exact_keys, self.exact_keys)
                if fnmatch.fnmatchcase(key, kglob) and any(prx.match(p) for p in paths if p)]

    def rewrite_words(self, value, key: str | None = None, paths: tuple[str, ...] = ()) -> list[str]:
        """The rewrites a left value uses, as "left → right", for explaining an equal result."""
        rws = self._in_scope(key, paths)
        if not rws:
            return []
        fn = _cached_rewriter(tuple((r.left, r.right) for r in rws))
        table = {r.left: r.right for r in rws}
        return [f"{w} → {table[w]}" for w in sorted(fn.used(value, set()))]

    @staticmethod
    def _scoped(rules: list, key: str, paths: tuple[str, ...]) -> list:
        return [r for r in rules if fnmatch.fnmatchcase(key, r.key)
                and any(_glob(r.path.strip().strip("/") or "**").match(p) for p in paths if p)]

    def unordered_rules(self, key: str, *paths: str) -> list[UnorderedRule]:
        return self._scoped(self.unordered_keys, key, paths)

    def volatile_rules(self, key: str, *paths: str) -> list[VolatileRule]:
        return self._scoped(self.volatile, key, paths)


def pair_paths(left: set[str], right: set[str], rules: Rules | None):
    """Pair up the two sides' secret paths under the rules.

    Returns (pairs, collisions, ignored): pairs maps a canonical key (the right-side form)
    to (left_path, right_path), where a missing side's path is where the secret *would* be,
    so a copy lands in the mapped place. collisions lists keys that more than one left path
    maps onto.
    """
    rules = rules or Rules()
    by_key: dict[str, list[str]] = {}
    for lp in left:
        by_key.setdefault(rules.to_right(lp), []).append(lp)
    pairs: dict[str, tuple[str, str]] = {}
    collisions: dict[str, list[str]] = {}
    for key, lps in by_key.items():
        if len(lps) > 1:
            collisions[key] = sorted(lps)
        pairs[key] = (sorted(lps)[0], key)
    for rp in right:
        if rp not in pairs:
            pairs[rp] = (rules.to_left(rp), rp)
    ignored = 0
    for key in list(pairs):
        lp, rp = pairs[key]
        if rules.path_ignored(lp, rp):
            del pairs[key]
            collisions.pop(key, None)
            ignored += 1
    return pairs, collisions, ignored


class Profile(BaseModel):
    """A saved comparison setup: rules plus, optionally, each side's mount and prefix."""

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    left_mount: str | None = None
    left_prefix: str | None = None
    right_mount: str | None = None
    right_prefix: str | None = None
    rules: Rules = Field(default_factory=Rules)
