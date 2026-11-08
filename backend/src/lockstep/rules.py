"""Comparison profile rules: path mappings and ignore rules. Pure logic, no I/O.

Patterns are globs over secret paths (relative to each side's prefix):
    *    any characters except "/"  (one path segment, or part of one)
    **   any characters including "/" (any depth, possibly empty)

A mapping pairs a left and a right pattern with the same wildcards in the same order.
`services/*/prod/**` <-> `services/*/staging/**` maps `services/billing/prod/db/main`
to `services/billing/staging/db/main` and back. The first matching mapping wins; paths no
mapping matches are compared as they are.
"""

from __future__ import annotations

import fnmatch
import re
from functools import cached_property

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


class Rules(BaseModel):
    mappings: list[Mapping] = Field(default_factory=list, max_length=100)
    ignore_paths: list[str] = Field(default_factory=list, max_length=200)
    ignore_keys: list[IgnoreKey] = Field(default_factory=list, max_length=200)

    model_config = {"frozen": True}

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
        return not (self.mappings or self.ignore_paths or self.ignore_keys)

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
        return any(fnmatch.fnmatchcase(key, kglob) and any(prx.match(p) for p in paths if p)
                   for prx, kglob in self._ignored_keys)


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
