"""Which capabilities a set of policies grants on a path, decided the way Vault decides it.

This mirrors Vault's ACL (vault/acl.go):
  * rules are keyed by their path: exact paths, prefix paths (ending in `*`, which is
    dropped) and segment-wildcard paths (containing `+`, kept as written);
  * rules with the same key, from one policy or several, are merged: capabilities are added
    up, and `deny` replaces everything;
  * a lookup tries the exact path, then the best of the longest prefix rule and every matching
    `+` rule, by Vault's priority order (see `_priority`);
  * up to Vault 2.2.1, for list requests (and sys/capabilities) a path ending in / is looked up
    without that slash first (exact, then wildcard rules), then as given;
  * from Vault 2.2.2 (vault/acl.go at v2.2.2):
      - exact rules match either slash form ("a" and "a/");
      - a list request on "a/" pools the wildcard candidates of "a" and "a/": the most specific
        deny wins if it's at least as specific as the most specific rule granting list, otherwise
        that rule, otherwise the most specific candidate;
      - other requests take the best wildcard match, and a segment-wildcard deny on the other
        slash form wins if it's at least as specific;
      - deny rules also apply case-insensitively: a deny that matches the lower-cased path wins
        unless the rule that matched as written is more specific.
OpenBao forked before either change and has its own order (internal/vault/policy/acl.go at v2.7.3):
the exact rule, then for list requests the exact rule without a trailing slash, then the best wildcard
rule for the path as written, then (list requests on "a/") for "a". Deny rules match case as written,
and there's a `scan` capability.
It's checked against real Vaults (1.21 and 2.2) and OpenBao (2.7) in tests/test_policy_acl.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .hcl import Policy

ORDER = ("sudo", "read", "list", "update", "delete", "create", "patch", "scan", "subscribe", "recover")


@dataclass
class Source:
    policy: str
    path: str  # the rule's path as written
    line: int | None
    capabilities: list[str]


@dataclass
class Entry:
    key: str  # exact path, prefix (without *), or segment-wildcard path (with any trailing *)
    kind: str  # exact | prefix | segment
    caps: set[str] = field(default_factory=set)
    sources: list[Source] = field(default_factory=list)

    @property
    def deny(self) -> bool:
        return "deny" in self.caps


@dataclass
class Decision:
    capabilities: list[str]  # as sys/capabilities reports them: ["deny"] when nothing is granted
    entry: Entry | None  # the rule key that decided it (None: nothing matched)

    @property
    def denied(self) -> bool:
        return self.capabilities == ["deny"]

    def allows(self, *caps: str) -> bool:
        return "root" in self.capabilities or any(c in self.capabilities for c in caps)


@dataclass(frozen=True)
class Behaviour:
    """Policy evaluation details that differ between Vault versions and OpenBao."""
    lookup: str = "current"  # current (Vault 2.2.2+) | legacy (Vault up to 2.2.1) | openbao
    deny_case_insensitive: bool = True  # Vault 2.2.2+: deny rules match regardless of case
    label: str = "Vault 2.2.2 or later"
    known: bool = True  # False: the server's rules couldn't be told, so these are a guess


LEGACY = Behaviour(lookup="legacy", deny_case_insensitive=False, label="Vault 2.2.1 or earlier")
CURRENT = Behaviour()
OPENBAO = Behaviour(lookup="openbao", deny_case_insensitive=False, label="OpenBao")
UNKNOWN = Behaviour(label="unknown rules, assumed Vault 2.2.2 or later", known=False)


def behaviour_for(version: str | None, product: str = "Vault") -> Behaviour:
    """The evaluation rules of a server: `product` is "Vault", "Vault Enterprise" or "OpenBao",
    `version` like "1.21.4" or "2.2.2+ent". An unreadable Vault version gives UNKNOWN."""
    if product == "OpenBao":
        return OPENBAO
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        return UNKNOWN
    return CURRENT if tuple(map(int, m.groups())) >= (2, 2, 2) else LEGACY


class ACL:
    def __init__(self, policies: list[Policy], behaviour: Behaviour = CURRENT, _lowered: bool = False):
        self.behaviour = behaviour
        self.root = any(p.name == "root" for p in policies)
        self._lower: ACL | None = None
        if behaviour.deny_case_insensitive and not _lowered and any(
                "deny" in r.capabilities for p in policies for r in p.rules):
            # Like Vault's folded deny index: only the deny rules, with lower-cased paths
            lowered = [Policy(p.name, [type(r)(**{**r.__dict__, "path": r.path.lower()}) for r in p.rules
                                       if "deny" in r.capabilities]) for p in policies]
            self._lower = ACL(lowered, behaviour, _lowered=True)
        self.exact: dict[str, Entry] = {}
        self.prefix: dict[str, Entry] = {}
        self.segment: dict[str, Entry] = {}
        for pol in policies:
            for r in pol.rules:
                path = r.path
                if "+" in path:
                    tree, kind, key = self.segment, "segment", path
                elif path.endswith("*"):
                    tree, kind, key = self.prefix, "prefix", path[:-1]
                else:
                    tree, kind, key = self.exact, "exact", path
                e = tree.setdefault(key, Entry(key=key, kind=kind))
                caps = set(r.capabilities) & {*ORDER, "deny"}
                e.caps = {"deny"} if "deny" in caps or e.deny else e.caps | caps
                e.sources.append(Source(pol.name, r.path, r.line, list(r.capabilities)))

    # ----------------------------------------------------------------- lookup

    def decide(self, path: str, list_op: bool = True) -> Decision:
        """The capabilities on `path`. `list_op`: evaluate it as a list request, as Vault does for
        sys/capabilities (the default)."""
        if self.root:
            return Decision(["root"], None)
        path = path.lstrip("/")
        if self.behaviour.lookup == "legacy":
            e = self._entry_legacy(path, list_op)
        elif self.behaviour.lookup == "openbao":
            e = self._entry_openbao(path, list_op)
        else:
            e = self._entry_current(path, list_op)
            if e is not None and not e.deny and self._lower is not None:
                deny = self._folded_deny(path, list_op, e)
                if deny is not None:
                    return Decision(["deny"], deny)
        return Decision(_report(e.caps if e else set()), e)

    def _entry_legacy(self, path: str, list_op: bool) -> Entry | None:
        """Up to Vault 2.2.1."""
        e = self.exact.get(path)
        if e is None and list_op and path.endswith("/"):
            e = self.exact.get(path[:-1]) or self._non_exact(path[:-1])
        if e is None:
            e = self._non_exact(path)
        return e

    def _entry_openbao(self, path: str, list_op: bool) -> Entry | None:
        """OpenBao (AllowOperation in internal/vault/policy/acl.go)."""
        e = self.exact.get(path)
        if e is None and list_op:
            e = self.exact.get(path.removesuffix("/"))
        if e is None:
            e = self._non_exact(path)
        if e is None and list_op and path.endswith("/"):
            e = self._non_exact(path[:-1])
        return e

    def _entry_current(self, path: str, list_op: bool) -> Entry | None:
        """From Vault 2.2.2."""
        e = self.exact.get(path)
        if e is None:
            e = self.exact.get(path[:-1] if path.endswith("/") else path + "/")
        if e is not None:
            return e
        if list_op and path.endswith("/"):
            pool = self._candidates(path[:-1]) + self._candidates(path)
            if not pool:
                return None
            deny = max((c for c in pool if c[1].deny), key=lambda c: c[0], default=None)
            lister = max((c for c in pool if "list" in c[1].caps), key=lambda c: c[0], default=None)
            if deny is not None and (lister is None or lister[0] < deny[0]):
                return deny[1]
            if lister is not None:
                return lister[1]
            return max(pool, key=lambda c: c[0])[1]
        primary = self._candidates(path)
        best = max(primary, key=lambda c: c[0]) if primary else None
        if best is None or not best[1].deny:
            alt = path[:-1] if path.endswith("/") else path + "/"
            denies = [c for c in self._candidates(alt) if c[1].kind == "segment" and not c[2] and c[1].deny]
            denies = [c for c in denies if best is None or not c[0] < best[0]]
            if denies:  # Vault takes the first it finds; with several, take the most specific
                return max(denies, key=lambda c: c[0])[1]
        return best[1] if best else None

    def _descrs(self, path: str, list_op: bool) -> list[tuple[tuple, Entry]]:
        """Every rule matching the path as written (and trimmed, for a list on "a/"), exact ones first."""
        forms = [path, path[:-1]] if list_op and path.endswith("/") else [path]
        out: list[tuple[tuple, Entry]] = []
        for f in forms:
            if f in self.exact:
                out.append(((float("inf"), True, 0, len(f), f), self.exact[f]))
            out += [(prio, e) for prio, e, *_ in self._candidates(f)]
        return out

    def _folded_deny(self, path: str, list_op: bool, winner: Entry) -> Entry | None:
        """A deny matching the lower-cased path, unless the winning rule is more specific."""
        assert self._lower is not None
        denies = [d for d in self._lower._descrs(path.lower(), list_op) if d[1].deny]
        if not denies:
            return None
        deny = max(denies, key=lambda d: d[0])
        for prio, e in self._descrs(path, list_op):
            if e is winner:
                folded = (prio[0], prio[1], prio[2], len(prio[4].lower()), prio[4].lower())
                return None if deny[0] < folded else deny[1]
        return deny[1]  # the winner isn't among the candidates: fail closed, as Vault does

    def matching(self, path: str) -> list[Entry]:
        """Every rule that matches `path` (or, for a trailing slash, the path without it)."""
        out: list[Entry] = []
        for p in {path, path[:-1]} if path.endswith("/") else {path}:
            if p in self.exact:
                out.append(self.exact[p])
            out += [e for k, e in self.prefix.items() if p.startswith(k)]
            out += [c[1] for c in self._candidates(p, prefixes=False)]
        return list({id(e): e for e in out}.values())

    def _non_exact(self, path: str) -> Entry | None:
        cands = self._candidates(path)
        if not cands:
            return None
        return max(cands, key=lambda c: c[0])[1]

    def _candidates(self, path: str, prefixes: bool = True) -> list[tuple[tuple, Entry, bool]]:
        """(priority, rule, is a prefix match) for the longest prefix rule and every matching + rule."""
        cands: list[tuple[tuple, Entry, bool]] = []
        best = max((k for k in self.prefix if path.startswith(k)), key=len, default=None) if prefixes else None
        if best is not None:
            cands.append((_priority(len(best), True, 0, best), self.prefix[best], True))
        parts = path.split("/")
        for full, e in self.segment.items():
            if not full:
                continue
            first = full.index("+")
            is_prefix = full.endswith("*")
            wc = full[:-1] if is_prefix else full
            acl_parts = wc.split("/")
            if len(parts) < len(acl_parts) or (not is_prefix and len(acl_parts) != len(parts)):
                continue
            n_wc = 0
            for i, ap in enumerate(acl_parts):
                if ap == "+":
                    n_wc += 1
                elif ap == parts[i]:
                    pass
                elif is_prefix and i == len(acl_parts) - 1 and parts[i].startswith(ap):
                    pass
                else:
                    break
            else:
                cands.append((_priority(first, is_prefix, n_wc, wc), e, is_prefix))
        return cands


def _priority(first_wildcard: int, is_prefix: bool, n_wildcards: int, path: str) -> tuple:
    """Higher sorts later = wins. Vault's rules, in order: the first wildcard comes later;
    not ending in *; fewer + segments; a longer path; lexicographically greater."""
    return (first_wildcard, not is_prefix, -n_wildcards, len(path), path)


def _report(caps: set[str]) -> list[str]:
    if "deny" in caps:
        return ["deny"]
    out = [c for c in ORDER if c in caps]
    return out or ["deny"]
