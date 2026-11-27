"""Parsing Vault ACL policies (HCL or JSON) into path rules.

Vault policies use a small part of HCL: `path "<path>" { capabilities = [...] }` blocks, with
optional fields such as `allowed_parameters` or the legacy `policy = "read"`. This parser reads
that subset: blocks, `key = value` fields, strings, numbers, booleans, lists and objects, and
`#`, `//` and `/* */` comments. Fields it doesn't model are kept in `extra`, untouched.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

CAPABILITIES = ("create", "read", "update", "patch", "delete", "list", "sudo", "deny", "subscribe", "recover",
                "scan")  # scan: OpenBao
# The legacy `policy = "..."` field, as Vault expands it
LEGACY = {
    "deny": ["deny"],
    "read": ["read", "list"],
    "write": ["create", "read", "update", "delete", "list"],
    "sudo": ["create", "read", "update", "delete", "list", "sudo"],
}


class PolicyParseError(ValueError):
    def __init__(self, message: str, line: int | None = None):
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


@dataclass
class PathRule:
    path: str  # as written, without a leading /
    capabilities: list[str]
    line: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)  # allowed_parameters, min_wrapping_ttl, ...
    unknown: list[str] = field(default_factory=list)  # capability names Vault doesn't know


@dataclass
class Policy:
    name: str
    rules: list[PathRule]
    text: str = ""
    other: list[str] = field(default_factory=list)  # top-level things that aren't path blocks


# --------------------------------------------------------------------------- tokens

_TOKEN = re.compile(r"""
    (?P<ws>[ \t\r]+)
  | (?P<nl>\n)
  | (?P<comment>\#[^\n]*|//[^\n]*)
  | (?P<block>/\*.*?\*/)
  | (?P<string>"(?:[^"\\\n]|\\.)*")
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_.\-]*)
  | (?P<punct>[{}\[\]=,:])
""", re.S | re.X)


def _tokens(text: str) -> list[tuple[str, Any, int]]:
    out: list[tuple[str, Any, int]] = []
    pos, line = 0, 1
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            snippet = text[pos:pos + 20].split("\n")[0]
            raise PolicyParseError(f"unexpected {snippet!r}", line)
        kind, val = m.lastgroup, m.group()
        if kind == "string":
            try:
                out.append(("string", json.loads(val), line))
            except ValueError as e:
                raise PolicyParseError(f"bad string {val}", line) from e
        elif kind == "number":
            out.append(("number", float(val) if "." in val else int(val), line))
        elif kind == "ident":
            out.append(("bool", val == "true", line) if val in ("true", "false") else ("ident", val, line))
        elif kind == "punct":
            out.append((val, val, line))
        line += val.count("\n")
        pos = m.end()
    out.append(("eof", None, line))
    return out


class _Parser:
    def __init__(self, text: str):
        self.t = _tokens(text)
        self.i = 0

    def peek(self, k: int = 0):
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expect(self, kind: str):
        tok = self.next()
        if tok[0] != kind:
            raise PolicyParseError(f"expected {kind!r}, found {tok[1]!r}", tok[2])
        return tok

    def body(self, end: str) -> list[tuple[str, list[str], Any, int]]:
        """Items until `end`: (key, labels, value, line). A block `key "a" "b" { }` has labels."""
        items = []
        while self.peek()[0] != end:
            kind, key, line = self.next()
            if kind not in ("ident", "string"):
                raise PolicyParseError(f"expected a name, found {key!r}", line)
            labels = []
            while self.peek()[0] == "string":
                labels.append(self.next()[1])
            if self.peek()[0] in ("=", ":"):
                self.next()
                value = self.value()
            elif self.peek()[0] == "{":
                self.next()
                value = self.body("}")
                self.expect("}")
            else:
                tok = self.peek()
                raise PolicyParseError(f"expected '=' or '{{' after {key!r}", tok[2])
            items.append((key, labels, value, line))
            if self.peek()[0] == ",":
                self.next()
        return items

    def value(self):
        kind, val, line = self.next()
        if kind in ("string", "number", "bool"):
            return val
        if kind == "[":
            out = []
            while self.peek()[0] != "]":
                out.append(self.value())
                if self.peek()[0] == ",":
                    self.next()
                elif self.peek()[0] != "]":
                    raise PolicyParseError("expected ',' or ']' in a list", self.peek()[2])
            self.next()
            return out
        if kind == "{":
            items = self.body("}")
            self.expect("}")
            return items
        raise PolicyParseError(f"unexpected {val!r}", line)


def _plain(v: Any) -> Any:
    """Body items (list of tuples) to plain dicts, for `extra` fields."""
    if isinstance(v, list) and v and all(isinstance(x, tuple) for x in v):
        out: dict = {}
        for key, labels, val, _ in v:
            target = out
            for lab in [key, *labels][:-1]:
                target = target.setdefault(lab, {})
            target[[key, *labels][-1]] = _plain(val)
        return out
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _obj(items: list) -> dict[str, Any]:
    """A block's body as a dict (an empty body is an empty dict)."""
    return _plain(items) if items else {}


def _rule(path: str, fields: dict[str, Any], line: int | None) -> PathRule:
    caps: list[str] = []
    raw = fields.pop("capabilities", [])
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not all(isinstance(c, str) for c in raw):
        raise PolicyParseError(f'path "{path}": capabilities must be a list of names', line)
    caps += [c.strip().lower() for c in raw]
    legacy = fields.pop("policy", None)
    if legacy is not None:
        if legacy not in LEGACY:
            raise PolicyParseError(f'path "{path}": unknown policy value {legacy!r}', line)
        caps += LEGACY[legacy]
    caps = list(dict.fromkeys(caps))
    return PathRule(path=path.lstrip("/"), capabilities=caps, line=line, extra=fields,
                    unknown=[c for c in caps if c not in CAPABILITIES])


def parse_policy(text: str, name: str = "policy") -> Policy:
    """Parse a policy written in HCL or JSON. Raises PolicyParseError."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except ValueError as e:
            raise PolicyParseError(f"not valid JSON: {e}") from e
        return _from_json(doc, name, text)
    items = _Parser(text).body("eof")
    rules: list[PathRule] = []
    other: list[str] = []
    for key, labels, value, line in items:
        if key != "path":
            other.append(key)
            continue
        if not labels and isinstance(value, list):  # path { "a" { ... } "b" { ... } }
            for k2, l2, v2, line2 in value:
                if not isinstance(v2, list) or not all(isinstance(x, tuple) for x in v2):
                    raise PolicyParseError(f"path {k2!r} needs a {{ }} block", line2)
                rules.append(_rule(k2, _obj(v2), line2))
            continue
        if len(labels) != 1 or not isinstance(value, list):
            raise PolicyParseError('a path rule looks like: path "secret/data/*" { capabilities = ["read"] }', line)
        rules.append(_rule(labels[0], _obj(value), line))
    return Policy(name=name, rules=rules, text=text, other=other)


def _from_json(doc: Any, name: str, text: str) -> Policy:
    if not isinstance(doc, dict):
        raise PolicyParseError("a JSON policy is an object with a \"path\" key")
    paths = doc.get("path") or {}
    if not isinstance(paths, dict):
        raise PolicyParseError("\"path\" must be an object of paths")
    rules = []
    for path, fields in paths.items():
        if isinstance(fields, list):  # [{"capabilities": [...]}]
            merged: dict = {}
            for f in fields:
                merged.update(f)
            fields = merged
        if not isinstance(fields, dict):
            raise PolicyParseError(f"path {path!r} must be an object")
        rules.append(_rule(path, dict(fields), None))
    return Policy(name=name, rules=rules, text=text, other=[k for k in doc if k != "path"])


def to_hcl(policy: Policy) -> str:
    """Write rules back as HCL, in a stable format (used for display and later for output)."""
    out = []
    for r in policy.rules:
        caps = ", ".join(f'"{c}"' for c in r.capabilities)
        lines = [f'path "{r.path}" {{', f"  capabilities = [{caps}]"]
        for k, v in r.extra.items():
            lines.append(f"  {k} = {json.dumps(v)}")
        out.append("\n".join(lines + ["}"]))
    return "\n\n".join(out) + "\n"
