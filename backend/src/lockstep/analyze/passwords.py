"""Finding a keystore's password elsewhere in the secret tree.

Keystore passwords often live away from the keystore itself, for example
`some-secrets/files/certs.p12` with its password in `some-secrets/strings/KEYSTORE_PASSWORD`.
Candidates are short, single-line string values whose key name or secret name looks like a
password (pass, pwd, pin, secret…), or that sit in a folder named like one (passwords/, creds/…). They're ranked by how close they are to the keystore
(same secret, then the longest shared folder path) and how much their names share with the
keystore's (cert, keystore, app…), then tried against the keystore.

Pure logic, no I/O: callers read the secrets and pass them in. Values never leave the server.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .detect import Node, analyze

HINT = re.compile(r"pass|pwd|pin|secret", re.I)  # in a key name or the secret's own name
# Folders count only when the whole name says so: "some-secrets/" holds everything, not just passwords
FOLDER_HINT = re.compile(r"^(passwords?|passwds?|pwds?|pins?|passphrases?|credentials?|creds)$", re.I)
LOCKED_KINDS = {"pkcs12", "jks", "jceks", "encrypted_private_key"}
MAX_PASSWORD_LEN = 256
# Java's default keystore password: worth trying, it's often left in place.
DEFAULTS = {"changeit": "Java's default keystore password"}

# Words that say "this is a keystore" (on the keystore's side) or "for a keystore" (on a candidate's)
STORE_WORDS = {"keystore", "truststore", "store", "p12", "pkcs12", "pfx", "jks", "jceks", "cert", "certificate",
               "tls", "ssl", "key"}
# Too generic to count as a shared name
STOPWORDS = {"the", "and", "for", "data", "value", "values", "file", "files", "secret", "secrets", "string",
             "strings", "config", "configs", "password", "passwords", "pass", "pwd", "pin", "base64", "b64",
             "prod", "dev", "test", "staging"}


def needs_password(node: Node) -> bool:
    """Is any keystore (or encrypted key) in this analysis still locked?"""
    return (node.kind in LOCKED_KINDS and node.needs_password) or any(needs_password(c) for c in node.children)


def opens(value: Any, password: str) -> bool:
    """Does this password open the keystore(s) in `value`?"""
    try:
        a = analyze(value, password=password)
    except Exception:  # noqa: BLE001 (a candidate that breaks parsing just doesn't open it)
        return False
    return a.password_used and not needs_password(a.root)


def tokens(text: str) -> set[str]:
    """Name words: split on punctuation and camelCase, lower-cased, plural 's' dropped."""
    words = re.findall(r"[A-Z]+(?![a-z])\d*|[A-Z]?[a-z]+\d*|\d+", text)
    out = set()
    for w in (w.lower() for w in words):
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        if len(w) >= 2:
            out.add(w)
    return out


@dataclass
class Candidate:
    path: str  # secret path within the mount
    key: str
    score: float
    reasons: list[str] = field(default_factory=list)
    value: str = field(default="", repr=False)  # never returned to the browser

    @property
    def label(self) -> str:
        return f"{self.path} · {self.key}" if self.path else self.key


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def rank(store_path: str, store_key: str, secrets: dict[str, dict], limit: int = 40) -> list[Candidate]:
    """Password candidates for the keystore at store_path/store_key, best first.

    `secrets` maps secret paths (within the mount) to their data.
    """
    store_dir = _segments(store_path)[:-1]
    store_words = (tokens(store_path) | tokens(store_key)) - STOPWORDS
    out: list[Candidate] = []
    for path, data in secrets.items():
        segs = _segments(path)
        for key, value in (data or {}).items():
            if (path == store_path and key == store_key) or not isinstance(value, str):
                continue
            if not value or len(value) > MAX_PASSWORD_LEN or "\n" in value:
                continue
            if not (HINT.search(key) or (segs and HINT.search(segs[-1]))
                    or any(FOLDER_HINT.match(f) for f in segs[:-1])):
                continue
            reasons: list[str] = []
            if path == store_path:
                score = 100.0
                reasons.append("same secret")
            else:
                shared = 0
                for a, b in zip(store_dir, segs[:-1]):
                    if a != b:
                        break
                    shared += 1
                hops = (len(store_dir) - shared) + (len(segs) - 1 - shared)  # folders between them
                score = 40.0 + 10 * shared - 4 * hops
                reasons.append("same folder" if hops == 0 else f"{shared} folder{'s' if shared != 1 else ''} in common"
                               if shared else "elsewhere in the tree")
            mine = (tokens(path) | tokens(key)) - STOPWORDS
            common = sorted(store_words & mine)
            if common:
                score += 12 * len(common)
                reasons.append("shares " + ", ".join(common))
            if mine & STORE_WORDS:
                score += 6
            if len(value) > 64:
                score -= 10  # long values are more often tokens or keys than passwords
            out.append(Candidate(path=path, key=key, score=score, reasons=reasons, value=value))
    out.sort(key=lambda c: (-c.score, c.path, c.key))
    return out[:limit]


def search_root(store_path: str) -> str:
    """Where to look: the keystore's top-level folder ("" for a secret at the mount root)."""
    segs = _segments(store_path)
    return f"{segs[0]}/" if len(segs) > 1 else ""
