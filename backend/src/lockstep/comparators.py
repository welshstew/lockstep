"""Comparators: two texts that are written differently but hold the same thing.

A comparator decodes both values and compares what they hold, so encoding noise doesn't make a
key differ. Each is exact about something and never fuzzy:

  PEM          the DER bytes of each block, in order. Line endings, line wrapping and spacing
               around the blocks don't count. Text outside the blocks, or RFC 1421 headers
               (Proc-Type, DEK-Info), turn the comparator off: the values are compared as text.
  certificate  a PEM certificate block is the same certificate when its DER bytes (and so its
               SHA-256 fingerprint) are the same. When they aren't, the reason names which
               fields changed: subject, issuer, names (SANs), validity, key, serial.
  private key  compared like any PEM block (same label, same DER bytes). The same key in another
               format (PKCS#1 on one side, PKCS#8 on the other) is *different*, because many
               libraries read only one of them; the reason says it's the same key.
  base64       wrapped base64 (a value with line breaks inside it) is the same data when the
               decoded bytes are the same. Only line breaks are ignored: padding, the alphabet
               (standard or URL-safe), spaces and a single-line value's trailing newline still
               count, because decoders differ on them.

  keystore     a PKCS#12 that opens without a password, or a JKS or JCEKS (whose certificates
               can be read without one), held as base64. Compared as its entries: alias, kind,
               certificate fingerprints and the key. What a save changes (timestamps, salts, the
               MAC, entry order) doesn't count. A keystore with a password is opened with a
               password stored next to it in the same secret (a key named like *pass*, *pin* or
               *secret*) or Java's default, `changeit`. When none opens it, the key is *not
               compared*, rather than called different. The same goes for a JKS private key that
               can't be decrypted and whose encrypted bytes differ.

What isn't ignored, on purpose: the PEM label (`BEGIN X509 CERTIFICATE` isn't `BEGIN CERTIFICATE`
to a parser that looks for the latter). A certificate in PEM on one side and base64 DER on the other is
the same certificate but not the same value (a service that reads PEM can't read DER), so it's
*different*, with that as the reason. Certificates in a different order are different (a chain's
order matters).

`compare()` returns None when no comparator applies, and the caller compares the values as text.
Nothing here returns a value: reasons name kinds and fields only.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.serialization import pkcs12

from .analyze import certs, der, javaks

MAX_TEXT = 1024 * 1024
MIN_B64 = 16

_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)
_B64_STD = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_B64_URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")
CERT_LABELS = {"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"}
KEY_FORMATS = {"PRIVATE KEY": "PKCS#8", "RSA PRIVATE KEY": "PKCS#1", "EC PRIVATE KEY": "SEC1"}


@dataclass
class Verdict:
    equal: bool
    reason: str  # for an equal verdict: "equal as certificates (same fingerprint; line endings differ)"
    noise: str = ""  # for an equal verdict: what differs in the text ("line endings differ")
    compared: bool = True  # False: the values couldn't be compared (a keystore needs a password)


@dataclass
class _Block:
    label: str
    der: bytes
    kind: str  # "certificate", "private key" or "block"
    cert: x509.Certificate | None = None
    key: bytes | None = None  # a private key's PKCS#8 DER, to say "same key, other format"
    wrap: tuple = ()  # body line lengths

    @property
    def canon(self) -> tuple:
        return self.label, self.der


def _block(label: str, body: str) -> _Block | None:
    if ":" in body:
        return None  # RFC 1421 headers: compared as text
    lines = [ln for ln in re.split(r"\r?\n", body.strip()) if ln.strip()]
    compact = "".join(ln.strip() for ln in lines)
    if not _B64_STD.fullmatch(compact or "-") or len(compact) % 4:
        return None
    try:
        der = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    wrap = tuple(len(ln.strip()) for ln in lines)
    if label in CERT_LABELS and label != "TRUSTED CERTIFICATE":
        try:
            cert = x509.load_der_x509_certificate(der)
            return _Block(label, der, "certificate", cert, None, wrap)
        except ValueError:
            pass
    if label in KEY_FORMATS:
        try:
            key = serialization.load_der_private_key(der, None)
            pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
            return _Block(label, der, "private key", None, pkcs8, wrap)
        except (ValueError, TypeError):
            pass
    return _Block(label, der, "block", None, None, wrap)


def pem_blocks(s: str) -> list[_Block] | None:
    """The PEM blocks of a value that's nothing but PEM blocks (and whitespace), else None."""
    if "-----BEGIN " not in s or len(s) > MAX_TEXT:
        return None
    out, pos = [], 0
    for m in _BLOCK.finditer(s):
        if s[pos:m.start()].strip():
            return None
        b = _block(m.group(1), m.group(2))
        if b is None:
            return None
        out.append(b)
        pos = m.end()
    if not out or s[pos:].strip():
        return None
    return out


def wrapped_base64(s: str) -> bytes | None:
    """The bytes of base64 with line breaks inside it (standard or URL-safe, padded), else None."""
    if len(s) > MAX_TEXT or "\n" not in s.strip():
        return None
    return _base64(s)


def _base64(s: str) -> bytes | None:
    if len(s) > MAX_TEXT:
        return None
    compact = s.replace("\r", "").replace("\n", "")
    if len(compact) < MIN_B64 or len(compact) % 4:
        return None
    if _B64_STD.fullmatch(compact):
        alt = None
    elif _B64_URL.fullmatch(compact):
        alt = b"-_"
    else:
        return None
    try:
        return base64.b64decode(compact, altchars=alt, validate=True)
    except (binascii.Error, ValueError):
        return None


def _alphabet(s: str) -> str:
    return "URL-safe" if re.search(r"[-_]", s) else "standard"


def _noise(a: str, b: str, wraps_differ: bool) -> str:
    out = []
    if ("\r\n" in a) != ("\r\n" in b):
        out.append("line endings differ")
    if wraps_differ:
        out.append("line wrapping differs")
    if not out:
        out.append("spacing differs")
    return "; ".join(out)


# --------------------------------------------------------------------------- certificates


def _names(c: x509.Certificate) -> set:
    try:
        return set(map(str, c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value))
    except x509.ExtensionNotFound:
        return set()


def cert_changes(a: x509.Certificate, b: x509.Certificate) -> str:
    """Why two certificates differ, by field name: "renewed: new validity", "different subject, key"."""
    changed = []
    if a.subject != b.subject:
        changed.append("subject")
    if a.issuer != b.issuer:
        changed.append("issuer")
    if _names(a) != _names(b):
        changed.append("names (SANs)")
    if (a.not_valid_before_utc, a.not_valid_after_utc) != (b.not_valid_before_utc, b.not_valid_after_utc):
        changed.append("validity")
    if certs.spki(a.public_key()) != certs.spki(b.public_key()):
        changed.append("key")
    if a.serial_number != b.serial_number:
        changed.append("serial")
    same = {"subject", "issuer", "names (SANs)"}.isdisjoint(changed)
    if same and "validity" in changed:
        return "renewed: new validity" + (" and key" if "key" in changed else "") + " (same subject, issuer and names)"
    if not changed:
        return "different certificate (same subject, names, validity and key; other fields differ)"
    return "different certificate: " + ", ".join(changed)


# --------------------------------------------------------------------------- compare


def _what(blocks: list[_Block]) -> str:
    kinds = {b.kind for b in blocks}
    n = len(blocks)
    if kinds == {"certificate"}:
        return "certificate" if n == 1 else f"chain of {n} certificates"
    if kinds == {"private key"} and n == 1:
        return "private key"
    if kinds == {"certificate", "private key"}:
        return "certificate and key"
    return "PEM block" if n == 1 else f"PEM blocks ({n})"


def _plural(what: str) -> str:
    return {"certificate": "certificates", "private key": "private keys"}.get(what, "PEM")


def _pem(a: str, b: str, la: list[_Block], lb: list[_Block]) -> Verdict:
    ca, cb = [x.canon for x in la], [x.canon for x in lb]
    if ca == cb:
        noise = _noise(a, b, [x.wrap for x in la] != [x.wrap for x in lb])
        what = _what(la)
        same = "same fingerprint" if what == "certificate" else f"same {what}"
        return Verdict(True, f"equal as {_plural(what) if len(la) == 1 else 'PEM'} ({same}; {noise})", noise)
    if sorted(ca) == sorted(cb):
        return Verdict(False, f"same {_what(la)} in a different order")
    if len(la) != len(lb):
        return Verdict(False, f"{len(la)} PEM block{'s' if len(la) != 1 else ''} on the left, {len(lb)} on the right")
    for i, (x, y) in enumerate(zip(la, lb)):
        if x.canon == y.canon:
            continue
        where = "" if len(la) == 1 else f"block {i + 1} of {len(la)}: "
        if x.der == y.der:
            return Verdict(False, where + f"same {x.kind}, but labelled `BEGIN {x.label}` on the left "
                                          f"and `BEGIN {y.label}` on the right")
        if x.key is not None and x.key == y.key:
            return Verdict(False, where + f"same private key, but {KEY_FORMATS[x.label]} on the left "
                                          f"and {KEY_FORMATS[y.label]} on the right")
        if x.cert is not None and y.cert is not None:
            return Verdict(False, where + cert_changes(x.cert, y.cert))
        if x.kind == y.kind == "private key":
            return Verdict(False, where + "different private key")
        if x.kind != y.kind or x.label != y.label:
            return Verdict(False, where + f"{x.label.lower()} on the left, {y.label.lower()} on the right")
        return Verdict(False, where + f"different {x.label.lower()}")
    return Verdict(False, "different PEM")  # unreachable: some block differs


# --------------------------------------------------------------------------- keystores


@dataclass
class _Entry:
    alias: str
    kind: str  # "key", "certificate" or "secret key"
    certs: tuple[str, ...]  # SHA-256 fingerprints, in chain order
    key: bytes | None  # PKCS#8 DER, or the encrypted key bytes (a JKS key not decrypted)
    objects: tuple = ()  # the certificates, for explaining a change
    clear: bool = True  # key is PKCS#8 (False: still encrypted)


@dataclass
class _Store:
    kind: str  # "PKCS#12", "JKS" or "JCEKS"
    entries: list[_Entry]
    sealed: bool  # some keys are still encrypted: the same only if the encrypted bytes are
    locked: bool = False  # needs a password none of the candidates opened
    opened_with: str = ""  # where the password came from ("`keystore_password`")


Passwords = list[tuple[str, str]]  # (where it came from, the password), tried in order


def keystore(raw: bytes, passwords: Passwords = ()) -> _Store | None:
    """The entries of a keystore, opened without a password or with one of `passwords`.
    None: not a keystore (or one that can't be read whole)."""
    kind = javaks.detect(raw)
    if kind:
        ks, used = None, ""
        for label, pw in passwords:
            k = javaks.parse(raw, pw)
            if k.integrity == "ok":
                ks, used = k, label
                break
        ks = ks or javaks.parse(raw, None)
        if ks.integrity == "incomplete":
            return None  # secret-key entries: not all of it can be read
        out = [_Entry(e.alias, "key" if e.kind == "private_key" else "certificate",
                      tuple(certs.fingerprint(c) for c in e.certs), e.pkcs8 or e.encrypted_key, tuple(e.certs),
                      clear=e.pkcs8 is not None)
               for e in ks.entries]
        return _Store(kind.upper(), out, any(e.kind == "key" and not e.clear for e in out), opened_with=used)
    if not der.is_pfx(raw):
        return None
    store, used = None, ""
    for label, pw in [("", None), ("", ""), *passwords]:
        try:
            store = pkcs12.load_pkcs12(raw, pw.encode() if isinstance(pw, str) else pw)
            used = label
            break
        except (ValueError, TypeError):
            continue
    if store is None:
        return _Store("PKCS#12", [], False, locked=True)
    out = []
    name = lambda c: c.friendly_name.decode(errors="replace") if c and c.friendly_name else ""  # noqa: E731
    if store.key is not None or store.cert is not None:
        key = store.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()) if store.key is not None else None
        chain = (store.cert.certificate,) if store.cert else ()
        out.append(_Entry(name(store.cert), "key" if key else "certificate",
                          tuple(certs.fingerprint(c) for c in chain), key, chain))
    for extra in store.additional_certs:
        out.append(_Entry(name(extra), "certificate", (certs.fingerprint(extra.certificate),), None,
                          (extra.certificate,)))
    return _Store("PKCS#12", out, False, opened_with=used)


def _count(n: int, word: str) -> str:
    return f"{n} {word if n == 1 else word[:-1] + 'ies' if word.endswith('y') else word + 's'}"


def _opened(sa: _Store, sb: _Store) -> str:
    """How the keystores were opened, for the reason."""
    labels = list(dict.fromkeys(x for x in (sa.opened_with, sb.opened_with) if x))
    return f"; opened with {' and '.join(labels)}" if labels else ""


def _keystores(sa: _Store, sb: _Store) -> Verdict:
    if sa.kind != sb.kind:
        return Verdict(False, f"{sa.kind} on the left, {sb.kind} on the right")
    if sa.locked or sb.locked:
        where = "both sides" if sa.locked and sb.locked else "the left" if sa.locked else "the right"
        return Verdict(False, f"{sa.kind} keystore with a password on {where}: no key in the secret opens it, "
                              "so it can't be compared (add the password to the secret, next to the keystore)",
                       compared=False)
    key = lambda e: (e.alias, e.kind, e.certs, e.key or b"")  # noqa: E731
    ea, eb = sorted(sa.entries, key=key), sorted(sb.entries, key=key)
    if [key(e) for e in ea] == [key(e) for e in eb]:
        noise = "entry order differs" if [key(e) for e in sa.entries] != [key(e) for e in sb.entries] else \
            "saved again: timestamps or encryption salts differ"
        keys = sum(e.kind == "key" for e in ea)
        what = ", ".join(x for x in (_count(keys, "key") if keys else "",
                                     _count(sum(len(e.certs) for e in ea), "certificate")) if x)
        return Verdict(True, f"equal as {sa.kind} keystores (same {what}; {noise}{_opened(sa, sb)})", noise)
    by_a = {(e.alias, e.kind): e for e in sa.entries}
    by_b = {(e.alias, e.kind): e for e in sb.entries}
    changed = []
    if by_a.keys() != by_b.keys():
        only_a, only_b = len(by_a.keys() - by_b.keys()), len(by_b.keys() - by_a.keys())
        changed.append(" and ".join(x for x in (f"{_count(only_a, 'entry')} only on the left" if only_a else "",
                                                f"{_count(only_b, 'entry')} only on the right" if only_b else "") if x)
                       )
    both = [(by_a[k], by_b[k]) for k in sorted(by_a.keys() & by_b.keys())]
    cert_diffs = [(x, y) for x, y in both if x.certs != y.certs]
    if cert_diffs:
        x, y = cert_diffs[0]
        detail = ""
        if len(cert_diffs) == 1 and x.objects and y.objects and len(x.certs) == len(y.certs):
            i = next(i for i, (p, q) in enumerate(zip(x.certs, y.certs)) if p != q)
            detail = f" ({cert_changes(x.objects[i], y.objects[i])})"
        changed.append(f"certificates differ in {_count(len(cert_diffs), 'entry')}" + detail)
    key_diffs = [(x, y) for x, y in both if x.kind == "key" and x.certs == y.certs and x.key != y.key]
    known = [(x, y) for x, y in key_diffs if x.clear and y.clear]
    sealed = len(key_diffs) - len(known)
    if known:
        changed.append(f"{_count(len(known), 'private key')} differ" if len(known) > 1 else "the private key differs")
    if sealed and not changed:
        return Verdict(False, f"same {sa.kind} entries and certificates, but {_count(sealed, 'private key')} "
                              f"can't be checked without the password (encrypted differently on each side)",
                       compared=False)
    if sealed:
        changed.append(f"{_count(sealed, 'private key')} can't be checked without the password")
    if not changed:
        changed.append("entries differ")
    return Verdict(False, f"different {sa.kind} keystore: " + "; ".join(changed) + _opened(sa, sb))


def compare(a: object, b: object, passwords_a: Passwords = (), passwords_b: Passwords = ()) -> Verdict | None:
    """Compare two values with the comparator their content calls for. None: none applies.
    `passwords_*`: passwords to open each side's keystore with (see keystore)."""
    if not (isinstance(a, str) and isinstance(b, str)) or a == b:
        return None
    try:
        la, lb = pem_blocks(a), pem_blocks(b)
        if la and lb:
            return _pem(a, b, la, lb)
        if la or lb:
            blocks, other, side = (la, b, "left") if la else (lb, a, "right")
            raw = _base64(other.strip())
            if raw is not None and len(blocks) == 1 and raw == blocks[0].der:
                pem_side, der_side = (side, "right" if side == "left" else "left")
                return Verdict(False, f"same {_what(blocks)}, but PEM on the {pem_side} and base64 DER on the {der_side}")
            return None
        ka, kb = _base64(a), _base64(b)
        sa = keystore(ka, passwords_a) if ka else None
        sb = keystore(kb, passwords_b) if kb and sa else None
        if sa and sb:
            return _keystores(sa, sb)
        ba, bb = wrapped_base64(a), wrapped_base64(b)
        if ba is None and bb is None:
            if ka and kb and ka != kb:  # one-line base64 on both sides: explain two certificates
                try:
                    return Verdict(False, cert_changes(x509.load_der_x509_certificate(ka),
                                                       x509.load_der_x509_certificate(kb)))
                except ValueError:
                    pass
            return None
        ba = ba if ba is not None else _base64(a)
        bb = bb if bb is not None else _base64(b)
        if ba is None or bb is None:
            return None
        if ba == bb:
            if _alphabet(a) != _alphabet(b):
                return Verdict(False, f"same bytes, but {_alphabet(a)} base64 on the left and {_alphabet(b)} on the right")
            noise = "line endings differ" if a.replace("\r\n", "\n") == b.replace("\r\n", "\n") else "line breaks differ"
            return Verdict(True, f"equal as base64 (same {len(ba)} bytes; {noise})", noise)
        try:
            xa, xb = x509.load_der_x509_certificate(ba), x509.load_der_x509_certificate(bb)
        except ValueError:
            return Verdict(False, "different data (both base64; the decoded bytes differ)")
        return Verdict(False, cert_changes(xa, xb))
    except Exception:  # noqa: BLE001 (a comparator is best effort: fall back to comparing text)
        return None
