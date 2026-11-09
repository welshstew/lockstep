"""Reader for Java's proprietary keystore formats, JKS and JCEKS.

`cryptography` reads PKCS#12 but not these. The format (big-endian, Java DataOutputStream):
  magic (JKS 0xFEEDFEED / JCEKS 0xCECECECE), version, entry count, then per entry:
    tag 1 private key:  alias, timestamp, EncryptedPrivateKeyInfo, certificate chain
    tag 2 trusted cert: alias, timestamp, certificate
    tag 3 secret key:   JCEKS only, a Java-serialised SealedObject (not parsed)
  and a trailing SHA-1 over (password as UTF-16BE + "Mighty Aphrodite" + everything before).

Certificates are stored in the clear, so they can be listed without the password. The
password lets us check the store's integrity and decrypt JKS private keys (Sun's simple
SHA-1 keystream scheme). JCEKS keys use PBEWithMD5AndTripleDES and aren't decrypted here.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from cryptography import x509

from . import der

JKS_MAGIC = 0xFEEDFEED
JCEKS_MAGIC = 0xCECECECE
# Told to the user for every JKS/JCEKS keystore. The SHA-1 and MD5 below are fixed by these
# formats: we only verify and decrypt existing files and never create hashes of our own.
WEAK_FORMAT_NOTE = ("{kind} protects keys and checks integrity with SHA-1{extra}, which is weak by today's "
                    "standards. Java has used PKCS#12 by default since Java 9; consider converting: "
                    "keytool -importkeystore -srckeystore old.{ext} -destkeystore new.p12 -deststoretype pkcs12")
JKS_KEY_OID = "1.3.6.1.4.1.42.2.17.1.1"  # Sun's proprietary JKS key protection
JCEKS_KEY_OID = "1.3.6.1.4.1.42.2.19.1"  # PBEWithMD5AndTripleDES


class KeystoreError(ValueError):
    pass


@dataclass
class Entry:
    alias: str
    kind: str  # private_key | trusted_cert | secret_key
    timestamp_ms: int
    certs: list[x509.Certificate] = field(default_factory=list)
    encrypted_key: bytes | None = None  # EncryptedPrivateKeyInfo DER
    key_algorithm_oid: str | None = None
    pkcs8: bytes | None = None  # decrypted private key (JKS + correct password)
    note: str = ""


@dataclass
class Keystore:
    kind: str  # jks | jceks
    version: int
    entries: list[Entry]
    integrity: str  # ok | bad_password | unchecked | incomplete
    notes: list[str] = field(default_factory=list)


def detect(buf: bytes) -> str | None:
    if len(buf) < 12:
        return None
    magic = struct.unpack(">I", buf[:4])[0]
    return {JKS_MAGIC: "jks", JCEKS_MAGIC: "jceks"}.get(magic)


class _Reader:
    def __init__(self, buf: bytes):
        self.buf, self.pos = buf, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise KeystoreError("truncated keystore")
        b = self.buf[self.pos:self.pos + n]
        self.pos += n
        return b

    def u2(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u8(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def utf(self) -> str:
        return self.take(self.u2()).decode("utf-8", errors="replace")  # Java modified UTF-8 ≈ UTF-8

    def cert(self, version: int) -> x509.Certificate:
        if version == 2:
            ctype = self.utf()
            if ctype != "X.509":
                raise KeystoreError(f"unsupported certificate type {ctype!r}")
        return x509.load_der_x509_certificate(self.take(self.u4()))


def _pw(password: str) -> bytes:
    return password.encode("utf-16-be")


def parse(buf: bytes, password: str | None = None) -> Keystore:
    kind = detect(buf)
    if not kind:
        raise KeystoreError("not a JKS/JCEKS keystore")
    r = _Reader(buf)
    r.u4()
    version = r.u4()
    if version not in (1, 2):
        raise KeystoreError(f"unsupported keystore version {version}")
    count = r.u4()
    entries: list[Entry] = []
    notes: list[str] = [WEAK_FORMAT_NOTE.format(
        kind=kind.upper(), ext=kind, extra=" (and MD5 with Triple DES for keys)" if kind == "jceks" else "")]
    complete = True
    for _ in range(count):
        tag = r.u4()
        alias, ts = r.utf(), r.u8()
        if tag == 1:
            enc = r.take(r.u4())
            chain = [r.cert(version) for _ in range(r.u4())]
            e = Entry(alias, "private_key", ts, chain, encrypted_key=enc)
            try:
                algo = der.children(der.children(der.read(enc).value)[0].value)[0]
                e.key_algorithm_oid = der.oid(algo.value)
            except der.DerError:
                pass
            entries.append(e)
        elif tag == 2:
            entries.append(Entry(alias, "trusted_cert", ts, [r.cert(version)]))
        elif tag == 3:
            entries.append(Entry(alias, "secret_key", ts, note="Secret key entry (contents not shown)."))
            notes.append("This keystore holds secret-key entries, which are Java-serialised objects. "
                         "Entries after the first one can't be listed.")
            complete = False
            break
        else:
            raise KeystoreError(f"unknown entry tag {tag}")

    integrity = "unchecked"
    if complete:
        body, digest = buf[:r.pos], buf[r.pos:r.pos + 20]
        if len(digest) == 20 and password is not None:
            # SHA-1 is mandated by the JKS/JCEKS format; we only verify existing files.
            calc = hashlib.sha1(_pw(password) + b"Mighty Aphrodite" + body).digest()  # nosec B324
            integrity = "ok" if calc == digest else "bad_password"
    else:
        integrity = "incomplete"

    if password is not None and integrity != "bad_password":
        for e in entries:
            if e.kind != "private_key" or not e.encrypted_key:
                continue
            if e.key_algorithm_oid == JKS_KEY_OID:
                e.pkcs8 = _decrypt_jks_key(e.encrypted_key, password)
                if e.pkcs8 is None:
                    e.note = "The key password differs from the store password; key not decrypted."
            elif e.key_algorithm_oid == JCEKS_KEY_OID:
                e.note = "JCEKS key protection (PBEWithMD5AndTripleDES): key present, not decrypted."
            else:
                e.note = f"Unknown key protection {e.key_algorithm_oid}; key not decrypted."
    return Keystore(kind, version, entries, integrity, notes)


def _decrypt_jks_key(epki: bytes, password: str) -> bytes | None:
    """Sun's JKS key protection: salt(20) || ciphertext || check(20), XOR with a SHA-1 keystream."""
    try:
        enc = der.children(der.read(epki).value)[1].value
    except (der.DerError, IndexError):
        return None
    if len(enc) < 40:
        return None
    salt, data, check = enc[:20], enc[20:-20], enc[-20:]
    pw = _pw(password)
    stream, cur = b"", salt
    while len(stream) < len(data):
        cur = hashlib.sha1(pw + cur).digest()  # nosec B324 (JKS key protection is defined with SHA-1)
        stream += cur
    plain = bytes(a ^ b for a, b in zip(data, stream))
    return plain if hashlib.sha1(pw + plain).digest() == check else None  # nosec B324 (format-mandated check)
