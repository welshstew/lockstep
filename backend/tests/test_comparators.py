"""Comparators: the same certificate, PEM or base64 data written differently is equal, with the
reason saying how the text differs. Anything a service could read differently stays different."""

import base64
import datetime as dt
import os
import random
import textwrap

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from lockstep.comparators import compare
from lockstep.diff import diff_keys, diff_secret, SideInfo
from lockstep.rules import Rules

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def make_cert(cn="app.example", key=None, days=90, serial=1, sans=("app.example",), start=NOW):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(serial).not_valid_before(start).not_valid_after(start + dt.timedelta(days=days)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(key, hashes.SHA256()), key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def rewrap(p: str, width: int) -> str:
    out = []
    for block in p.strip().split("-----END CERTIFICATE-----"):
        if not block.strip():
            continue
        body = "".join(block.replace("-----BEGIN CERTIFICATE-----", "").split())
        out.append("-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(body, width)) + "\n-----END CERTIFICATE-----\n")
    return "".join(out)


@pytest.fixture(scope="module")
def certs():
    c, key = make_cert()
    return c, key


def status(a, b, **kw):
    (k,) = diff_keys({"v": a}, {"v": b}, **kw)
    return k


# ---- equal: encoding noise only

def test_same_certificate_with_crlf_is_equal(certs):
    c, _ = certs
    k = status(pem(c), pem(c).replace("\n", "\r\n"))
    assert k.status == "equal" and k.reason == "equal as certificates (same fingerprint; line endings differ)"


def test_same_certificate_wrapped_differently_or_with_spacing_is_equal(certs):
    c, _ = certs
    assert status(pem(c), rewrap(pem(c), 76)).reason == "equal as certificates (same fingerprint; line wrapping differs)"
    assert status(pem(c), "\n  " + pem(c).strip()).reason == "equal as certificates (same fingerprint; spacing differs)"


def test_same_chain_is_equal(certs):
    c, _ = certs
    other, _ = make_cert("ca.example")
    chain = pem(c) + pem(other)
    k = status(chain, chain.replace("\n", "\r\n"))
    assert k.status == "equal" and k.reason == "equal as PEM (same chain of 2 certificates; line endings differ)"


def test_same_private_key_same_format_is_equal(certs):
    _, key = certs
    p = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    k = status(p, p.replace("\n", "\r\n"))
    assert k.status == "equal" and k.reason == "equal as private keys (same private key; line endings differ)"


def test_wrapped_base64_is_equal_when_the_bytes_are():
    data = os.urandom(300)
    one = base64.b64encode(data).decode()
    wrapped = "\n".join(textwrap.wrap(one, 76)) + "\n"
    k = status(one, wrapped)
    assert k.status == "equal" and k.reason == "equal as base64 (same 300 bytes; line breaks differ)"
    assert status(wrapped, wrapped.replace("\n", "\r\n")).reason == "equal as base64 (same 300 bytes; line endings differ)"


# ---- different, and why

def test_renewed_certificate(certs):
    c, key = certs
    renewed, _ = make_cert(key=key, serial=2, start=NOW + dt.timedelta(days=60))
    k = status(pem(c), pem(renewed))
    assert k.status == "different" and k.reason == "renewed: new validity (same subject, issuer and names)"
    rekeyed, _ = make_cert(serial=3, start=NOW + dt.timedelta(days=60))
    assert status(pem(c), pem(rekeyed)).reason == "renewed: new validity and key (same subject, issuer and names)"


def test_certificate_fields_that_changed(certs):
    c, key = certs
    other, _ = make_cert("other.example", key=key, sans=("other.example", "www.other.example"))
    assert status(pem(c), pem(other)).reason == "different certificate: subject, issuer, names (SANs)"


def test_chain_order_and_length(certs):
    c, _ = certs
    other, _ = make_cert("ca.example")
    assert status(pem(c) + pem(other), pem(other) + pem(c)).reason == "same chain of 2 certificates in a different order"
    assert status(pem(c) + pem(other), pem(c)).reason == "2 PEM blocks on the left, 1 on the right"
    third, _ = make_cert("ca2.example")
    assert status(pem(c) + pem(other), pem(c) + pem(third)).reason.startswith("block 2 of 2: different certificate")


def test_key_in_another_format_is_different_but_named():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p8 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    p1 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption())
    k = status(p1.decode(), p8.decode())
    assert k.status == "different" and k.reason == "same private key, but PKCS#1 on the left and PKCS#8 on the right"
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert status(p8.decode(), other.decode()).reason == "different private key"


def test_pem_label_counts(certs):
    c, _ = certs
    relabelled = pem(c).replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE").replace("END CERTIFICATE", "END X509 CERTIFICATE")
    k = status(pem(c), relabelled)
    assert k.status == "different"
    assert k.reason == "same certificate, but labelled `BEGIN CERTIFICATE` on the left and `BEGIN X509 CERTIFICATE` on the right"


def test_pem_and_der_are_the_same_certificate_but_different(certs):
    c, _ = certs
    der = base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
    k = status(pem(c), der)
    assert k.status == "different" and k.reason == "same certificate, but PEM on the left and base64 DER on the right"
    assert status(der, pem(c)).reason == "same certificate, but PEM on the right and base64 DER on the left"


def test_base64_alphabet_padding_and_spaces_count():
    data = b"\xfb\xff" * 60 + b"\x01"
    std = base64.b64encode(data).decode()
    url = base64.urlsafe_b64encode(data).decode()
    wrapped = "\n".join(textwrap.wrap(std, 64))
    assert status(wrapped, url).reason == "same bytes, but standard base64 on the left and URL-safe on the right"
    k = status(wrapped, std.rstrip("="))
    assert k.status == "different"
    assert status(wrapped, wrapped.replace("\n", " \n")).status == "different"


def test_text_outside_blocks_or_headers_turn_the_comparator_off(certs):
    c, _ = certs
    bag = "Bag Attributes\n    friendlyName: app\n" + pem(c)
    assert status(bag, pem(c).replace("\n", "\r\n")).reason == "different value"
    legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"
    assert compare(legacy, legacy.replace("\n", "\r\n")) is None


def test_trailing_newline_on_a_single_line_value_still_counts():
    token = base64.b64encode(os.urandom(32)).decode()
    k = status(token, token + "\n")
    assert k.status == "different" and k.reason == "differs only in spaces or newlines at the start or end"


def test_short_multiline_text_isnt_base64():
    assert compare("abcd\nefgh", "abcdefgh") is None


# ---- profiles: compare as text

def test_exact_rule_turns_comparators_off(certs):
    c, _ = certs
    rules = Rules(exact_keys=[{"key": "tls_*", "path": "apps/**"}])
    left = {"tls_cert": pem(c), "ca": pem(c)}
    right = {"tls_cert": pem(c).replace("\n", "\r\n"), "ca": pem(c).replace("\n", "\r\n")}
    d = diff_secret("apps/web", SideInfo(state="present"), left, SideInfo(state="present"), right,
                    rules=rules)
    by = {k.key: k for k in d.keys}
    assert by["ca"].status == "equal"
    assert by["tls_cert"].status == "different" and d.status == "different"
    assert by["tls_cert"].reason == ("line endings differ; it would be equal as certificates (same fingerprint; "
                                     "line endings differ), but profile rule `tls_*` under apps/** compares it as text")
    assert Rules(exact_keys=[{"key": "x"}]).empty is False


# ---- property: never equal unless the decoded content is the same

def test_never_equal_when_the_content_differs(certs):
    c, _ = certs
    rnd = random.Random(7)
    base = pem(c)
    der = c.public_bytes(serialization.Encoding.DER)
    for _ in range(200):
        b = bytearray(der)
        b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
        mutated = "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(base64.b64encode(bytes(b)).decode(), 64)) \
                  + "\n-----END CERTIFICATE-----\n"
        v = compare(base, mutated.replace("\n", "\r\n") if rnd.random() < 0.5 else mutated)
        assert v is None or not v.equal
    for _ in range(200):
        x = os.urandom(rnd.randrange(12, 200))
        y = bytearray(x)
        y[rnd.randrange(len(y))] ^= 1 << rnd.randrange(8)
        a = "\n".join(textwrap.wrap(base64.b64encode(x).decode(), 20))
        bb = base64.b64encode(bytes(y)).decode()
        v = compare(a, bb)
        assert v is None or not v.equal


def test_reasons_never_hold_values(certs):
    c, key = certs
    renewed, _ = make_cert(key=key, serial=2, start=NOW + dt.timedelta(days=60))
    body = "".join(pem(c).splitlines()[1:-1])
    for a, b in ((pem(c), pem(c).replace("\n", "\r\n")), (pem(c), pem(renewed))):
        r = status(a, b).reason
        assert body[:20] not in r and "app.example" not in r


# ---- keystores

import hashlib  # noqa: E402
import struct  # noqa: E402

from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402


def _utf(s: str) -> bytes:
    return struct.pack(">H", len(s.encode())) + s.encode()


def _cert(c) -> bytes:
    d = c.public_bytes(serialization.Encoding.DER)
    return _utf("X.509") + struct.pack(">I", len(d)) + d


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = bytes([n]) if n < 128 else bytes([0x80 | len(n.to_bytes((n.bit_length() + 7) // 8, "big"))]) + \
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def jks_key(key, password: str) -> bytes:
    """A private key protected the way JKS does it (salt, SHA-1 keystream, check), as EncryptedPrivateKeyInfo."""
    plain = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pw, salt = password.encode("utf-16-be"), os.urandom(20)
    stream, cur = b"", salt
    while len(stream) < len(plain):
        cur = hashlib.sha1(pw + cur).digest()  # nosec B324 (the JKS format)
        stream += cur
    enc = salt + bytes(a ^ b for a, b in zip(plain, stream)) + hashlib.sha1(pw + plain).digest()  # nosec B324
    oid = bytes.fromhex("060a2b060104012a02110101")  # 1.3.6.1.4.1.42.2.17.1.1
    return _der(0x30, _der(0x30, oid + b"\x05\x00") + _der(0x04, enc))


def jks(entries, ts=1000, password=None) -> str:
    """A JKS keystore as base64: entries are ("cert", alias, cert) or ("key", alias, encrypted, [chain])."""
    body = struct.pack(">III", 0xFEEDFEED, 2, len(entries))
    for e in entries:
        if e[0] == "cert":
            body += struct.pack(">I", 2) + _utf(e[1]) + struct.pack(">Q", ts) + _cert(e[2])
        else:
            body += (struct.pack(">I", 1) + _utf(e[1]) + struct.pack(">Q", ts) + struct.pack(">I", len(e[2])) + e[2]
                     + struct.pack(">I", len(e[3])) + b"".join(_cert(c) for c in e[3]))
    pw = password.encode("utf-16-be") if password else b""
    body += hashlib.sha1(pw + b"Mighty Aphrodite" + body).digest()  # nosec B324 (the format's digest)
    return base64.b64encode(body).decode()


def p12(key, cert, extra=(), name=b"app") -> str:
    raw = pkcs12.serialize_key_and_certificates(name, key, cert, list(extra), serialization.NoEncryption())
    return base64.b64encode(raw).decode()


def test_truststore_saved_again_is_equal(certs):
    c, _ = certs
    other, _ = make_cert("ca.example")
    a = jks([("cert", "app", c), ("cert", "ca", other)], ts=1000)
    b = jks([("cert", "ca", other), ("cert", "app", c)], ts=2000)
    k = status(a, b)
    assert k.status == "equal" and k.reason == "equal as JKS keystores (same 2 certificates; entry order differs)"
    assert status(a, jks([("cert", "app", c), ("cert", "ca", other)], ts=5)).reason == \
        "equal as JKS keystores (same 2 certificates; saved again: timestamps or encryption salts differ)"


def test_keystore_differences_named(certs):
    c, key = certs
    other, _ = make_cert("ca.example")
    renewed, _ = make_cert(key=key, serial=2, start=NOW + dt.timedelta(days=60))
    a = jks([("cert", "app", c), ("cert", "ca", other)])
    assert status(a, jks([("cert", "app", renewed), ("cert", "ca", other)])).reason == \
        "different JKS keystore: certificates differ in 1 entry (renewed: new validity (same subject, issuer and names))"
    assert status(a, jks([("cert", "app", c)])).reason == "different JKS keystore: 1 entry only on the left"
    enc1, enc2 = b"\x30\x03\x02\x01\x01", b"\x30\x03\x02\x01\x02"
    k1 = jks([("key", "app", enc1, [c])])
    assert status(k1, jks([("key", "app", enc1, [c])], ts=9)).status == "equal"
    k = status(k1, jks([("key", "app", enc2, [c])]))
    assert k.status == "not_compared" and k.reason == ("same JKS entries and certificates, but 1 private key can't be "
                                                       "checked without the password (encrypted differently on each side)")
    assert status(k1, jks([("key", "app", enc2, [renewed])])).reason == (
        "different JKS keystore: certificates differ in 1 entry (renewed: new validity (same subject, issuer and names))")


def test_pkcs12_without_password(certs):
    c, key = certs
    other, _ = make_cert("ca.example")
    a, b = p12(key, c, [other]), p12(key, c, [other])
    assert a != b  # a new MAC salt each time
    k = status(a, b)
    assert k.status == "equal" and k.reason.startswith("equal as PKCS#12 keystores (same 1 key, 2 certificates;")
    rekeyed, newkey = make_cert()
    assert status(a, p12(newkey, rekeyed, [other])).reason == \
        "different PKCS#12 keystore: certificates differ in 1 entry (different certificate: key)"
    assert status(a, jks([("cert", "app", c)])).reason == "PKCS#12 on the left, JKS on the right"


def locked_p12(key, cert, password: bytes) -> str:
    enc = serialization.BestAvailableEncryption(password)
    return base64.b64encode(pkcs12.serialize_key_and_certificates(b"app", key, cert, None, enc)).decode()


def test_keystore_with_a_password(certs):
    c, key = certs
    a, b = locked_p12(key, c, b"s3cret"), locked_p12(key, c, b"s3cret")
    k = status(a, b)
    assert k.status == "not_compared"
    assert k.reason == ("PKCS#12 keystore with a password on both sides: no key in the secret opens it, so it can't be "
                        "compared (add the password to the secret, next to the keystore)")
    d = diff_secret("x", SideInfo(state="present"), {"store": a, "store_password": "s3cret"},
                    SideInfo(state="present"), {"store": b, "store_password": "s3cret"})
    by = {x.key: x for x in d.keys}
    assert by["store"].status == "equal" and d.status == "equal"
    assert by["store"].reason == ("equal as PKCS#12 keystores (same 1 key, 1 certificate; saved again: timestamps or "
                                  "encryption salts differ; opened with the password in `store_password`)")
    assert "s3cret" not in by["store"].reason
    # only the left's password is there: the right can't be opened
    d = diff_secret("x", SideInfo(state="present"), {"store": a, "store_password": "s3cret"},
                    SideInfo(state="present"), {"store": b})
    store = next(x for x in d.keys if x.key == "store")
    assert store.status == "not_compared" and store.reason.startswith("PKCS#12 keystore with a password on the right")
    # Java's default password is tried too
    ja, jb = locked_p12(key, c, b"changeit"), locked_p12(key, c, b"changeit")
    assert status(ja, jb).reason.endswith("opened with Java's default password)")


def test_not_compared_secret_status(certs):
    c, key = certs
    a, b = locked_p12(key, c, b"pw-1"), locked_p12(key, c, b"pw-1")
    P = SideInfo(state="present")
    d = diff_secret("x", P, {"store": a, "user": "u"}, P, {"store": b, "user": "u"})
    assert d.status == "not_compared"
    d = diff_secret("x", P, {"store": a, "user": "u"}, P, {"store": b, "user": "v"})
    assert d.status == "different"  # a real difference wins
    rules = Rules(ignore_keys=[{"key": "store"}])
    assert diff_secret("x", P, {"store": a}, P, {"store": b}, rules=rules).status == "equal"
    from lockstep.diff import summarize
    assert summarize([diff_secret("x", P, {"store": a}, P, {"store": b})])["not_compared"] == 1


def test_jks_opened_with_its_password(certs):
    c, key = certs
    a = jks([("key", "app", jks_key(key, "storepw"), [c])], password="storepw")
    b = jks([("key", "app", jks_key(key, "storepw"), [c])], ts=7, password="storepw")
    P = SideInfo(state="present")
    d = diff_secret("x", P, {"keystore.jks": a, "keystore.password": "storepw"}, P, {"keystore.jks": b, "keystore.password": "storepw"})
    by = {x.key: x for x in d.keys}
    assert by["keystore.jks"].status == "equal", by["keystore.jks"].reason
    assert by["keystore.jks"].reason.endswith("opened with the password in `keystore.password`)")
    other = ec.generate_private_key(ec.SECP256R1())
    c2 = jks([("key", "app", jks_key(other, "storepw"), [c])], password="storepw")
    d = diff_secret("x", P, {"keystore.jks": a, "keystore.password": "storepw"}, P, {"keystore.jks": c2, "keystore.password": "storepw"})
    assert d.keys[0].status == "different" and d.keys[0].reason.startswith("different JKS keystore: the private key differs")
    assert status(a, b).status == "not_compared"  # without the password, the salts differ


# ---- pattern rewrites

def test_pattern_rewrites():
    from pydantic import ValidationError
    rules = Rules.model_validate({"rewrites": [{"left": "{app}-test-db", "right": "{app}-dev-db"},
                                               {"left": "test", "right": "dev"}]})
    assert rules.rewrite("billing-api-test-db on test") == "billing-api-dev-db on dev"
    assert rules.rewrite("billing-api-dev-db on dev", to="left") == "billing-api-test-db on test"
    (k,) = diff_keys({"db": "orders-test-db"}, {"db": "orders-dev-db"}, rules=rules, paths=("x",))
    assert k.status == "equal" and k.reason == "equal after rewrite `{app}-test-db → {app}-dev-db`"
    assert rules.rewrite("orders-testx-db") == "orders-testx-db"
    for bad in ({"left": "{a}test", "right": "{a}dev"}, {"left": "{a}-x", "right": "{b}-y"},
                {"left": "{a}{b}-x", "right": "{a}{b}-y"}, {"left": "{a}", "right": "{a}-y"},
                {"left": "{a}-{a}", "right": "{a}-y"}):
        with pytest.raises(ValidationError):
            Rules.model_validate({"rewrites": [bad]})


def test_one_line_base64_certificates_are_explained(certs):
    c, key = certs
    renewed, _ = make_cert(key=key, serial=2, start=NOW + dt.timedelta(days=60))
    der = lambda x: base64.b64encode(x.public_bytes(serialization.Encoding.DER)).decode()  # noqa: E731
    k = status(der(c), der(renewed))
    assert k.status == "different" and k.reason == "renewed: new validity (same subject, issuer and names)"
