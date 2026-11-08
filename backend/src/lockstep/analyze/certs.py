"""Certificate details and chain validation.

The chain builder is our own (not cryptography's PolicyBuilder) so it can explain every
link: which issuer was found, whether its signature verifies, whether it's a CA, whether
it's in date, and where the chain stops. The verdict:
  trusted          reaches a trust anchor and every link is good
  untrusted_root   ends at a self-signed root that isn't a trust anchor
  incomplete       an issuer couldn't be found
  invalid          a link failed (bad signature, not a CA, expired or not yet valid)
"""

from __future__ import annotations

import datetime as dt
from functools import lru_cache
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

EXPIRING_DAYS = 30
MAX_DEPTH = 10

_EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "TLS server", ExtendedKeyUsageOID.CLIENT_AUTH: "TLS client",
    ExtendedKeyUsageOID.CODE_SIGNING: "Code signing", ExtendedKeyUsageOID.EMAIL_PROTECTION: "Email",
    ExtendedKeyUsageOID.TIME_STAMPING: "Time stamping", ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP signing",
}


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_description(public_key) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.curve.name}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(public_key, dsa.DSAPublicKey):
        return f"DSA {public_key.key_size}"
    return type(public_key).__name__


def _ext(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def validity(cert: x509.Certificate, at: dt.datetime | None = None) -> tuple[str, int]:
    """(status, days until expiry): status is valid | expiring | expired | not_yet_valid."""
    at = at or now()
    days = (cert.not_valid_after_utc - at).days
    if at < cert.not_valid_before_utc:
        return "not_yet_valid", days
    if at > cert.not_valid_after_utc:
        return "expired", days
    return ("expiring" if days < EXPIRING_DAYS else "valid"), days


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:  # noqa: BLE001 (any verification failure)
        return False


def is_ca(cert: x509.Certificate) -> bool:
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    return bool(bc and bc.ca)


def info(cert: x509.Certificate) -> dict[str, Any]:
    status, days = validity(cert)
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    ku = _ext(cert, ExtensionOID.KEY_USAGE)
    eku = _ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    ski = _ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    aki = _ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    usages = []
    if ku:
        for name in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                     "key_agreement", "key_cert_sign", "crl_sign"):
            if getattr(ku, name):
                usages.append(name.replace("_", " "))
    sans = []
    if san:
        sans = [f"DNS:{n}" for n in san.get_values_for_type(x509.DNSName)]
        sans += [f"IP:{n}" for n in san.get_values_for_type(x509.IPAddress)]
        sans += [f"email:{n}" for n in san.get_values_for_type(x509.RFC822Name)]
        sans += [f"URI:{n}" for n in san.get_values_for_type(x509.UniformResourceIdentifier)]
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "status": status,
        "days_left": days,
        "sans": sans,
        "key_usage": usages,
        "extended_key_usage": [_EKU_NAMES.get(o, o.dotted_string) for o in eku] if eku else [],
        "is_ca": bool(bc and bc.ca),
        "path_length": bc.path_length if bc else None,
        "self_signed": is_self_signed(cert),
        "public_key": key_description(cert.public_key()),
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else
        cert.signature_algorithm_oid._name,  # noqa: SLF001
        "sha256": fingerprint(cert),
        "sha1": cert.fingerprint(hashes.SHA1()).hex(),  # nosec B303 (display-only fingerprint, as keytool shows)
        "subject_key_id": ski.digest.hex() if ski else None,
        "authority_key_id": aki.key_identifier.hex() if aki and aki.key_identifier else None,
    }


@lru_cache(maxsize=1)
def system_roots() -> tuple[x509.Certificate, ...]:
    """Mozilla's root store as shipped by certifi (already a dependency via httpx).

    Loaded one certificate at a time: the bundle contains a legacy root with a non-positive
    serial number, which newer `cryptography` releases reject. Skipping it keeps one bad
    root from breaking the whole trust store.
    """
    import re
    import warnings

    import certifi
    from cryptography.utils import CryptographyDeprecationWarning
    with open(certifi.where(), "rb") as f:
        blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", f.read(), re.S)
    roots = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        for b in blocks:
            try:
                roots.append(x509.load_pem_x509_certificate(b))
            except ValueError:
                continue
    return tuple(roots)


def _short(name: x509.Name) -> str:
    cns = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(cns[0].value) if cns else name.rfc4514_string()


def chain(cert: x509.Certificate, pool: list[x509.Certificate], anchors: list[x509.Certificate]) -> dict:
    """Build and check the chain from `cert` up to a trust anchor."""
    anchor_fps = {fingerprint(a) for a in anchors}
    candidates = {fingerprint(c): c for c in [*pool, *anchors]}
    links: list[dict] = []
    seen: set[str] = set()
    current = cert
    verdict, reason = "incomplete", ""

    for _ in range(MAX_DEPTH):
        fp = fingerprint(current)
        status, _ = validity(current)
        link = {"subject": _short(current.subject), "sha256": fp, "status": status,
                "anchor": fp in anchor_fps, "self_signed": is_self_signed(current),
                "signature_ok": None, "issuer_is_ca": None, "problem": ""}
        links.append(link)
        if status in ("expired", "not_yet_valid"):
            link["problem"] = "expired" if status == "expired" else "not yet valid"
        if fp in seen:
            verdict, reason = "invalid", "The chain loops back on itself."
            break
        seen.add(fp)
        if fp in anchor_fps:
            verdict, reason = "trusted", f"Ends at trust anchor “{link['subject']}”."
            break
        if link["self_signed"]:
            verdict, reason = "untrusted_root", (f"Ends at self-signed “{link['subject']}”, which isn't one of "
                                                 f"your trust anchors.")
            break
        # Find the issuer: same name, and its key must verify this certificate's signature.
        named = [c for c in candidates.values() if c.subject == current.issuer and fingerprint(c) != fp]
        issuer = None
        for c in named:
            try:
                current.verify_directly_issued_by(c)
                issuer = c
                break
            except Exception:  # noqa: BLE001
                continue
        if issuer is None:
            if named:
                link["signature_ok"] = False
                link["problem"] = "signature doesn't verify with the issuer found"
                verdict, reason = "invalid", f"“{_short(current.issuer)}” was found but didn't sign this certificate."
            else:
                verdict, reason = "incomplete", f"Issuer “{_short(current.issuer)}” not found in this value, its secret or your trust anchors."
            break
        link["signature_ok"] = True
        link["issuer_is_ca"] = is_ca(issuer)
        if not link["issuer_is_ca"]:
            link["problem"] = (link["problem"] + "; " if link["problem"] else "") + "issuer isn't a CA"
        current = issuer

    if any(l["problem"] for l in links) and verdict in ("trusted", "untrusted_root", "incomplete"):
        bad = next(l for l in links if l["problem"])
        reason = f"“{bad['subject']}”: {bad['problem']}. " + reason
        verdict = "invalid"
    return {"verdict": verdict, "reason": reason, "links": links}
