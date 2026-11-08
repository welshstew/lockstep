"""Identify what a secret value is, recursively, and build an analysis tree.

A value is identified by content, never by key name:
  text      → PEM blocks, JSON, base64 (strict, then decoded and identified again), plain text
  bytes     → PKCS#12, JKS/JCEKS, DER (certificate, CSR, PKCS#8 key, public key, PKCS#7),
              images (PNG/JPEG/GIF/WebP/ICO/SVG), PDF, ZIP, GZIP, UTF-8 text, other binary

Each node keeps its raw bytes (for download/preview) in `Analysis.blobs`, never in the
tree that's returned to the browser.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from . import certs, der, javaks

MAX_DEPTH = 4
MAX_BYTES = 8 * 1024 * 1024
MIN_B64_LEN = 16

PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)-----END \1-----", re.S)
B64_RE = re.compile(r"^[A-Za-z0-9+/=\s_-]+$")
SIGNATURES = [  # (prefix, kind, label, mime, ext)
    (b"\x89PNG\r\n\x1a\n", "image", "PNG image", "image/png", "png"),
    (b"\xff\xd8\xff", "image", "JPEG image", "image/jpeg", "jpg"),
    (b"GIF87a", "image", "GIF image", "image/gif", "gif"),
    (b"GIF89a", "image", "GIF image", "image/gif", "gif"),
    (b"\x00\x00\x01\x00", "image", "ICO image", "image/x-icon", "ico"),
    (b"%PDF-", "pdf", "PDF document", "application/pdf", "pdf"),
    (b"PK\x03\x04", "zip", "ZIP archive", "application/zip", "zip"),
    (b"\x1f\x8b", "gzip", "GZIP data", "application/gzip", "gz"),
]


@dataclass
class Node:
    id: str
    kind: str
    label: str
    size: int = 0
    encoding: list[str] = field(default_factory=list)  # how we got here, e.g. ["base64"]
    mime: str = "application/octet-stream"
    ext: str = "bin"
    downloadable: bool = True
    details: dict[str, Any] = field(default_factory=dict)
    children: list["Node"] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    needs_password: bool = False

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "children"}
        d["children"] = [c.to_dict() for c in self.children]
        return d


@dataclass
class Analysis:
    root: Node
    blobs: dict[str, bytes]  # node id -> raw bytes
    certificates: list[tuple[str, x509.Certificate]]  # (node id, cert), for chains and key matching
    private_keys: list[tuple[str, Any]]  # (node id, private key object)
    password_used: bool = False


class _Ctx:
    def __init__(self, password: str | None):
        self.password = password
        self.password_used = False
        self.blobs: dict[str, bytes] = {}
        self.certs: list[tuple[str, x509.Certificate]] = []
        self.keys: list[tuple[str, Any]] = []


# --------------------------------------------------------------------------- entry points


def analyze(value: Any, password: str | None = None) -> Analysis:
    ctx = _Ctx(password)
    if isinstance(value, str):
        root = _text(value, "0", [], ctx, 0)
    else:
        raw = json.dumps(value, indent=2).encode()
        root = Node("0", "json", f"JSON {type(value).__name__}", len(raw), mime="application/json", ext="json")
        ctx.blobs["0"] = raw
    return Analysis(root, ctx.blobs, ctx.certs, ctx.keys, ctx.password_used)


def badge(value: Any) -> dict | None:
    """A cheap one-line summary for the diff view. None for plain text/JSON. No values."""
    if not isinstance(value, str) or len(value) < MIN_B64_LEN or len(value) > MAX_BYTES:
        return None
    try:
        a = analyze(value)
    except Exception:  # noqa: BLE001 (a badge is best effort)
        return None
    node = a.root
    while node.kind in ("base64",) and node.children:
        node = node.children[0]
    if node.kind in ("text", "json"):
        return None
    if node.kind == "binary" and node.size < 48:
        return None  # most likely a random token that happens to be valid base64
    out = {"kind": node.kind, "label": node.label, "status": None, "detail": ""}
    statuses = [certs.validity(c) for _, c in a.certificates]
    if statuses:
        worst = min(statuses, key=lambda s: s[1])
        rank = {"expired": 0, "not_yet_valid": 1, "expiring": 2, "valid": 3}
        status, days = min(statuses, key=lambda s: (rank[s[0]], s[1]))
        out["status"] = {"expired": "bad", "not_yet_valid": "bad", "expiring": "warn", "valid": "ok"}[status]
        out["detail"] = ("expired" if status == "expired" else "not yet valid" if status == "not_yet_valid"
                         else f"expires in {worst[1]} days")
    if node.needs_password:
        out["detail"] = "password needed"
    return out


# --------------------------------------------------------------------------- text


def _text(s: str, nid: str, enc: list[str], ctx: _Ctx, depth: int) -> Node:
    raw = s.encode()
    stripped = s.strip()

    blocks = PEM_RE.findall(s)
    if blocks:
        node = Node(nid, "pem", f"PEM ({len(blocks)} block{'s' if len(blocks) != 1 else ''})", len(raw),
                    enc, "application/x-pem-file", "pem")
        ctx.blobs[nid] = raw
        for i, (label, body) in enumerate(blocks):
            node.children.append(_pem_block(label, body, f"{nid}.{i}", ctx))
        return node

    if stripped[:1] in "{[":
        try:
            json.loads(stripped)
            ctx.blobs[nid] = raw
            return Node(nid, "json", "JSON text", len(raw), enc, "application/json", "json")
        except ValueError:
            pass

    if stripped.lstrip().startswith(("<svg", "<?xml")) and "<svg" in stripped[:2048]:
        ctx.blobs[nid] = raw
        return Node(nid, "image", "SVG image", len(raw), enc, "image/svg+xml", "svg",
                    notes=["Shown as an image, so any scripts inside it don't run."])

    decoded = _b64(stripped) if depth < MAX_DEPTH else None
    if decoded is not None:
        inner = _bytes(decoded, nid + ".0", [*enc, "base64"], ctx, depth + 1, strict=True)
        if inner is not None:
            ctx.blobs[nid] = raw
            node = Node(nid, "base64", f"base64 → {inner.label}", len(raw), enc, "text/plain", "b64",
                        details={"decoded_size": len(decoded)})
            node.children.append(inner)
            return node

    ctx.blobs[nid] = raw
    return Node(nid, "text", "Text", len(raw), enc, "text/plain", "txt")


def _b64(s: str) -> bytes | None:
    compact = re.sub(r"\s+", "", s)
    if len(compact) < MIN_B64_LEN or not B64_RE.match(s) or len(compact) > MAX_BYTES * 2:
        return None
    alt = "-_" if ("-" in compact or "_" in compact) else None
    padded = compact + "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(padded, altchars=alt.encode() if alt else None, validate=True)
    except (binascii.Error, ValueError):
        return None


# --------------------------------------------------------------------------- bytes


def _bytes(b: bytes, nid: str, enc: list[str], ctx: _Ctx, depth: int, strict: bool = False) -> Node | None:
    """Identify raw bytes. With strict=True (input came from base64 of an unknown string)
    return None unless we recognise something, so a random password isn't called 'binary'."""
    for prefix, kind, label, mime, ext in SIGNATURES:
        if b.startswith(prefix):
            node = Node(nid, kind, label, len(b), enc, mime, ext)
            ctx.blobs[nid] = b
            if kind == "zip":
                _zip_listing(node, b)
            return node
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        ctx.blobs[nid] = b
        return Node(nid, "image", "WebP image", len(b), enc, "image/webp", "webp")

    ks = javaks.detect(b)
    if ks:
        return _java_keystore(b, ks, nid, enc, ctx)
    if der.is_pfx(b):
        return _pkcs12(b, nid, enc, ctx)
    if der.is_der_sequence(b):
        node = _der(b, nid, enc, ctx)
        if node:
            return node

    try:
        text = b.decode("utf-8")
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(len(text), 1)
        if printable > 0.95:
            inner = _text(text, nid, enc, ctx, depth)
            if inner.kind != "text" or not strict or len(b) >= MIN_B64_LEN:
                return inner
    except UnicodeDecodeError:
        pass
    if strict and len(b) < 24:
        return None  # a short random string that merely looks like base64
    ctx.blobs[nid] = b
    return Node(nid, "binary", f"Binary data ({len(b)} bytes)", len(b), enc,
                notes=["Unrecognised binary content. You can still download it."])


def _zip_listing(node: Node, b: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            infos = z.infolist()
            node.details["entries"] = [{"name": i.filename, "size": i.file_size} for i in infos[:200]]
            if len(infos) > 200:
                node.notes.append(f"Showing 200 of {len(infos)} entries.")
            if any(i.filename.startswith("META-INF/MANIFEST.MF") for i in infos):
                node.label = "ZIP archive (JAR)"
    except zipfile.BadZipFile:
        node.problems.append("ZIP structure is damaged.")


# --------------------------------------------------------------------------- PEM / DER


_PEM_KIND = {
    "CERTIFICATE": "certificate", "TRUSTED CERTIFICATE": "certificate", "X509 CERTIFICATE": "certificate",
    "CERTIFICATE REQUEST": "csr", "NEW CERTIFICATE REQUEST": "csr",
    "PRIVATE KEY": "private_key", "RSA PRIVATE KEY": "private_key", "EC PRIVATE KEY": "private_key",
    "ENCRYPTED PRIVATE KEY": "encrypted_private_key",
    "PUBLIC KEY": "public_key", "RSA PUBLIC KEY": "public_key", "PKCS7": "pkcs7",
}


def _pem_block(label: str, body: str, nid: str, ctx: _Ctx) -> Node:
    pem = f"-----BEGIN {label}-----\n{body.strip()}\n-----END {label}-----\n".encode()
    kind = _PEM_KIND.get(label, "pem_block")
    try:
        if kind == "certificate":
            return _cert_node(x509.load_pem_x509_certificate(pem), nid, ["pem"], ctx)
        if kind == "csr":
            return _csr_node(x509.load_pem_x509_csr(pem), nid, ["pem"], ctx, pem)
        if kind == "private_key":
            return _key_node(serialization.load_pem_private_key(pem, None), nid, ["pem"], ctx, pem)
        if kind == "encrypted_private_key":
            return _encrypted_key_node(pem, nid, ["pem"], ctx, is_pem=True)
        if kind == "public_key":
            k = serialization.load_pem_public_key(pem)
            ctx.blobs[nid] = pem
            return Node(nid, "public_key", f"Public key ({certs.key_description(k)})", len(pem), ["pem"],
                        "application/x-pem-file", "pub.pem", details={"key": certs.key_description(k)})
        if kind == "pkcs7":
            return _pkcs7_node(pkcs7.load_pem_pkcs7_certificates(pem), nid, ["pem"], ctx, pem)
    except Exception as e:  # noqa: BLE001
        ctx.blobs[nid] = pem
        return Node(nid, kind, f"PEM {label.title()} (unreadable)", len(pem), ["pem"], problems=[str(e)[:200]])
    ctx.blobs[nid] = pem
    return Node(nid, "pem_block", f"PEM {label.title()}", len(pem), ["pem"], "application/x-pem-file", "pem")


def _der(b: bytes, nid: str, enc: list[str], ctx: _Ctx) -> Node | None:
    loaders = [
        lambda: _cert_node(x509.load_der_x509_certificate(b), nid, [*enc, "der"], ctx),
        lambda: _csr_node(x509.load_der_x509_csr(b), nid, [*enc, "der"], ctx, b),
        lambda: _key_node(serialization.load_der_private_key(b, None), nid, [*enc, "der"], ctx, b),
        lambda: _pkcs7_node(pkcs7.load_der_pkcs7_certificates(b), nid, [*enc, "der"], ctx, b),
    ]
    for load in loaders:
        try:
            return load()
        except Exception:  # noqa: BLE001
            continue
    try:
        k = serialization.load_der_public_key(b)
        ctx.blobs[nid] = b
        return Node(nid, "public_key", f"Public key ({certs.key_description(k)})", len(b), [*enc, "der"],
                    ext="pub.der", details={"key": certs.key_description(k)})
    except Exception:  # noqa: BLE001
        pass
    # An EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    try:
        kids = der.children(der.read(b).value)
        if len(kids) == 2 and kids[0].tag == 0x30 and kids[1].tag == 0x04:
            return _encrypted_key_node(b, nid, [*enc, "der"], ctx, is_pem=False)
    except der.DerError:
        pass
    return None


def _cert_node(cert: x509.Certificate, nid: str, enc: list[str], ctx: _Ctx, alias: str | None = None) -> Node:
    raw = cert.public_bytes(serialization.Encoding.PEM)
    ctx.blobs[nid] = raw
    ctx.certs.append((nid, cert))
    i = certs.info(cert)
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    name = str(cn[0].value) if cn else i["subject"]
    label = f"Certificate: {name}" + (f" (alias {alias})" if alias else "")
    return Node(nid, "certificate", label, len(raw), enc, "application/x-pem-file", "crt",
                details={"certificate": i, **({"alias": alias} if alias else {})})


def _csr_node(csr: x509.CertificateSigningRequest, nid: str, enc, ctx: _Ctx, raw: bytes) -> Node:
    ctx.blobs[nid] = raw
    return Node(nid, "csr", f"Certificate request: {csr.subject.rfc4514_string()}", len(raw), enc,
                ext="csr", details={"subject": csr.subject.rfc4514_string(),
                                    "public_key": certs.key_description(csr.public_key()),
                                    "signature_valid": csr.is_signature_valid})


def _key_node(key, nid: str, enc, ctx: _Ctx, raw: bytes | None, alias: str | None = None,
              downloadable: bool = True) -> Node:
    if raw is not None:
        ctx.blobs[nid] = raw
    ctx.keys.append((nid, key))
    desc = certs.key_description(key.public_key())
    return Node(nid, "private_key", f"Private key ({desc})" + (f", alias {alias}" if alias else ""),
                len(raw or b""), enc, "application/x-pem-file", "key", downloadable=downloadable and raw is not None,
                details={"key": desc, **({"alias": alias} if alias else {})})


def _encrypted_key_node(raw: bytes, nid: str, enc, ctx: _Ctx, is_pem: bool) -> Node:
    ctx.blobs[nid] = raw
    node = Node(nid, "encrypted_private_key", "Encrypted private key", len(raw), enc,
                "application/x-pem-file" if is_pem else "application/octet-stream", "key")
    if ctx.password is None:
        node.needs_password = True
        node.notes.append("Enter the password to see the key type and which certificate it belongs to.")
        return node
    try:
        load = serialization.load_pem_private_key if is_pem else serialization.load_der_private_key
        key = load(raw, ctx.password.encode())
        ctx.password_used = True
        ctx.keys.append((nid, key))
        node.label = f"Encrypted private key ({certs.key_description(key.public_key())})"
        node.details["key"] = certs.key_description(key.public_key())
    except Exception:  # noqa: BLE001
        node.needs_password = True
        node.problems.append("Wrong password, or unsupported encryption.")
    return node


def _pkcs7_node(cs: list[x509.Certificate], nid: str, enc, ctx: _Ctx, raw: bytes) -> Node:
    ctx.blobs[nid] = raw
    node = Node(nid, "pkcs7", f"PKCS#7 bundle ({len(cs)} certificate{'s' if len(cs) != 1 else ''})", len(raw), enc,
                ext="p7b")
    node.children = [_cert_node(c, f"{nid}.{i}", ["pkcs7"], ctx) for i, c in enumerate(cs)]
    return node


# --------------------------------------------------------------------------- keystores


def _pkcs12(b: bytes, nid: str, enc, ctx: _Ctx) -> Node:
    ctx.blobs[nid] = b
    node = Node(nid, "pkcs12", "PKCS#12 keystore", len(b), [*enc], "application/x-pkcs12", "p12")
    store = None
    for pw, used in ((None, False), (b"", False)):
        try:
            store = pkcs12.load_pkcs12(b, pw)
            node.notes.append("This keystore has no password.")
            break
        except Exception:  # noqa: BLE001
            continue
    if store is None and ctx.password is not None:
        try:
            store = pkcs12.load_pkcs12(b, ctx.password.encode())
            ctx.password_used = True
        except Exception:  # noqa: BLE001
            node.needs_password = True
            node.problems.append("Wrong password (or an unsupported encryption algorithm).")
            return node
    if store is None:
        node.needs_password = True
        node.notes.append("Enter the keystore password to list its contents.")
        return node

    i = 0
    if store.key is not None:
        alias = store.cert.friendly_name.decode(errors="replace") if store.cert and store.cert.friendly_name else None
        node.children.append(_key_node(store.key, f"{nid}.{i}", ["pkcs12"], ctx, None, alias, downloadable=False))
        i += 1
    if store.cert is not None:
        alias = store.cert.friendly_name.decode(errors="replace") if store.cert.friendly_name else None
        node.children.append(_cert_node(store.cert.certificate, f"{nid}.{i}", ["pkcs12"], ctx, alias))
        i += 1
    for extra in store.additional_certs:
        alias = extra.friendly_name.decode(errors="replace") if extra.friendly_name else None
        node.children.append(_cert_node(extra.certificate, f"{nid}.{i}", ["pkcs12"], ctx, alias))
        i += 1
    node.label = f"PKCS#12 keystore ({'1 key, ' if store.key else ''}{i - (1 if store.key else 0)} certificate(s))"
    return node


def _java_keystore(b: bytes, kind: str, nid: str, enc, ctx: _Ctx) -> Node:
    ctx.blobs[nid] = b
    upper = kind.upper()
    node = Node(nid, kind, f"Java keystore ({upper})", len(b), [*enc], "application/octet-stream", kind)
    try:
        ks = javaks.parse(b, ctx.password)
    except Exception as e:  # noqa: BLE001
        node.problems.append(f"Couldn't read the keystore: {str(e)[:200]}")
        return node
    node.notes.extend(ks.notes)
    node.details["integrity"] = ks.integrity
    if ks.integrity == "ok":
        ctx.password_used = True
        node.notes.append("Password correct: keystore integrity verified.")
    elif ks.integrity == "bad_password":
        node.needs_password = True
        node.problems.append("Wrong password: the keystore's integrity check failed. Certificates are listed "
                             "anyway (JKS stores them unencrypted) but haven't been verified.")
    elif ctx.password is None:
        node.needs_password = True
        node.notes.append("Certificates are listed without a password. Enter it to verify the keystore's "
                          "integrity and decrypt JKS private keys.")
    i = 0
    for e in ks.entries:
        eid = f"{nid}.{i}"
        i += 1
        if e.kind == "trusted_cert":
            child = _cert_node(e.certs[0], eid, [kind], ctx, e.alias)
            child.label = f"Trusted certificate (alias {e.alias})"
            node.children.append(child)
        elif e.kind == "private_key":
            entry = Node(eid, "keystore_entry", f"Key entry (alias {e.alias})", 0, [kind], downloadable=False,
                         details={"alias": e.alias})
            if e.pkcs8:
                key = serialization.load_der_private_key(e.pkcs8, None)
                entry.children.append(_key_node(key, f"{eid}.k", [kind], ctx, None, e.alias, downloadable=False))
            elif e.note:
                entry.notes.append(e.note)
            for j, c in enumerate(e.certs):
                entry.children.append(_cert_node(c, f"{eid}.{j}", [kind], ctx, e.alias if j == 0 else None))
            node.children.append(entry)
        else:
            node.children.append(Node(eid, "keystore_entry", f"Secret key entry (alias {e.alias})", 0, [kind],
                                      downloadable=False, notes=[e.note]))
    node.label = f"Java keystore ({upper}, {len(ks.entries)} entr{'y' if len(ks.entries) == 1 else 'ies'})"
    return node
