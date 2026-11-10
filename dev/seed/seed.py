"""Seed two dev Vaults with mounts, policies, auth methods and comparison test data.

Dev only. Idempotent enough to re-run against already-seeded dev Vaults.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import secrets
import sys
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEV_PASSWORD = "password"
P12_PASSWORD = "changeit"
NOW = dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- Vault client


class Vault:
    def __init__(self, name: str, addr: str, token: str):
        self.name = name
        self.c = httpx.Client(base_url=f"{addr}/v1/", headers={"X-Vault-Token": token}, timeout=10)

    def req(self, method: str, path: str, body: dict | None = None, ok=(200, 204)) -> dict:
        r = self.c.request(method, path, json=body)
        if r.status_code not in ok:
            raise RuntimeError(f"[{self.name}] {method} {path} -> {r.status_code}: {r.text}")
        return r.json() if r.content else {}

    def wait_ready(self) -> None:
        for _ in range(60):
            try:
                if self.c.get("sys/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1)
        sys.exit(f"[{self.name}] not ready")

    def mount_kv(self, path: str, version: int = 2, description: str = "") -> None:
        """(Re)create a KV mount. Disabling an existing mount deletes all its data, so every
        seed run resets the fixtures exactly, even after manual testing or test runs wrote extra
        secrets."""
        mounts = self.req("GET", "sys/mounts")["data"]
        if f"{path}/" in mounts:
            self.req("DELETE", f"sys/mounts/{path}")
        self.req("POST", f"sys/mounts/{path}",
                 {"type": "kv", "options": {"version": str(version)}, "description": description})

    def enable_auth(self, path: str, type_: str) -> str:
        auths = self.req("GET", "sys/auth")["data"]
        if f"{path}/" not in auths:
            self.req("POST", f"sys/auth/{path}", {"type": type_})
            auths = self.req("GET", "sys/auth")["data"]
        # Show the method on the login screen (Vault UI and Lockstep both read
        # sys/internal/ui/mounts without a token).
        self.req("POST", f"sys/auth/{path}/tune", {"listing_visibility": "unauth"})
        return auths[f"{path}/"]["accessor"]

    def policy(self, name: str, hcl: str) -> None:
        self.req("PUT", f"sys/policies/acl/{name}", {"policy": hcl})

    def kv_put(self, mount: str, path: str, data: dict) -> None:
        self.req("POST", f"{mount}/data/{path}", {"data": data})

    def kv1_put(self, mount: str, path: str, data: dict) -> None:
        self.req("POST", f"{mount}/{path}", data)


# --------------------------------------------------------------------------- PKI material


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _cert(subject_cn, key, issuer_cert, issuer_key, *, ca=False, days=365, start_offset_days=-1,
          sans=None, path_len=None):
    subject = _name(subject_cn)
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    b = (x509.CertificateBuilder()
         .subject_name(subject)
         .issuer_name(issuer)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=start_offset_days))
         .not_valid_after(NOW + dt.timedelta(days=start_offset_days + days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if issuer_cert is not None:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    if ca:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, key_cert_sign=False, crl_sign=False,
            content_commitment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        b = b.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(s) for s in (sans or [subject_cn])]), critical=False)
    return b.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def build_pki() -> dict:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert("Example Root CA", root_key, None, None, ca=True, days=3650, path_len=1)
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter = _cert("Example Intermediate CA", int_key, root, root_key, ca=True, days=1825, path_len=0)

    def leaf(cn, **kw):
        k = ec.generate_private_key(ec.SECP256R1())
        return k, _cert(cn, k, inter, int_key, **kw)

    app_key, app = leaf("app.example.com", sans=["app.example.com", "www.app.example.com"])
    app2_key, app2 = leaf("app.example.com", sans=["app.example.com", "www.app.example.com"])  # renewed
    _, expired = leaf("old.example.com", days=30, start_offset_days=-60)
    _, notyet = leaf("future.example.com", start_offset_days=30)

    ss_key = ec.generate_private_key(ec.SECP256R1())
    selfsigned = _cert("selfsigned.example.com", ss_key, None, None, sans=["selfsigned.example.com"])

    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_ca = _cert("Rogue CA", rogue_key, None, None, ca=True, days=3650)
    ut_key = ec.generate_private_key(ec.SECP256R1())
    untrusted = _cert("untrusted.example.com", ut_key, rogue_ca, rogue_key)

    def p12(name: bytes, key, cert, cas, password: str | None):
        enc = (serialization.BestAvailableEncryption(password.encode()) if password
               else serialization.NoEncryption())
        return pkcs12.serialize_key_and_certificates(name, key, cert, cas, enc)

    return {
        "root": root, "inter": inter, "app": app, "app_key": app_key, "app2": app2,
        "app2_key": app2_key, "expired": expired, "notyet": notyet, "selfsigned": selfsigned,
        "ss_key": ss_key, "untrusted": untrusted,
        "p12_app": p12(b"app", app_key, app, [inter, root], P12_PASSWORD),
        "p12_app2": p12(b"app", app2_key, app2, [inter, root], P12_PASSWORD),
        "p12_nopass": p12(b"selfsigned", ss_key, selfsigned, None, None),
    }


# --------------------------------------------------------------------------- policies

POLICY_ADMIN = """
path "*" { capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"] }
"""

POLICY_READONLY = """
path "sys/mounts" { capabilities = ["read"] }
path "+/data/*" { capabilities = ["read"] }
path "+/metadata/*" { capabilities = ["read", "list"] }
path "+/metadata" { capabilities = ["list"] }
"""

# No sys/mounts (exercises the mount-discovery fallback and manual entry), plus:
#  - restricted/    fully hidden. Vault checks LIST on a folder against the path WITHOUT its
#                   trailing slash, so the folder path itself has to be denied too.
#  - payments/api   listable but not readable (no access at the secret level).
POLICY_LIMITED = """
path "app-config/data/*" { capabilities = ["read", "create", "update", "patch"] }
path "app-config/metadata/*" { capabilities = ["read", "list"] }
path "app-config/metadata" { capabilities = ["list"] }
path "app-config/data/restricted/*" { capabilities = ["deny"] }
path "app-config/metadata/restricted" { capabilities = ["deny"] }
path "app-config/metadata/restricted/*" { capabilities = ["deny"] }
path "app-config/data/payments/api" { capabilities = ["deny"] }
"""


def configure_auth(v: Vault) -> None:
    v.policy("lockstep-admin", POLICY_ADMIN)
    v.policy("lockstep-readonly", POLICY_READONLY)
    v.policy("lockstep-limited", POLICY_LIMITED)

    v.enable_auth("userpass", "userpass")
    for user, pol in [("alice", "lockstep-admin"), ("bob", "lockstep-readonly"), ("carol", "lockstep-limited")]:
        v.req("POST", f"auth/userpass/users/{user}", {"password": DEV_PASSWORD, "token_policies": pol})

    accessor = v.enable_auth("oidc", "oidc")
    attempts = int(os.environ.get("OIDC_WAIT_ATTEMPTS", "30"))  # 2 s apart; longer when TLS certs are being issued
    for attempt in range(attempts):
        try:
            v.req("POST", "auth/oidc/config", {
                "oidc_discovery_url": os.environ["OIDC_DISCOVERY_URL"],
                "oidc_client_id": os.environ["OIDC_CLIENT_ID"],
                "oidc_client_secret": os.environ["OIDC_CLIENT_SECRET"],
                "default_role": "default",
            })
            break
        except RuntimeError as e:  # Dex may still be starting
            if attempt == attempts - 1:
                raise
            print(f"[{v.name}] waiting for Dex: {e}")
            time.sleep(2)

    tool = os.environ["TOOL_PUBLIC_URL"].rstrip("/")
    v.req("POST", "auth/oidc/role/default", {
        "role_type": "oidc",
        "user_claim": "email",
        "oidc_scopes": ["openid", "email", "profile"],
        "allowed_redirect_uris": [
            f"{tool}/api/auth/oidc/callback",
            "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8201/ui/vault/auth/oidc/oidc/callback",
            "http://localhost:8250/oidc/callback",
        ],
        "token_policies": ["lockstep-readonly"],
        "token_ttl": "8h",
    })
    # JWT auth: log in with an ID token from Dex (tests get one with the password grant).
    jwt_accessor = v.enable_auth("jwt", "jwt")
    v.req("POST", "auth/jwt/config", {
        "oidc_discovery_url": os.environ["OIDC_DISCOVERY_URL"],
        "bound_issuer": os.environ["OIDC_DISCOVERY_URL"],
        "default_role": "default",
    })
    v.req("POST", "auth/jwt/role/default", {
        "role_type": "jwt",
        "user_claim": "email",
        "bound_audiences": [os.environ["OIDC_CLIENT_ID"]],
        "token_policies": ["lockstep-readonly"],
        "token_ttl": "1h",
    })

    # alice@example.com gets admin via an identity entity (from OIDC or JWT); bob@example.com
    # stays read-only.
    ent = v.req("POST", "identity/entity", {"name": "alice", "policies": ["lockstep-admin"]}, ok=(200, 204))
    ent_id = (ent.get("data") or {}).get("id") or v.req("GET", "identity/entity/name/alice")["data"]["id"]
    for acc in (accessor, jwt_accessor):
        v.req("POST", "identity/entity-alias",
              {"name": "alice@example.com", "canonical_id": ent_id, "mount_accessor": acc},
              ok=(200, 204, 400))  # 400: alias already exists on re-run


# --------------------------------------------------------------------------- test data


def seed_data(a: Vault, b: Vault, pki: dict) -> None:
    for v in (a, b):
        v.mount_kv("app-config", description="Application configuration")
        v.mount_kv("certs", description="TLS material")
        v.mount_kv("legacy-kv", version=1, description="KV v1: should be ignored by the tool")
    a.mount_kv("team-a-only", description="Only exists in Vault A")
    b.mount_kv("app-config-staging", description="Compare against app-config in the same Vault")

    flags_a = json.dumps({"newCheckout": True, "darkMode": False})
    flags_b = json.dumps({"newCheckout": True, "darkMode": True})

    # ---- app-config
    a.kv_put("app-config", "payments/db", {"host": "db.internal", "port": "5432", "username": "pay", "password": "old"})
    a.kv_put("app-config", "payments/db", {"host": "db.internal", "port": "5432", "username": "pay", "password": "s3cret-A"})
    b.kv_put("app-config", "payments/db", {"host": "db.internal", "port": "5432", "username": "pay", "password": "s3cret-B"})

    for v in (a, b):
        v.kv_put("app-config", "payments/api", {"api_key": "ak_live_1234567890", "endpoint": "https://pay.example.com"})
        v.kv_put("app-config", "restricted/root-creds", {"user": "root", "password": "hunter2"})
        v.kv_put("app-config", "team/x/y/z/deep", {"value": "deeply nested"})

    a.kv_put("app-config", "frontend/settings", {
        "feature_flags": flags_a, "banner_b64": b64(b"Welcome to Example Corp!"), "timeout": "30"})
    b.kv_put("app-config", "frontend/settings", {
        "feature_flags": flags_b, "banner_b64": b64(b"Welcome to Example Corp!"), "timeout": "30",
        "cdn_url": "https://cdn.example.com"})

    # Edge cases for the diff engine
    a.kv_put("app-config", "types/mixed", {"port": 5432, "enabled": True, "tags": {"a": 1, "b": 2}})
    b.kv_put("app-config", "types/mixed", {"port": "5432", "enabled": True, "tags": {"b": 2, "a": 1}})
    for v in (a, b):
        v.kv_put("app-config", "odd names/with space", {"k": "v"})
        v.kv_put("app-config", "retired/thing", {"token": "abc"})
    a.req("DELETE", "app-config/data/retired/thing")  # soft-delete the latest version in A only

    # Environment-style layout for comparison profiles: prod paths in A, staging paths in B.
    # Profile "Prod ↔ staging services" maps services/*/prod/** <-> services/*/staging/**
    # and ignores "host" (expected to differ per environment).
    a.kv_put("app-config", "services/billing/prod/db", {"host": "db-prod.internal", "port": "5432", "user": "billing", "password": "b1ll1ng"})
    b.kv_put("app-config", "services/billing/staging/db", {"host": "db-staging.internal", "port": "5432", "user": "billing", "password": "b1ll1ng"})
    a.kv_put("app-config", "services/billing/prod/api", {"key": "bk-prod", "timeout": "30"})
    b.kv_put("app-config", "services/billing/staging/api", {"key": "bk-staging", "timeout": "30"})
    a.kv_put("app-config", "services/search/prod/config", {"replicas": "3", "index": "products"})
    b.kv_put("app-config", "services/orders/staging/queue", {"url": "amqp://mq.staging.internal"})

    a.kv_put("app-config", "legacy/old-service", {"url": "http://old.internal"})
    b.kv_put("app-config", "new-service/config", {"url": "http://new.internal", "replicas": "3"})

    b.kv_put("app-config-staging", "payments/db", {"host": "db.staging", "port": "5432", "username": "pay", "password": "staging"})
    b.kv_put("app-config-staging", "payments/api", {"api_key": "ak_test_000", "endpoint": "https://pay.example.com"})

    a.kv_put("team-a-only", "notes", {"text": "Vault A only"})
    for v in (a, b):
        v.kv1_put("legacy-kv", "thing", {"k": "v"})

    # ---- certs
    root_pem, inter_pem = pem(pki["root"]), pem(pki["inter"])
    for v in (a, b):
        v.kv_put("certs", "ca/root", {"certificate": root_pem})
        v.kv_put("certs", "ca/intermediate", {"certificate": inter_pem})
        v.kv_put("certs", "web/expired", {"tls.crt": pem(pki["expired"])})
        v.kv_put("certs", "keystores/selfsigned-nopass", {"keystore.p12": b64(pki["p12_nopass"])})

    a.kv_put("certs", "web/app", {
        "tls.crt": pem(pki["app"]), "tls.key": key_pem(pki["app_key"]),
        "chain.pem": pem(pki["app"]) + inter_pem, "ca.crt": root_pem,
        "tls.crt.der.b64": b64(pki["app"].public_bytes(serialization.Encoding.DER))})
    b.kv_put("certs", "web/app", {  # renewed certificate: differs from A
        "tls.crt": pem(pki["app2"]), "tls.key": key_pem(pki["app2_key"]),
        "chain.pem": pem(pki["app2"]) + inter_pem, "ca.crt": root_pem,
        "tls.crt.der.b64": b64(pki["app2"].public_bytes(serialization.Encoding.DER))})

    a.kv_put("certs", "keystores/app", {"keystore.p12": b64(pki["p12_app"]), "keystore.password": P12_PASSWORD})
    b.kv_put("certs", "keystores/app", {"keystore.p12": b64(pki["p12_app2"]), "keystore.password": P12_PASSWORD})

    b.kv_put("certs", "web/not-yet-valid", {"tls.crt": pem(pki["notyet"])})
    b.kv_put("certs", "web/selfsigned", {"tls.crt": pem(pki["selfsigned"]), "tls.key": key_pem(pki["ss_key"])})
    b.kv_put("certs", "web/untrusted", {"tls.crt": pem(pki["untrusted"])})
    b.kv_put("certs", "web/missing-intermediate", {"tls.crt": pem(pki["app2"]), "ca.crt": root_pem})


def png(width: int = 24, height: int = 24) -> bytes:
    """A small gradient PNG, built by hand (no imaging library needed)."""
    import struct
    import zlib
    rows = b"".join(b"\x00" + bytes(c for x in range(width) for c in (x * 10 % 256, y * 10 % 256, 180))
                    for y in range(height))
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect width="64" height="64" rx="12" '
       b'fill="#3b5bdb"/><circle cx="32" cy="32" r="14" fill="#e0864a"/>'
       b'<script>document.title="svg script ran"</script></svg>')  # the script must NOT run in the UI


def zip_bytes() -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("config/app.properties", "feature.x=true\n")
    return buf.getvalue()


def seed_value_tool_fixtures(a: Vault, b: Vault, pki: dict) -> None:
    fx = os.environ.get("FIXTURES_DIR", "/seed/fixtures")
    jks = open(f"{fx}/app.jks", "rb").read()
    jceks = open(f"{fx}/app.jceks", "rb").read()
    trust = open(f"{fx}/trust.jks", "rb").read()
    chain_pem = (pem(pki["app"]) + pem(pki["inter"])).encode()
    for v in (a, b):
        v.kv_put("certs", "keystores/java-app", {"keystore.jks": b64(jks), "keystore.password": P12_PASSWORD})
        v.kv_put("certs", "truststores/partner", {"truststore.jks": b64(trust)})
    a.kv_put("certs", "keystores/java-jceks", {"keystore.jceks": b64(jceks), "storepass": P12_PASSWORD})
    a.kv_put("certs", "web/app-b64", {"tls.crt.b64": b64(chain_pem), "ca.crt": pem(pki["root"])})
    b.kv_put("certs", "web/app-b64", {"tls.crt.b64": b64((pem(pki["app2"]) + pem(pki["inter"])).encode()),
                                      "ca.crt": pem(pki["root"])})
    for v in (a, b):
        v.kv_put("app-config", "frontend/assets", {"logo.png": b64(png()), "icon.svg": b64(SVG)})
        v.kv_put("app-config", "frontend/bundle", {"plugin.jar": b64(zip_bytes())})
    a.kv_put("app-config", "crypto/keys", {"aes_key": b64(os.urandom(32)), "hmac_key": b64(os.urandom(64))})
    b.kv_put("app-config", "crypto/keys", {"aes_key": b64(os.urandom(32)), "hmac_key": b64(os.urandom(64))})


def seed_password_finder(a: Vault, b: Vault, pki: dict) -> None:
    """A keystore whose password lives elsewhere in the tree, among decoys (password finder)."""
    pw = secrets.token_urlsafe(12)  # different each seed: nothing may depend on the value
    p12 = pkcs12.serialize_key_and_certificates(
        b"app", pki["app_key"], pki["app"], [pki["inter"]], serialization.BestAvailableEncryption(pw.encode()))
    for v in (a, b):
        v.kv_put("certs", "some-secrets/files/certs.p12", {"certs.p12": b64(p12)})
        v.kv_put("certs", "some-secrets/passwords/CERT_PASSWORD", {"value": "not-the-store-password"})
        v.kv_put("certs", "some-secrets/strings/KEYSTORE_PASSWORD", {"value": pw})
        v.kv_put("certs", "some-secrets/passwords/DB_PASSWORD", {"value": "db-password"})
        v.kv_put("certs", "some-secrets/strings/API_URL", {"value": "https://api.example.com"})


def main() -> None:
    a = Vault("vault-a", os.environ["VAULT_A_ADDR"], os.environ["VAULT_A_TOKEN"])
    b = Vault("vault-b", os.environ["VAULT_B_ADDR"], os.environ["VAULT_B_TOKEN"])
    for v in (a, b):
        v.wait_ready()
        configure_auth(v)
        print(f"[{v.name}] auth configured")
    pki = build_pki()
    seed_data(a, b, pki)
    seed_value_tool_fixtures(a, b, pki)
    seed_password_finder(a, b, pki)
    print("seed complete")


if __name__ == "__main__":
    # RESEED_INTERVAL (seconds): keep running and restore the fixtures periodically (public demo).
    interval = int(os.environ.get("RESEED_INTERVAL", "0"))
    main()
    while interval > 0:
        time.sleep(interval)
        try:
            main()
            print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "demo data restored", flush=True)
        except Exception as e:  # keep the loop alive; the next run tries again
            print("reseed failed:", e, flush=True)
