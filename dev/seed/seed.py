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
    def __init__(self, name: str, addr: str, token: str, namespace: str | None = None):
        self.name, self.addr, self.token = name, addr, token
        headers = {"X-Vault-Token": token, **({"X-Vault-Namespace": namespace} if namespace else {})}
        self.c = httpx.Client(base_url=f"{addr}/v1/", headers=headers, timeout=10)

    def in_namespace(self, ns: str) -> "Vault":
        return Vault(f"{self.name}:{ns}", self.addr, self.token, ns)

    def has_namespaces(self) -> bool:
        """Namespaces: OpenBao (2.3+) and Vault Enterprise. Vault Community answers
        "enterprise-only feature"; with namespaces, a missing one is a plain 404."""
        r = self.c.get("sys/namespaces/lockstep-no-such-namespace")
        return r.status_code in (200, 404) and "enterprise-only" not in r.text

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

    def has_plugin(self, kind: str, name: str) -> bool:
        """Whether this server has a built-in auth method or secrets engine. OpenBao ships
        fewer than Vault (no LDAP, AWS, Azure or GCP), so the seed skips what's missing."""
        if not hasattr(self, "_catalog"):
            data = self.req("GET", "sys/plugins/catalog")["data"]
            self._catalog = {k: set(data.get(k) or []) for k in ("auth", "secret")}
        return name in self._catalog[kind]

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


# Policies that differ between the two Vaults, for the Policies tab's Compare (dev in A, prod in B)
POLICIES_A = {
    "payments-dev": """
# Developers on payments: full access in dev, read in test
path "app-config/metadata/*" { capabilities = ["list"] }
path "app-config/data/payments/*" { capabilities = ["create", "read", "update", "delete"] }
""",
    "ci-drift-check": """
path "app-config/metadata/*" { capabilities = ["read", "list"] }
path "app-config/data/*" { capabilities = ["read"] }
""",
    "search-app": """path "app-config/data/services/search/*" { capabilities = ["read"] }""",
}
POLICIES_B = {
    "payments-prod": """
path "app-config/metadata/*" {
  capabilities = ["list"]
}
path "app-config/data/payments/*" {
  capabilities = ["read"]
}
""",
    "ci-drift-check": """
# Same as Vault A, written differently
path "app-config/data/*" { capabilities = ["read"] }
path "app-config/metadata/*" { capabilities = ["list", "read"] }
""",
    "orders-app": """path "app-config/data/services/orders/*" { capabilities = ["read"] }""",
}


def seed_pki(v: Vault) -> None:
    """A PKI engine in Vault A for issuing development certificates (Certificate expiry tab)."""
    mounts = v.req("GET", "sys/mounts")["data"]
    if "pki-dev/" in mounts:
        v.req("DELETE", "sys/mounts/pki-dev")
    v.req("POST", "sys/mounts/pki-dev", {"type": "pki", "description": "Development certificates",
                                         "config": {"max_lease_ttl": "87600h"}})
    v.req("POST", "pki-dev/root/generate/internal", {"common_name": "Lockstep Dev Root CA", "ttl": "87600h",
                                                      "issuer_name": "dev-root"}, ok=(200,))
    v.req("POST", "pki-dev/roles/dev-services", {"allowed_domains": ["dev.internal"], "allow_subdomains": True,
                                                  "max_ttl": "72h", "key_type": "ec", "key_bits": 256})
    print(f"[{v.name}] pki-dev ready")


def seed_database(v: Vault) -> None:
    """Vault A's database engine against the dev Postgres: two dynamic roles."""
    url = os.environ.get("POSTGRES_URL")
    if not url:
        return
    mounts = v.req("GET", "sys/mounts")["data"]
    if "database/" in mounts:
        v.req("DELETE", "sys/mounts/database")
    v.req("POST", "sys/mounts/database", {"type": "database", "description": "Dev Postgres credentials"})
    for attempt in range(20):  # Postgres may still be finishing its first start
        try:
            v.req("POST", "database/config/orders", {
                "plugin_name": "postgresql-database-plugin", "connection_url": url,
                "username": "postgres", "password": os.environ.get("POSTGRES_PASSWORD", "dev-postgres"),
                "allowed_roles": ["orders-readonly", "orders-app"], "verify_connection": True})
            break
        except RuntimeError:
            if attempt == 19:
                raise
            time.sleep(2)
    v.req("POST", "database/roles/orders-readonly", {
        "db_name": "orders", "default_ttl": "1h", "max_ttl": "24h",
        "creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                                "GRANT pg_read_all_data TO \"{{name}}\";"]})
    v.req("POST", "database/roles/orders-app", {
        "db_name": "orders", "default_ttl": "15m", "max_ttl": "1h",
        "creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                                "GRANT pg_read_all_data, pg_write_all_data TO \"{{name}}\";"]})
    print(f"[{v.name}] database ready")


def seed_ldap_secrets(v: Vault) -> None:
    """The LDAP secrets engine at directory/: a dynamic and a static role (no directory behind
    them: they're created without contacting it), for Configuration -> Engine roles and keys."""
    if not v.has_plugin("secret", "ldap"):
        print(f"[{v.name}] no LDAP secrets engine on this server: skipped")
        return
    mounts = v.req("GET", "sys/mounts")["data"]
    if "directory/" in mounts:
        v.req("DELETE", "sys/mounts/directory")
    v.req("POST", "sys/mounts/directory", {"type": "ldap", "description": "Directory service accounts"})
    v.req("POST", "directory/role/dev-users", {
        "creation_ldif": "dn: cn={{.Username}},ou=users,dc=example,dc=internal\nobjectClass: person\n",
        "deletion_ldif": "dn: cn={{.Username}},ou=users,dc=example,dc=internal\nchangetype: delete\n",
        "default_ttl": "1h", "max_ttl": "8h" if v.name == "vault-a" else "24h"})
    v.req("POST", "directory/static-role/reporting", {
        "dn": "cn=reporting,ou=services,dc=example,dc=internal", "username": "reporting",
        "rotation_period": "24h", "skip_import_rotation": True})
    print(f"[{v.name}] ldap secrets engine ready")


def seed_transit(v: Vault) -> None:
    """Transit keys for the Tools tab's playground: one for encryption, one for signing."""
    mounts = v.req("GET", "sys/mounts")["data"]
    if "transit/" in mounts:
        v.req("DELETE", "sys/mounts/transit")
    v.req("POST", "sys/mounts/transit", {"type": "transit", "description": "Encryption as a service"})
    v.req("POST", "transit/keys/app-key", {"type": "aes256-gcm96"})
    v.req("POST", "transit/keys/signing-key", {"type": "ed25519"})
    if v.name == "vault-b":  # drift for Configuration -> Engine roles and keys
        v.req("POST", "transit/keys/app-key/config", {"deletion_allowed": True, "auto_rotate_period": "720h"})
    print(f"[{v.name}] transit ready")


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


def seed_ldap_and_users(v: Vault) -> None:
    """An LDAP auth mount with group mappings (no LDAP server: the mappings are Vault's own),
    and a service user on userpass, with drift between the Vaults for the compare."""
    if v.has_plugin("auth", "ldap"):
        seed_ldap_auth(v)
    else:
        print(f"[{v.name}] no LDAP auth method on this server: skipped")
    svc = {"password": DEV_PASSWORD, "token_policies": "ci-drift-check" if v.name == "vault-a" else "lockstep-readonly",
           "token_ttl": "15m"}
    v.req("POST", "auth/userpass/users/svc-ci", svc)
    print(f"[{v.name}] service user ready")


def seed_ldap_auth(v: Vault) -> None:
    auths = v.req("GET", "sys/auth")["data"]
    if "ldap/" not in auths:  # not tuned to show on the login screen: there's no directory behind it
        v.req("POST", "sys/auth/ldap", {"type": "ldap", "description": "Company directory (mappings only in dev)"})
    v.req("POST", "auth/ldap/config", {
        "url": "ldaps://ldap.example.internal", "userdn": "ou=people,dc=example,dc=internal", "userattr": "uid",
        "groupdn": "ou=groups,dc=example,dc=internal", "groupattr": "cn",
        "token_ttl": "8h" if v.name == "vault-a" else "1h"})
    groups = {"payments-devs": ["payments-dev" if v.name == "vault-a" else "payments-prod"],
              "platform": ["lockstep-readonly"], "auditors": ["lockstep-readonly"]}
    if v.name == "vault-a":
        groups["sandbox-users"] = ["lockstep-limited"]
    for name, pols in groups.items():
        v.req("POST", f"auth/ldap/groups/{name}", {"policies": ",".join(pols)})
    v.req("POST", "auth/ldap/users/dana", {"groups": "payments-devs,platform" if v.name == "vault-a" else "payments-devs"})
    print(f"[{v.name}] ldap mappings ready")


# Namespaces (OpenBao, Vault Enterprise): team-a and team-a/apps on both sides, team-b only on
# A and team-c only on B, each with its own app-config mount, users and policies, and drift
# between the sides, for comparing a namespace with its counterpart.
NS_ADMIN = """
path "app-config/*" { capabilities = ["create", "read", "update", "patch", "delete", "list"] }
path "sys/mounts" { capabilities = ["read"] }
path "sys/policies/acl/*" { capabilities = ["read", "list"] }
path "sys/namespaces/*" { capabilities = ["read", "list"] }
"""
NS_READONLY = """
path "app-config/*" { capabilities = ["read", "list"] }
path "sys/mounts" { capabilities = ["read"] }
"""


def seed_namespaces(v: Vault) -> None:
    if not v.has_namespaces():
        print(f"[{v.name}] no namespaces on this server: skipped")
        return
    a = v.name == "vault-a"
    spaces = ["team-a", "team-a/apps", "team-b" if a else "team-c"]
    for ns in spaces:
        parent, _, child = ns.rpartition("/")
        where = v.in_namespace(parent) if parent else v
        listed = where.c.request("LIST", "sys/namespaces")
        existing = ((listed.json().get("data") or {}).get("keys") or []) if listed.status_code == 200 else []
        if f"{child}/" not in existing:
            where.req("POST", f"sys/namespaces/{child}")
        n = v.in_namespace(ns)
        n.mount_kv("app-config", description=f"{ns} application configuration")
        if "userpass/" not in n.req("GET", "sys/auth")["data"]:
            n.req("POST", "sys/auth/userpass", {"type": "userpass"})
        n.req("POST", "sys/auth/userpass/tune", {"listing_visibility": "unauth"})  # offered on the sign-in form
        n.policy("ns-admin", NS_ADMIN)
        n.policy("ns-readonly", NS_READONLY)
        n.req("POST", "auth/userpass/users/alice", {"password": DEV_PASSWORD, "token_policies": "ns-admin"})
        n.req("POST", "auth/userpass/users/bob", {"password": DEV_PASSWORD, "token_policies": "ns-readonly"})
    t = v.in_namespace("team-a")
    t.kv_put("app-config", "payments/db", {"host": "db.team-a.internal" if a else "db2.team-a.internal",
                                           "username": "payments", "password": "team-a-db-password"})
    t.kv_put("app-config", "payments/api", {"api_key": "team-a-api-key", "endpoint": "https://api.team-a.internal"})
    if a:
        t.kv_put("app-config", "legacy/batch", {"schedule": "0 2 * * *"})
        t.policy("payments-team", 'path "app-config/data/payments/*" { capabilities = ["read"] }')
    else:
        t.kv_put("app-config", "orders/queue", {"url": "amqp://queue.team-a.internal"})
    apps = v.in_namespace("team-a/apps")
    apps.kv_put("app-config", "web/config", {"base_url": "https://web.team-a.internal", "timeout_ms": 3000})
    apps.kv_put("app-config", "web/feature-flags", {"beta_checkout": "true" if a else "false", "dark_mode": "true"})
    v.in_namespace("team-b" if a else "team-c").kv_put("app-config", "service/config", {"owner": "team-b" if a else "team-c"})
    print(f"[{v.name}] namespaces ready: {', '.join(spaces)}")


def seed_environments(a: Vault, b: Vault, pki: dict) -> None:
    """The `apps` mount: Vault A plays the test environment, Vault B dev.

    Since the last release, the team renamed Enterprise Logging App to ELP in dev, so its
    secrets moved from enterprise-logging-app/ to ELP/; test still has the old name. Values
    name their environment and the application (logs.test... vs logs.dev..., svc-enterprise-
    logging-app vs svc-elp). The shared profile "Test ↔ dev: apps (ELP rename)" maps the folder,
    rewrites test ⇄ dev and enterprise-logging-app ⇄ elp, and ignores what's meant to differ per
    environment (tokens, log level, TLS material), so what's left is what changed in dev and has
    to ship with the next release: batch_size, the new otlp_endpoint and the new ELP/alerts.
    See docs/guides/compare-environments-after-a-rename.md."""
    for v in (a, b):
        v.mount_kv("apps", description="Applications (Vault A: test, Vault B: dev)")
    a.kv_put("apps", "enterprise-logging-app/values", {
        "log_level": "info",
        "retention_days": 30,
        "batch_size": "500",
        "ingest_endpoint": "https://ingest.test.logging.example.internal",
        "index_prefix": "enterprise-logging-app-test",
        "service_account": "svc-enterprise-logging-app@test.example.internal",
        "kafka_topic": "test.enterprise-logging-app.events",
        "db_url": "postgres://pg.test.example.internal:5432/logging",
        "api_token": "tok-test-8f2a1c90",
    })
    b.kv_put("apps", "ELP/values", {
        "log_level": "debug",  # verbose in dev on purpose
        "retention_days": 30,
        "batch_size": "1000",  # changed in dev since the release: has to ship
        "ingest_endpoint": "https://ingest.dev.logging.example.internal",
        "index_prefix": "elp-dev",
        "service_account": "svc-elp@dev.example.internal",
        "kafka_topic": "dev.elp.events",
        "db_url": "postgres://pg.dev.example.internal:5432/logging",
        "api_token": "tok-dev-3b9e7741",
        "otlp_endpoint": "https://otel.dev.example.internal:4317",  # new in dev
    })
    root_pem = pem(pki["root"])
    a.kv_put("apps", "enterprise-logging-app/certs", {
        "tls.crt": pem(pki["app"]), "tls.key": key_pem(pki["app_key"]), "ca.crt": root_pem})
    b.kv_put("apps", "ELP/certs", {
        "tls.crt": pem(pki["app2"]), "tls.key": key_pem(pki["app2_key"]), "ca.crt": root_pem})
    a.kv_put("apps", "enterprise-logging-app/legacy-syslog", {
        "syslog_host": "syslog.test.example.internal", "port": "514"})  # dropped in dev
    b.kv_put("apps", "ELP/alerts", {
        "pagerduty_service": "elp-dev", "errors_per_minute": "50"})  # new in dev

    # Applications that weren't renamed: the same profile's rewrites cover them too.
    a.kv_put("apps", "payments-gateway/config", {
        "endpoint": "https://pay.test.example.internal", "timeout_ms": "3000", "currency": "GBP"})
    b.kv_put("apps", "payments-gateway/config", {
        "endpoint": "https://pay.dev.example.internal", "timeout_ms": "3000", "currency": "GBP"})
    a.kv_put("apps", "search-indexer/config", {
        "queue": "test.search.reindex", "workers": "4", "index": "products"})
    b.kv_put("apps", "search-indexer/config", {
        "queue": "dev.search.reindex", "workers": "2", "index": "products"})  # workers differs: drift


def seed_release_baseline(a: Vault, pki: dict) -> None:
    """The `apps-baseline` mount on Vault A: the last release, as it runs in prod, under the
    application's old name. It's the baseline for the environment matrix: test (Vault A `apps`) and
    dev (Vault B `apps`, after the ELP rename) are each compared with it under their own shared
    profile ("Release ↔ test: apps", "Release ↔ dev: apps (ELP rename)"), which rewrite prod to the
    environment and ignore what differs per environment by design.

    What the matrix then shows: test matches the release, so dev's changes are the odd ones out
    (batch_size, the new otlp_endpoint and ELP/alerts, legacy-syslog dropped, search-indexer's
    workers); retention_days differs in both, because prod keeps logs longer on purpose."""
    a.mount_kv("apps-baseline", description="Applications: the last release, as in prod (the environment matrix's baseline)")
    a.kv_put("apps-baseline", "enterprise-logging-app/values", {
        "log_level": "warn",
        "retention_days": 90,  # prod keeps logs longer: differs from every environment on purpose
        "batch_size": "500",
        "ingest_endpoint": "https://ingest.prod.logging.example.internal",
        "index_prefix": "enterprise-logging-app-prod",
        "service_account": "svc-enterprise-logging-app@prod.example.internal",
        "kafka_topic": "prod.enterprise-logging-app.events",
        "db_url": "postgres://pg.prod.example.internal:5432/logging",
        "api_token": "tok-prod-5c1d0e62",
    })
    a.kv_put("apps-baseline", "enterprise-logging-app/certs", {
        "tls.crt": pem(pki["app"]), "tls.key": key_pem(pki["app_key"]), "ca.crt": pem(pki["root"])})
    a.kv_put("apps-baseline", "enterprise-logging-app/legacy-syslog", {
        "syslog_host": "syslog.prod.example.internal", "port": "514"})
    a.kv_put("apps-baseline", "payments-gateway/config", {
        "endpoint": "https://pay.prod.example.internal", "timeout_ms": "3000", "currency": "GBP"})
    a.kv_put("apps-baseline", "search-indexer/config", {
        "queue": "prod.search.reindex", "workers": "4", "index": "products"})


def main() -> None:
    a = Vault("vault-a", os.environ["VAULT_A_ADDR"], os.environ["VAULT_A_TOKEN"])
    b = Vault("vault-b", os.environ["VAULT_B_ADDR"], os.environ["VAULT_B_TOKEN"])
    for v in (a, b):
        v.wait_ready()
        configure_auth(v)
        seed_ldap_and_users(v)
        print(f"[{v.name}] auth configured")
    seed_pki(a)
    seed_database(a)
    for v in (a, b):
        seed_transit(v)
        seed_ldap_secrets(v)
        seed_namespaces(v)
    for v, policies in ((a, POLICIES_A), (b, POLICIES_B)):
        for name, text in policies.items():
            v.policy(name, text)
    pki = build_pki()
    seed_data(a, b, pki)
    seed_environments(a, b, pki)
    seed_release_baseline(a, pki)
    seed_value_tool_fixtures(a, b, pki)
    seed_password_finder(a, b, pki)
    print("seed complete")


def mark_seeded() -> None:
    """SEED_MARKER (a file path): write the time each time the data is fully restored, so the
    public demo's drift check knows to record a new baseline."""
    if path := os.environ.get("SEED_MARKER"):
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n")
        os.replace(tmp, path)


if __name__ == "__main__":
    # RESEED_INTERVAL (seconds): keep running and restore the fixtures periodically (public demo).
    interval = int(os.environ.get("RESEED_INTERVAL", "0"))
    main()
    mark_seeded()
    while interval > 0:
        time.sleep(interval)
        try:
            main()
            mark_seeded()
            print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "demo data restored", flush=True)
        except Exception as e:  # keep the loop alive; the next run tries again
            print("reseed failed:", e, flush=True)
