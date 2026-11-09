"""Connecting the CLI to each side's Vault, the way the vault CLI does.

Per side (left/right), first match wins:
  address    --left-addr, LOCKSTEP_LEFT_ADDR, VAULT_ADDR        (right: also falls back to the left's)
  namespace  --left-namespace, LOCKSTEP_LEFT_NAMESPACE, VAULT_NAMESPACE
  token      LOCKSTEP_LEFT_TOKEN, --left-token-file, VAULT_TOKEN, ~/.vault-token
             (or --left-auth userpass/ldap: logs in and prompts for the password, or reads
             LOCKSTEP_LEFT_PASSWORD; the token it gets is revoked when the command ends)
TLS follows the vault CLI too: VAULT_CACERT / --ca-cert, VAULT_SKIP_VERIFY / --tls-skip-verify.

When the right side points at the same Vault and namespace as the left and has no auth
options of its own, it reuses the left side's connection.
Tokens are never accepted as command-line arguments (they'd show up in `ps` and shell history).
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ..api.connections import connection_from_token
from ..config import Settings
from ..session import Connection
from ..vault import VaultClient, VaultError

SIDES = ("left", "right")
AUTH_METHODS = ("token", "userpass", "ldap")


class CliError(Exception):
    """A problem to report to the user in one line (exit code 2)."""


def add_tls_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("TLS (both sides)")
    g.add_argument("--ca-cert", metavar="FILE", help="CA bundle for verifying Vault (default: $VAULT_CACERT)")
    g.add_argument("--tls-skip-verify", action="store_true",
                   help="don't verify Vault's certificate (default: $VAULT_SKIP_VERIFY); insecure")


def add_side_args(p: argparse.ArgumentParser, which: str, *, locations: bool) -> None:
    """--left-* / --right-* options. `locations` adds mount, prefix, name and UI address
    (compare); apply takes those from the report."""
    other = "left" if which == "right" else None
    g = p.add_argument_group(f"{which} side")
    if locations:
        fallback = f"${env(which, 'ADDR')}, then " + ("the left side's address" if other else "$VAULT_ADDR")
    else:
        fallback = f"${env(which, 'ADDR')}, then the address in the report"
    g.add_argument(f"--{which}-addr", metavar="URL", help=f"Vault address (default: {fallback})")
    g.add_argument(f"--{which}-namespace", metavar="NS",
                   help="Vault Enterprise namespace" + ("" if locations else " (default: the report's)"))
    if locations:
        g.add_argument(f"--{which}-mount", metavar="MOUNT", help="KV v2 mount (default: --mount)")
        g.add_argument(f"--{which}-prefix", metavar="PATH", help="only compare under this path (default: --prefix)")
        g.add_argument(f"--{which}-name", metavar="NAME", help="label for this side in the report (default: host)")
        g.add_argument(f"--{which}-ui-addr", metavar="URL",
                       help="address people open the Vault UI at, if it differs from --{which}-addr")
    g.add_argument(f"--{which}-auth", choices=AUTH_METHODS, default=None,
                   help="how to log in (default: token)")
    g.add_argument(f"--{which}-user", metavar="NAME", help="username for userpass/ldap "
                                                           f"(default: ${env(which, 'USER')})")
    g.add_argument(f"--{which}-auth-mount", metavar="PATH", help="auth mount path (default: the method name)")
    g.add_argument(f"--{which}-token-file", metavar="FILE", help=f"read the token from this file "
                                                                 f"(after ${env(which, 'TOKEN')})")


def env(which: str, name: str) -> str:
    return f"LOCKSTEP_{which.upper()}_{name}"


def cli_settings(args: argparse.Namespace) -> Settings:
    """Settings for talking to Vault. The web-only settings get harmless defaults; the
    session key is random because the CLI never makes cookies or signed plans."""
    ca = args.ca_cert or os.environ.get("VAULT_CACERT") or None
    skip = args.tls_skip_verify or os.environ.get("VAULT_SKIP_VERIFY", "").lower() in ("1", "true", "yes")
    if ca and not Path(ca).is_file():
        raise CliError(f"CA bundle not found: {ca}")
    # LOCKSTEP_PROFILES and LOCKSTEP_MAX_TREE_SECRETS still come from the environment
    return Settings(session_key=secrets.token_hex(32), vault_tls_verify=not skip, vault_ca_bundle=ca)


@dataclass
class Target:
    """Where one side's Vault is and how to log in."""

    which: str
    addr: str
    namespace: str | None
    auth: str  # token | userpass | ldap
    explicit_auth: bool  # the user gave this side its own auth options
    user: str | None
    auth_mount: str | None
    token_file: str | None


def _opt(args, which: str, name: str):
    return getattr(args, f"{which}_{name}", None)


def resolve_targets(args: argparse.Namespace, defaults: dict[str, dict] | None = None) -> dict[str, Target]:
    """Work out each side's address, namespace and login method. `defaults` supplies
    per-side addr/namespace (apply: from the report), used before the environment."""
    defaults = defaults or {}
    out: dict[str, Target] = {}
    for which in SIDES:
        d = defaults.get(which, {})
        addr = (_opt(args, which, "addr") or os.environ.get(env(which, "ADDR")) or d.get("addr")
                or (out["left"].addr if which == "right" else os.environ.get("VAULT_ADDR")))
        if not addr:
            raise CliError(f"No Vault address for the {which} side: use --{which}-addr or set VAULT_ADDR.")
        u = urlparse(addr)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise CliError(f"The {which} Vault address must be http(s)://host[:port], not {addr!r}.")
        ns_given = _opt(args, which, "namespace") or os.environ.get(env(which, "NAMESPACE"))
        if ns_given:
            ns = ns_given
        elif "namespace" in d:
            ns = d["namespace"]
        elif which == "right" and addr.rstrip("/") == out["left"].addr:
            ns = out["left"].namespace
        else:
            ns = os.environ.get("VAULT_NAMESPACE")
        explicit = any(_opt(args, which, k) for k in ("auth", "user", "auth_mount", "token_file")) \
            or bool(os.environ.get(env(which, "TOKEN")))
        out[which] = Target(which=which, addr=addr.rstrip("/"), namespace=ns or None,
                            auth=_opt(args, which, "auth") or "token", explicit_auth=explicit,
                            user=_opt(args, which, "user") or os.environ.get(env(which, "USER")),
                            auth_mount=_opt(args, which, "auth_mount"), token_file=_opt(args, which, "token_file"))
    return out


def _read_token(t: Target) -> str:
    if tok := os.environ.get(env(t.which, "TOKEN")):
        return tok.strip()
    if t.token_file:
        try:
            return Path(t.token_file).expanduser().read_text().strip()
        except OSError as e:
            raise CliError(f"Can't read the {t.which} token file: {e}") from e
    if tok := os.environ.get("VAULT_TOKEN"):
        return tok.strip()
    p = Path.home() / ".vault-token"
    if p.is_file():
        return p.read_text().strip()
    raise CliError(f"No token for the {t.which} side ({t.addr}). Run `vault login` or set VAULT_TOKEN "
                   f"(or {env(t.which, 'TOKEN')}), or use --{t.which}-auth userpass/ldap.")


def _password(t: Target) -> str:
    if pw := os.environ.get(env(t.which, "PASSWORD")):
        return pw
    if not sys.stdin.isatty():
        raise CliError(f"No password for {t.user} on the {t.which} side: run interactively or set "
                       f"{env(t.which, 'PASSWORD')}.")
    return getpass.getpass(f"Password for {t.user} at {t.addr}: ")


async def connect(t: Target, settings: Settings, name: str) -> Connection:
    """Log in (or check the token) and return a connection. Raises CliError."""
    async with VaultClient(t.addr, settings, namespace=t.namespace) as anon:
        minted = False
        if t.auth == "token":
            token = _read_token(t)
        else:
            if not t.user:
                raise CliError(f"--{t.which}-user is required for {t.auth} login.")
            mount = t.auth_mount or t.auth
            try:
                login = anon.login_userpass if t.auth == "userpass" else anon.login_ldap
                token = (await login(t.user, _password(t), mount=mount))["client_token"]
            except VaultError as e:
                raise CliError(f"{t.auth} login to {t.addr} as {t.user} failed: {e.message}") from e
            minted = True
    async with VaultClient(t.addr, settings, token=token, namespace=t.namespace) as v:
        try:
            info = await v.lookup_self()
        except VaultError as e:
            if e.status == 0:
                raise CliError(f"Can't reach the {t.which} Vault: {e.message}") from e
            raise CliError(f"The {t.which} Vault ({t.addr}) rejected the token: {e.message}") from e
    return connection_from_token(token=token, info=info, url=t.addr, namespace=t.namespace, name=name,
                                 preset_id=None, method=t.auth, minted=minted)


async def connect_both(targets: dict[str, Target], settings: Settings,
                       names: dict[str, str]) -> tuple[Connection, Connection]:
    left = await connect(targets["left"], settings, names["left"])
    r = targets["right"]
    same = r.addr == targets["left"].addr and r.namespace == targets["left"].namespace
    if same and not r.explicit_auth:
        right = left.model_copy(update={"name": names["right"], "minted": False})
    else:
        try:
            right = await connect(r, settings, names["right"])
        except BaseException:
            await revoke(left, settings)
            raise
    return left, right


async def revoke(conn: Connection, settings: Settings) -> None:
    """Revoke a token we created by logging in. Best effort."""
    if not conn.minted:
        return
    try:
        async with VaultClient(conn.url, settings, token=conn.token, namespace=conn.namespace) as v:
            await v.revoke_self()
    except VaultError:
        pass


def default_name(addr: str) -> str:
    return urlparse(addr).netloc or addr
