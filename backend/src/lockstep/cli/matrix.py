"""`lockstep matrix FILE`: compare one baseline with several environments, from a matrix file.

  baseline:
    name: prod
    addr: https://vault.prod.example.com
    mount: app-config
    prefix: services
  environments:
    - {name: staging, addr: https://vault.staging.example.com, profile: profiles/prod-staging.yaml}
    - {name: dev, addr: https://vault.dev.example.com, prefix: services-dev}

Each environment is compared with the baseline under its own profile. Exit codes like compare:
0 = every environment matches, 1 = something differs (or couldn't be told), 2 = couldn't compare.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .. import matrix as matrix_mod
from ..vault import VaultError
from .connect import AUTH_METHODS, CliError, Target, add_tls_args, cli_settings, connect, env, revoke
from .formats import _cell, _code, _md

FORMATS = ("text", "json", "yaml", "markdown", "csv")
_BY_SUFFIX = {".json": "json", ".yaml": "yaml", ".yml": "yaml", ".md": "markdown", ".markdown": "markdown",
              ".csv": "csv", ".txt": "text"}
WORD = {"equal": "equal", "different": "different", "missing": "missing", "extra": "extra",
        "not_compared": "not compared", "absent": ""}


class AuthSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal[AUTH_METHODS] = "token"  # type: ignore[valid-type]
    mount: str | None = None  # the auth mount (default: the method's name)
    role: str | None = None  # jwt and kubernetes
    user: str | None = None  # userpass and ldap
    token_file: str | None = None
    jwt_file: str | None = None


class Place(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)
    addr: str | None = None
    namespace: str | None = None
    mount: str | None = None
    prefix: str | None = None
    auth: AuthSpec | None = None


class EnvSpec(Place):
    profile: str | None = None  # a profile file, or a name from $LOCKSTEP_PROFILES
    profile_name: str | None = None  # which profile, when the file holds several


class MatrixFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    auth: AuthSpec | None = None  # the default login for every Vault
    baseline: Place
    environments: list[EnvSpec] = Field(min_length=1, max_length=matrix_mod.MAX_ENVIRONMENTS)


def add_parser(sub) -> None:
    m = sub.add_parser(
        "matrix", help="compare one baseline with several environments, odd one out first",
        description="Compare a baseline (say prod) with several environments, each under its own comparison "
                    "profile, and print a grid: a row per secret and key, a column per environment. A key that "
                    "differs in only one environment comes first. Statuses only, never values. Logins: "
                    "LOCKSTEP_<NAME>_TOKEN (the name upper-cased, other characters as _), then VAULT_TOKEN or "
                    "~/.vault-token, or an auth: block in the file.")
    m.add_argument("file", help="the matrix file (YAML or JSON): baseline, environments, and optionally auth")
    m.add_argument("-o", "--output", metavar="FILE", action="append",
                   help="also write the matrix here ('-' for stdout); the format follows the extension: "
                        ".json, .yaml, .md, .csv, .txt. Repeat it for several formats")
    m.add_argument("--format", choices=FORMATS, help="the format of every -o, instead of following the extension")
    m.add_argument("--include-equal", action="store_true", help="list the rows where every environment matches too")
    m.add_argument("-q", "--quiet", action="store_true", help="don't print the grid")
    add_tls_args(m)


def load(path: str) -> MatrixFile:
    try:
        raw = yaml.safe_load(Path(path).read_text())
    except OSError as e:
        raise CliError(f"Can't read {path}: {e}") from e
    except yaml.YAMLError as e:
        raise CliError(f"{path} isn't valid YAML or JSON: {e}") from e
    try:
        spec = MatrixFile.model_validate(raw or {})
    except ValidationError as e:
        problems = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
        raise CliError(f"{path} isn't a valid matrix file: {problems}") from e
    names = [spec.baseline.name, *(e.name for e in spec.environments)]
    stems = [stem(n) for n in names]
    if len(set(names)) != len(names) or len(set(stems)) != len(stems):
        raise CliError(f"{path}: give the baseline and each environment a different name "
                       f"(they name the LOCKSTEP_<NAME>_TOKEN variables).")
    return spec


def stem(name: str) -> str:
    """The environment-variable part of a name: LOCKSTEP_<STEM>_TOKEN."""
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "env"


def _target(p: Place, default_auth: AuthSpec | None, addr: str, namespace: str | None) -> Target:
    a = p.auth or default_auth or AuthSpec()
    which = stem(p.name)
    u = urlparse(addr)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise CliError(f"{p.name}: the Vault address must be http(s)://host[:port], not {addr!r}.")
    if a.method == "kubernetes" and not a.role:
        raise CliError(f"{p.name}: kubernetes login needs auth.role.")
    if a.method in ("userpass", "ldap") and not (a.user or os.environ.get(env(which, "USER"))):
        raise CliError(f"{p.name}: {a.method} login needs auth.user (or {env(which, 'USER')}).")
    explicit = p.auth is not None or any(os.environ.get(env(which, k)) for k in ("TOKEN", "JWT"))
    return Target(which=which, addr=addr.rstrip("/"), namespace=namespace or None, auth=a.method,
                  explicit_auth=explicit, user=a.user or os.environ.get(env(which, "USER")), auth_mount=a.mount,
                  token_file=a.token_file, jwt_file=a.jwt_file, role=a.role)


def _login_key(t: Target) -> tuple:
    return (t.addr, t.namespace, t.auth, t.user, t.auth_mount, t.token_file, t.jwt_file, t.role)


def _profile_ref(ref: str, file: str) -> str:
    near = Path(file).expanduser().parent / ref
    return str(near) if not Path(ref).is_absolute() and near.is_file() else ref


async def run(args) -> int:
    from . import _load_profile  # the compare command's profile loader
    from ..api.connections import client_for

    spec = load(args.file)
    outputs = args.output or []
    if outputs.count("-") > 1:
        raise CliError("Only one -o can be '-' (stdout).")
    settings = cli_settings(args)
    b = spec.baseline
    base_addr = b.addr or os.environ.get(env(stem(b.name), "ADDR")) or os.environ.get("VAULT_ADDR")
    if not base_addr:
        raise CliError(f"No Vault address for {b.name}: set baseline.addr (or VAULT_ADDR).")
    base_ns = b.namespace or os.environ.get("VAULT_NAMESPACE")
    if not b.mount:
        raise CliError(f"No mount for {b.name}: set baseline.mount.")
    base_mount, base_prefix = b.mount.strip("/"), (b.prefix or "").strip("/")

    places: list[tuple[Place, Target, str, str, object]] = [(b, _target(b, spec.auth, base_addr, base_ns),
                                                             base_mount, base_prefix, None)]
    for e in spec.environments:
        profile, rules = _load_profile(_profile_ref(e.profile, args.file), settings, e.profile_name) if e.profile \
            else (None, None)
        addr = (e.addr or base_addr).rstrip("/")
        ns = e.namespace if e.namespace is not None else (base_ns if addr == base_addr.rstrip("/") else None)
        mount = e.mount or (profile.right_mount if profile else None) or base_mount
        prefix = e.prefix if e.prefix is not None else (profile.right_prefix if profile and profile.right_prefix is not None
                                                        else base_prefix)
        places.append((e, _target(e, spec.auth, addr, ns), mount.strip("/"), (prefix or "").strip("/"), rules))

    conns, logins = [], {}
    try:
        for p, t, *_ in places:
            key = _login_key(t)
            if key in logins and not t.explicit_auth:
                conns.append(logins[key].model_copy(update={"name": p.name, "minted": False}))
                continue
            c = await connect(t, settings, p.name)
            logins.setdefault(key, c)
            conns.append(c)
        async with _clients(client_for, conns, settings) as clients:
            envs = [matrix_mod.EnvInput(name=p.name, client=c, mount=m, prefix=f"{pre}/" if pre else "", rules=r)
                    for (p, _t, m, pre, r), c in zip(places[1:], clients[1:])]
            try:
                result = await matrix_mod.run(b.name, clients[0], base_mount, f"{base_prefix}/" if base_prefix else "",
                                              envs, max_secrets=settings.max_tree_secrets,
                                              include_equal=args.include_equal)
            except VaultError as e:
                raise CliError(f"Couldn't list {b.name} ({base_mount}): {e.message}") from e
    finally:
        await asyncio.gather(*(revoke(c, settings) for c in conns))

    addrs = {p.name: t.addr for p, t, *_ in places}
    to_stdout = "-" in outputs
    out = sys.stderr if to_stdout else sys.stdout
    if not args.quiet:
        out.write(text(result, addrs))
    for target in outputs:
        fmt = args.format or next((f for s, f in _BY_SUFFIX.items() if target.lower().endswith(s)), "json")
        body = render(result, fmt, addrs)
        if target == "-":
            sys.stdout.write(body)
        else:
            Path(target).write_text(body)
            if not args.quiet:
                print(f"Matrix written to {target}.", file=out)
    if result.summary["failed"]:
        return 2
    return 1 if result.summary["differing_rows"] or result.summary["unknown_rows"] else 0


class _clients:
    """Open a client per connection; close them all."""

    def __init__(self, factory, conns, settings):
        self.items = [factory(c, settings) for c in conns]

    async def __aenter__(self):
        return [await c.__aenter__() for c in self.items]

    async def __aexit__(self, *exc):
        for c in self.items:
            await c.__aexit__(*exc)


def render(m: matrix_mod.Matrix, fmt: str, addrs: dict[str, str] | None = None) -> str:
    if fmt == "json":
        return json.dumps(m.model_dump(), indent=2, ensure_ascii=False) + "\n"
    if fmt == "yaml":
        return yaml.safe_dump(m.model_dump(), sort_keys=False, allow_unicode=True)
    if fmt == "markdown":
        return markdown(m)
    if fmt == "csv":
        return csv_(m)
    return text(m, addrs or {})


def _where(mount: str, prefix: str) -> str:
    return mount + (f"/{prefix}" if prefix else "")


def _what(r: matrix_mod.MatrixRow) -> str:
    return r.path if r.key is None else f"{r.path} · {r.key}"


def text(m: matrix_mod.Matrix, addrs: dict[str, str]) -> str:
    b = m.baseline
    lines = [f"Baseline: {b.name} ({addrs.get(b.name, '')}) {_where(b.mount, b.prefix)}".replace(" () ", " ")]
    for e in m.environments:
        where = f"{e.name} ({addrs.get(e.name, '')}) {_where(e.mount, e.prefix)}".replace(" () ", " ")
        lines.append(f"  {where}" + (f": couldn't compare: {e.error}" if e.error else ""))
    if m.rows:
        width = min(60, max(len(_what(r)) for r in m.rows))
        cols = [max(len(e.name), 7) for e in m.environments]
        lines += ["", " " * (width + 4) + "  ".join(e.name.ljust(w) for e, w in zip(m.environments, cols)).rstrip()]
        for r in m.rows:
            what = _what(r)
            what = what if len(what) <= width else "…" + what[-(width - 1):]
            cells = "  ".join(matrix_mod.SYMBOL[c.status].ljust(w) for c, w in zip(r.cells, cols))
            lines.append(f"  {what:<{width}}  {cells}".rstrip())
        lines.append("\n= equal  ≠ different  missing: not in this environment  extra: only in this environment  "
                     "? not compared  · neither has it")
    s = m.summary
    n = s["environments"]
    if s["differing_rows"] or s["unknown_rows"]:
        lines.append(f"\n{s['differing_rows']} row{'s' if s['differing_rows'] != 1 else ''} differ"
                     f"{'s' if s['differing_rows'] == 1 else ''} from {b.name}"
                     + (f"; {s['odd_one_out']} in only one environment (listed first)" if n > 1 and s["odd_one_out"] else "")
                     + (f"; {s['unknown_rows']} couldn't be told" if s["unknown_rows"] else "") + ".")
    else:
        lines.append(f"\nEvery environment matches {b.name}" + (" (except those that couldn't be compared)." if s["failed"] else "."))
    return "\n".join(lines) + "\n"


MD = {"equal": "=", "different": "≠ different", "missing": "missing", "extra": "extra", "not_compared": "? not compared",
      "absent": "·"}


def markdown(m: matrix_mod.Matrix) -> str:
    b = m.baseline
    out = ["### Lockstep: environment matrix", "",
           f"Baseline **{_md(b.name)}** ({_code(_where(b.mount, b.prefix))}) compared with "
           + ", ".join(f"**{_md(e.name)}** ({_code(_where(e.mount, e.prefix))})" for e in m.environments) + ".", ""]
    for e in m.environments:
        if e.error:
            out += [f"> **{_md(e.name)}** couldn't be compared: {_md(e.error)}", ""]
    if m.rows:
        out.append("| Secret | Key | " + " | ".join(_md(e.name) for e in m.environments) + " |")
        out.append("|---|---|" + "---|" * len(m.environments))
        for r in m.rows:
            out.append(f"| {_code(r.path)} | {_code(r.key) if r.key is not None else '(the secret)'} | "
                       + " | ".join(MD[c.status] for c in r.cells) + " |")
        out.append("")
    s = m.summary
    out.append(f"{s['differing_rows']} rows differ, {s['odd_one_out']} in only one environment. Values are never shown.")
    return "\n".join(out) + "\n"


def csv_(m: matrix_mod.Matrix) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["secret", "key", *(_cell(e.name) for e in m.environments)])
    for r in m.rows:
        w.writerow([_cell(r.path), _cell(r.key or ""), *(WORD[c.status] for c in r.cells)])
    return buf.getvalue()
