"""`lockstep export` and `lockstep import`: secret-engine exports from the command line.

Both act on one Vault, logged in like the other commands (--vault-addr, VAULT_ADDR,
VAULT_TOKEN, ~/.vault-token, --vault-auth userpass/ldap/jwt…). The format, encryption and
import rules are the same as the web UI's (see lockstep/exports.py).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from .. import exports as ex
from ..api.compare import FileSide, Side, side_connection
from ..api.connections import client_for
from ..api.exports import ImportScopeError, import_changes, plan_import
from ..api.sync import _Ctx, apply_changes
from ..rules import IgnoreKey
from ..vault import VaultError
from .connect import CliError, add_side_args, add_tls_args, cli_settings, connect, default_name, revoke

KEY_ENV = "LOCKSTEP_EXPORT_KEY"


def add_parsers(sub) -> None:
    e = sub.add_parser("export", help="export a KV v2 mount (or prefix) with its values to a file",
                       description="Export every secret under a mount (and prefix), with values and versions, to "
                                   "a JSON file. It's encrypted with a one-time key unless you pass --no-encrypt; "
                                   "the key is printed once (or written to --key-file).")
    e.add_argument("--mount", required=True, help="KV v2 mount")
    e.add_argument("--prefix", default="", help="only export under this path")
    _rule_args(e)
    e.add_argument("--profile", metavar="FILE|NAME", help="take ignore rules from a comparison profile")
    e.add_argument("--profile-name", metavar="NAME", help="which profile, when the --profile file holds several")
    e.add_argument("--no-encrypt", action="store_true", help="write values in plain text (anyone with the file can read them)")
    e.add_argument("--key-file", metavar="FILE", help="write the key to this file (mode 600) instead of printing it")
    e.add_argument("-o", "--output", metavar="FILE", required=True, help="the export file ('-' for stdout)")
    add_side_args(e, "vault", locations=False)
    add_tls_args(e)

    i = sub.add_parser("import", help="import an export file into a KV v2 mount",
                       description="Import an export into a mount, after optional rules: leave out paths and "
                                   "keys, then transforms. Values are merged into each target secret with "
                                   "check-and-set; keys only on the target are kept and nothing is deleted, unless "
                                   "--delete-missing makes the target match the file. "
                                   f"An encrypted file's key comes from --key-file, ${KEY_ENV}, or a prompt.")
    i.add_argument("file", help="the export file")
    i.add_argument("--mount", required=True, help="KV v2 mount to import into")
    i.add_argument("--prefix", default="", help="import under this path")
    i.add_argument("--key-file", metavar="FILE", help="the export key (default: $LOCKSTEP_EXPORT_KEY, or ask)")
    i.add_argument("--rules", metavar="FILE", help="import rules: YAML/JSON with ignore_paths, ignore_keys, transforms "
                                                   "(the web UI's Save rules writes one)")
    _rule_args(i)
    i.add_argument("--replace", metavar="FIND=WITH", action="append", default=[],
                   help="replace text in string values (after --rules' transforms; repeatable). "
                        "Text starting with '-' needs the = form: --replace=-dev-=-test-")
    i.add_argument("--replace-path", metavar="FIND=WITH", action="append", default=[],
                   help="replace text in secret paths (repeatable)")
    i.add_argument("--delete-missing", action="store_true",
                   help="make the target match the file: remove keys the file doesn't have from each imported "
                        "secret, and soft-delete secrets under --prefix that aren't in the file (entries with "
                        "\"keep\": true are left alone). Deleted versions can be restored with vault kv undelete")
    i.add_argument("-y", "--yes", action="store_true", help="don't ask before writing")
    i.add_argument("-n", "--dry-run", action="store_true", help="show what would be written; write nothing")
    i.add_argument("--show-values", action="store_true", help="show old and new values (prints secrets!)")
    i.add_argument("--audit-log", metavar="FILE", help="append a JSON audit line per write to this file")
    add_side_args(i, "vault", locations=False)
    add_tls_args(i)


def _rule_args(p) -> None:
    p.add_argument("--ignore-path", metavar="GLOB", action="append", default=[], help="leave out matching secrets (repeatable)")
    p.add_argument("--ignore-key", metavar="KEY[@PATH]", action="append", default=[],
                   help="leave out keys matching KEY, under secrets matching PATH (default: everywhere; repeatable)")


def _ignore_keys(items: list[str]) -> list[IgnoreKey]:
    out = []
    for item in items:
        key, _, path = item.partition("@")
        if not key:
            raise CliError(f"--ignore-key {item!r}: give a key pattern, e.g. password or *_token@services/**")
        out.append(IgnoreKey(key=key, path=path or "**"))
    return out


def _pairs(items: list[str], flag: str) -> list[tuple[str, str]]:
    out = []
    for item in items:
        find, sep, with_ = item.partition("=")
        if not sep or not find:
            raise CliError(f"{flag} {item!r}: use FIND=WITH")
        out.append((find, with_))
    return out


def _vault(args):
    from .connect import resolve_targets
    return resolve_targets(args, sides=("vault",))["vault"]


# --------------------------------------------------------------------------- export


async def run_export(args, load_profile) -> int:
    settings = cli_settings(args)
    rules = ex.ExportRules(ignore_paths=list(args.ignore_path), ignore_keys=_ignore_keys(args.ignore_key))
    if args.profile:
        _, prof_rules = load_profile(args.profile, settings, args.profile_name)
        if prof_rules:
            rules.ignore_paths += prof_rules.ignore_paths
            rules.ignore_keys += prof_rules.ignore_keys
    t = _vault(args)
    conn = await connect(t, settings, default_name(t.addr))
    try:
        source = ex.ExportSource(vault=conn.name, url=t.addr, namespace=t.namespace, mount=args.mount.strip("/"),
                                 identity=conn.display_name)
        async with client_for(conn, settings) as v:
            try:
                doc = await ex.build(v, mount=args.mount.strip("/"), prefix=args.prefix, rules=rules, source=source,
                                     max_secrets=settings.max_tree_secrets, tool=f"lockstep {_ver()}")
            except VaultError as e:
                raise CliError(f"Export failed: {e}") from e
    finally:
        await revoke(conn, settings)

    key = None
    if args.no_encrypt:
        data = doc.dump()
    else:
        env, key = ex.encrypt(doc)
        data = env.dump()
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    to_stdout = args.output == "-"
    if to_stdout:
        sys.stdout.write(text)
    else:
        _write_private(Path(args.output), text)
    log = sys.stderr if to_stdout else sys.stdout
    n_keys = sum(len(s.data or {}) for s in doc.secrets)
    where = f"{args.mount.strip('/')}" + (f"/{doc.source.prefix}" if doc.source.prefix else "")
    print(f"Exported {len(doc.secrets)} secret{'s' if len(doc.secrets) != 1 else ''} ({n_keys} keys) from "
          f"{t.addr} {where}{'' if to_stdout else f' to {args.output}'}"
          f"{' (encrypted)' if key else ' in PLAIN TEXT: anyone with the file can read the values'}.", file=log)
    sk = doc.skipped
    if sk.ignored_paths or sk.ignored_keys:
        print(f"Left out by the rules: {sk.ignored_paths} secret(s), {sk.ignored_keys} key(s).", file=log)
    for label, items in (("unreadable", sk.unreadable), ("deleted (latest version)", sk.deleted),
                         ("folders you can't list", sk.denied_folders)):
        if items:
            print(f"Not exported, {label}: {', '.join(items)}", file=log)
    if sk.truncated:
        print("Warning: the listing hit the limit (LOCKSTEP_MAX_TREE_SECRETS); some secrets weren't exported.", file=log)
    if key:
        if args.key_file:
            _write_private(Path(args.key_file), key + "\n")
            print(f"Key written to {args.key_file}. Keep it apart from the export.", file=log)
        else:
            print(f"Key (shown once, keep it apart from the file): {key}", file=sys.stderr)
    return 0


def _write_private(path: Path, text: str) -> None:
    """Create the file readable by its owner only (it holds values or a key)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    except OSError as e:
        raise CliError(f"Can't write {path}: {e}") from e


def _ver() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("lockstep")
    except PackageNotFoundError:
        return "unknown"


# --------------------------------------------------------------------------- import


def _load_rules(args) -> ex.ImportRules:
    data: dict = {}
    if args.rules:
        try:
            data = yaml.safe_load(Path(args.rules).read_text()) or {}
        except (OSError, yaml.YAMLError) as e:
            raise CliError(f"Can't read the rules file {args.rules}: {e}") from e
    try:
        rules = ex.ImportRules.model_validate(data)
    except ValidationError as e:
        err = e.errors()[0]
        raise CliError(f"{args.rules} isn't valid import rules ({'.'.join(map(str, err['loc']))}: {err['msg']}).") from e
    rules.ignore_paths += list(args.ignore_path)
    rules.ignore_keys += _ignore_keys(args.ignore_key)
    rules.transforms += [ex.Transform(op="replace", find=f, with_=w) for f, w in _pairs(args.replace, "--replace")]
    rules.transforms += [ex.Transform(op="replace", target="paths", find=f, with_=w)
                         for f, w in _pairs(args.replace_path, "--replace-path")]
    return rules


def _key(args) -> str | None:
    if args.key_file:
        try:
            return Path(args.key_file).read_text().strip()
        except OSError as e:
            raise CliError(f"Can't read the key file: {e}") from e
    if k := os.environ.get(KEY_ENV):
        return k
    if sys.stdin.isatty():
        return getpass.getpass("Export key: ")
    return None


async def run_import(args) -> int:
    try:
        raw = json.loads(Path(args.file).read_text())
    except (OSError, ValueError) as e:
        raise CliError(f"Can't read {args.file} as JSON: {e}") from e
    encrypted = isinstance(raw, dict) and raw.get("format") == ex.ENCRYPTED_FORMAT
    try:
        doc = ex.load(raw, _key(args) if encrypted else None)
    except ex.ExportError as e:
        raise CliError(f"{args.file}: {e}" + (f" (use --key-file or ${KEY_ENV})" if encrypted and "enter its key" in str(e) else "")) from e
    rules = _load_rules(args)
    prep = ex.prepare(doc, rules)
    if not (args.yes or args.dry_run) and not sys.stdin.isatty():
        raise CliError("Not running in a terminal, so I can't ask before writing: add --yes or --dry-run.")
    if args.audit_log:
        import logging
        h = logging.FileHandler(args.audit_log)
        h.setFormatter(logging.Formatter("%(message)s"))
        log = logging.getLogger("lockstep.audit")
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False

    settings = cli_settings(args)
    t = _vault(args)
    conn = await connect(t, settings, default_name(t.addr))
    try:
        fside = FileSide(export=prep.doc, name=Path(args.file).name)
        target = Side(conn_id=conn.id, mount=args.mount, prefix=args.prefix)
        ctx = _Ctx.direct(side_connection(fside, None), conn, fside, target, settings)
        async with ctx:
            try:
                plans, warnings = await plan_import(ctx, prep, args.delete_missing, args.show_values,
                                                    settings.max_tree_secrets)
            except ImportScopeError as e:
                raise CliError(str(e)) from e
            _print_preview(prep, plans, warnings, doc, t.addr, args)
            ready = [p for p in plans if p.status == "ready"]
            if not ready or args.dry_run:
                if args.dry_run:
                    print("Dry run: nothing written.")
                return 0 if all(p.status in ("ready", "noop") for p in plans) else 1
            if not args.yes:
                n_del = sum(p.action == "delete" for p in ready)
                what = _count(len(ready) - n_del, "secret") + (f" and delete {_count(n_del, 'secret')}" if n_del else "")
                answer = input(f"Write {what} in {t.addr} {args.mount.strip('/')}? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    print("Nothing written.")
                    return 1
            changes = import_changes(prep, {p.path: p.target.version if p.target.state != "absent" else None
                                            for p in ready}, args.delete_missing)
            out = await apply_changes(ctx, changes)
    finally:
        await revoke(conn, settings)
    for r in out.results:
        if r.status != "applied":
            print(f"  {r.status:<9} {r.path}: {r.message}")
    s = out.summary
    n_del = sum(r.status == "applied" and r.action == "delete" for r in out.results)
    print(f"Wrote {_count(s['applied'] - n_del, 'secret')}" + (f", deleted {n_del}" if n_del else "")
          + (f"; {s['conflict']} changed meanwhile (not written)" if s["conflict"] else "")
          + (f"; {s['denied'] + s['error']} failed" if s["denied"] + s["error"] else "") + ".")
    return 0 if s["applied"] == len(changes) and all(p.status in ("ready", "noop") for p in plans) else 1


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'s' if n != 1 else ''}"


def _print_preview(prep: ex.Prepared, plans, warnings: list[str], doc: ex.ExportDoc, addr: str, args) -> None:
    src = doc.source
    print(f"From: {args.file} ({src.vault} {src.mount}{'/' + src.prefix if src.prefix else ''}, "
          f"exported {doc.created_at}, {len(doc.secrets)} secrets)")
    print(f"To:   {addr} {args.mount.strip('/')}{'/' + args.prefix.strip('/') if args.prefix.strip('/') else ''}")
    if prep.ignored_paths or prep.ignored_keys:
        print(f"Left out by the rules: {prep.ignored_paths} secret(s), {prep.ignored_keys} key(s).")
    if prep.paths_changed or prep.keys_changed or prep.values_changed:
        print(f"Transforms changed {prep.paths_changed} path(s), {prep.keys_changed} key name(s), "
              f"{prep.values_changed} value(s).")
    if prep.kept:
        print(f"Kept as they are: {', '.join(prep.kept)}.")
    for path, msg in sorted(prep.problems.items()):
        print(f"  skipped   {path}: {msg}")
    for w in warnings:
        print(f"  warning   {w}")
    width = max((len(p.path) for p in plans), default=0)
    print()
    for p in plans:
        changed = [k for k in p.keys if k.action != "unchanged"]
        if p.status == "noop":
            continue
        if p.action == "delete":
            label = "delete" if p.status == "ready" else p.status
            detail = f"{_count(len(p.keys), 'key')}, v{p.target.version}" if p.status == "ready" else "; ".join(p.problems)
        else:
            label = {"ready": "new" if p.target.state == "absent" else "update"}.get(p.status, p.status)
            detail = ", ".join(f"{k.key} ({k.action})" for k in changed) if p.status == "ready" else "; ".join(p.problems)
        print(f"  {label:<9} {p.path:<{width}}  {detail}")
        if args.show_values and p.status == "ready":
            for k in changed:
                if k.action == "remove":
                    print(f"            {k.key}: {json.dumps(k.target_value)} -> (removed)")
                    continue
                old = "" if k.action == "add" else f"{json.dumps(k.target_value)} -> "
                print(f"            {k.key}: {old}{json.dumps(k.source_value)}")
    writes = [p for p in plans if p.action == "write"]
    ready = sum(p.status == "ready" for p in writes)
    noop = sum(p.status == "noop" for p in writes)
    dels = sum(p.status == "ready" for p in plans if p.action == "delete")
    blocked = sum(p.status not in ("ready", "noop") for p in plans)
    print(f"\n{ready} to write, {noop} already the same" + (f", {dels} to delete" if args.delete_missing else "")
          + (f", {blocked} can't be done" if blocked else "") + ".")
