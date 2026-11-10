"""Lockstep on the command line: compare two KV v2 locations into a report, then apply it.

  lockstep compare --left-addr https://vault-a --right-addr https://vault-b --mount app-config -o report.yaml
  (edit the actions in report.yaml)
  lockstep apply report.yaml

  lockstep export --vault-addr https://vault-a --mount app-config -o export.json   (prints a one-time key)
  lockstep import export.json --vault-addr https://vault-b --mount app-config --replace app-dev=app-test

Exit codes, like diff(1): compare 0 = no differences, 1 = differences, 2 = couldn't compare.
apply/import 0 = done, 1 = some secrets were skipped (changed since the report or preview, or not
writable), 2 = couldn't run (bad file, login failed, ...).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..rules import Profile, Rules
from ..vault import VaultError
from . import apply as apply_mod
from . import report as report_mod
from . import transfer
from .connect import (CliError, SIDES, add_side_args, add_tls_args, cli_settings, connect_both, default_name,
                      resolve_targets, revoke)

DIFFERENT = ("different", "left_only", "right_only")
LABEL = {"different": "different", "left_only": "left only", "right_only": "right only",
         "no_access": "no access", "error": "error", "equal": "equal"}


def _version() -> str:
    try:
        return version("lockstep")
    except PackageNotFoundError:
        return "unknown"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lockstep", description="Compare and sync KV v2 secrets across Vault clusters, mounts and paths.",
        epilog="Logs in like the vault CLI: VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, ~/.vault-token, or "
               "per side LOCKSTEP_LEFT_ADDR / LOCKSTEP_LEFT_TOKEN / LOCKSTEP_RIGHT_... . "
               "Run `lockstep COMMAND --help` for details.")
    p.add_argument("--version", action="version", version=f"lockstep {_version()}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    c = sub.add_parser("compare", help="compare two locations and write a report of the differences",
                       description="Compare two KV v2 locations. Prints a summary and, with -o, writes a YAML "
                                   "report: no values, but each secret's Vault UI link and `vault kv get` "
                                   "command, and an action per key to fill in for `lockstep apply`.")
    c.add_argument("--mount", help="KV v2 mount on both sides (or --left-mount / --right-mount)")
    c.add_argument("--prefix", default=None, help="only compare under this path on both sides")
    c.add_argument("--profile", metavar="FILE|NAME",
                   help="comparison profile: a YAML/JSON file (a profile, or just its rules) or a name "
                        "from $LOCKSTEP_PROFILES")
    c.add_argument("--profile-name", metavar="NAME", help="which profile, when the --profile file holds several")
    c.add_argument("-o", "--output", metavar="FILE", help="write the report here ('-' for stdout)")
    c.add_argument("--include-equal", action="store_true", help="list equal secrets in the report too")
    c.add_argument("-q", "--quiet", action="store_true", help="don't print the summary")
    for which in SIDES:
        add_side_args(c, which, locations=True)
    add_tls_args(c)

    a = sub.add_parser("apply", help="carry out the actions set in a report",
                       description="Carry out the actions set in a report from `lockstep compare`. Values are "
                                   "read fresh from the source; each key is confirmed before it's written. A "
                                   "secret that changed in Vault since the report was made is skipped.")
    a.add_argument("report", help="the report file ('-' for stdin; then --yes or --dry-run is needed)")
    a.add_argument("-y", "--yes", action="store_true", help="don't ask: write every key the report says to")
    a.add_argument("-n", "--dry-run", action="store_true", help="show what would be written; write nothing")
    a.add_argument("--show-values", action="store_true",
                   help="show the current and new value of each key before asking (prints secrets!)")
    a.add_argument("--audit-log", metavar="FILE", help="append a JSON audit line per write to this file")
    for which in SIDES:
        add_side_args(a, which, locations=False)
    add_tls_args(a)

    transfer.add_parsers(sub)

    s = sub.add_parser("schema", help="print a JSON Schema (report, export or import rules)",
                       description=f"Print the JSON Schema of a Lockstep file. report (the default, also at "
                                   f"{report_mod.SCHEMA_URL}): editors use it to complete and check `action:` values.")
    s.add_argument("kind", nargs="?", choices=("report", "export", "import-rules"), default="report")
    return p


# --------------------------------------------------------------------------- compare


def _load_profile(ref: str | None, settings, name: str | None = None) -> tuple[Profile | None, Rules | None]:
    if not ref:
        return None, None
    path = Path(ref).expanduser()
    if path.is_file():
        try:
            raw = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            raise CliError(f"{ref} isn't valid YAML or JSON: {e}") from e
        if isinstance(raw, dict) and "profiles" in raw:  # the web UI's export: {"profiles": [...]}
            raw = raw["profiles"]
        if isinstance(raw, list):
            names = [p.get("name") for p in raw if isinstance(p, dict)]
            if name:
                if name not in names:
                    raise CliError(f"{ref} has no profile named {name!r} (it has: {', '.join(map(str, names))}).")
                raw = raw[names.index(name)]
            elif len(raw) == 1:
                raw = raw[0]
            else:
                raise CliError(f"{ref} holds {len(raw)} profiles ({', '.join(map(str, names))}): "
                               f"pick one with --profile-name.")
        try:
            if isinstance(raw, dict) and ("rules" in raw or "name" in raw):
                prof = Profile.model_validate({"name": path.stem, **raw})
                return prof, prof.rules
            return None, Rules.model_validate(raw or {})
        except ValidationError as e:
            raise CliError(f"{ref} isn't a valid profile: {e}") from e
    for prof in settings.profiles:
        if prof.name == ref:
            return prof, prof.rules
    raise CliError(f"No profile file or $LOCKSTEP_PROFILES entry named {ref!r}.")


def _print_summary(rep: report_mod.Report, out) -> None:
    def where(s: report_mod.ReportSide) -> str:
        loc = s.mount + (f"/{s.prefix.strip('/')}" if s.prefix.strip("/") else "")
        return f"{s.name} ({s.addr}{f', namespace {s.namespace}' if s.namespace else ''}) {loc}"

    print(f"Left:  {where(rep.left)}", file=out)
    print(f"Right: {where(rep.right)}", file=out)
    if rep.profile:
        print(f"Profile: {rep.profile}", file=out)
    rows = [s for s in rep.secrets if s.status != "equal"]
    if rows:
        width = max(len(s.path) for s in rows)
        print(file=out)
        for s in rows:
            detail = ", ".join(k.key + (" (type)" if k.type_differs else "") + (" (ignored)" if k.ignored else "")
                               for k in s.keys if k.status == "different")
            if s.left.path != s.right.path:
                detail = f"left {s.left.path}" + (f"; differs: {detail}" if detail else "")
            elif detail:
                detail = f"differs: {detail}"
            if s.note:
                detail = s.note
            print(f"  {LABEL.get(s.status, s.status):<11} {s.path:<{width}}  {detail}".rstrip(), file=out)
    for w in rep.warnings:
        print(f"\nWarning: {w}", file=out)
    sm = rep.summary
    counts = ", ".join(f"{sm[k]} {LABEL[k]}" for k in ("equal", "different", "left_only", "right_only",
                                                           "no_access", "error") if sm.get(k))
    print(f"\n{sm.get('total', 0)} secrets: {counts or 'none found'}.", file=out)


async def _compare(args) -> int:
    settings = cli_settings(args)
    profile, rules = _load_profile(args.profile, settings, args.profile_name)
    targets = resolve_targets(args)

    sides: dict[str, report_mod.ReportSide] = {}
    for which in SIDES:
        t = targets[which]
        mount = (getattr(args, f"{which}_mount") or args.mount
                 or (getattr(profile, f"{which}_mount", None) if profile else None))
        if not mount:
            raise CliError(f"No mount for the {which} side: use --mount or --{which}-mount.")
        prefix = getattr(args, f"{which}_prefix")
        if prefix is None:
            prefix = args.prefix
        if prefix is None and profile:
            prefix = getattr(profile, f"{which}_prefix", None)
        sides[which] = report_mod.ReportSide(
            name=getattr(args, f"{which}_name") or default_name(t.addr), addr=t.addr, namespace=t.namespace,
            mount=mount.strip("/"), prefix=(prefix or "").strip("/"),
            ui_addr=(getattr(args, f"{which}_ui_addr") or "").rstrip("/") or None)
    if sides["left"].name == sides["right"].name and sides["left"].mount == sides["right"].mount:
        sides["left"].name += " (left)"
        sides["right"].name += " (right)"

    from ..api.connections import client_for
    from ..engine import compare

    lconn, rconn = await connect_both(targets, settings, {w: sides[w].name for w in SIDES})
    try:
        sides["left"].identity, sides["right"].identity = lconn.display_name, rconn.display_name
        async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
            try:
                result = await compare(lv, sides["left"].mount, report_mod._prefix(sides["left"].prefix),
                                       rv, sides["right"].mount, report_mod._prefix(sides["right"].prefix),
                                       rules, max_secrets=settings.max_tree_secrets)
            except VaultError as e:
                raise CliError(f"Comparison failed: {e}") from e
    finally:
        await asyncio.gather(revoke(lconn, settings), revoke(rconn, settings))

    rep = report_mod.build(result, sides["left"], sides["right"], profile.name if profile else None,
                           include_equal=args.include_equal)
    to_stdout = args.output == "-"
    if not args.quiet:
        _print_summary(rep, sys.stderr if to_stdout else sys.stdout)
    if args.output:
        text = report_mod.dump(rep, "-" if to_stdout else args.output)
        if to_stdout:
            sys.stdout.write(text)
        else:
            Path(args.output).write_text(text)
            if not args.quiet:
                print(f"Report written to {args.output}. Set actions in it, then run: lockstep apply {args.output}")
    elif not args.quiet and any(s.status in DIFFERENT for s in rep.secrets):
        print("Add -o report.yaml to write a report you can act on with `lockstep apply`.")
    sm = rep.summary
    return 1 if any(sm.get(k) for k in DIFFERENT) else 0


# --------------------------------------------------------------------------- apply


async def _apply(args) -> int:
    if args.report == "-":
        if not (args.yes or args.dry_run):
            raise CliError("Reading the report from stdin leaves no way to answer questions: add --yes or --dry-run.")
        text, source = sys.stdin.read(), "stdin"
    else:
        try:
            text, source = Path(args.report).read_text(), args.report
        except OSError as e:
            raise CliError(f"Can't read {args.report}: {e}") from e
    rep = report_mod.load(text, source)
    changes = report_mod.plan(rep)
    if not changes:
        print(f"Nothing to do: no actions are set in {source}. Set a key's or secret's action to "
              f"copy-to-right or copy-to-left first.")
        return 0
    if not (args.yes or args.dry_run) and not sys.stdin.isatty():
        raise CliError("Not running in a terminal, so I can't ask before writing: add --yes or --dry-run.")

    if args.audit_log:
        h = logging.FileHandler(args.audit_log)
        h.setFormatter(logging.Formatter("%(message)s"))
        log = logging.getLogger("lockstep.audit")
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False

    settings = cli_settings(args)
    defaults = {w: {"addr": getattr(rep, w).addr, "namespace": getattr(rep, w).namespace} for w in SIDES}
    targets = resolve_targets(args, defaults)
    for w in SIDES:
        if targets[w].addr != getattr(rep, w).addr.rstrip("/"):
            print(f"Note: the report's {w} side is {getattr(rep, w).addr}; using {targets[w].addr} as you asked.")
    lconn, rconn = await connect_both(targets, settings, {w: getattr(rep, w).name for w in SIDES})
    try:
        n = len(changes)
        print(f"{n} secret{'s' if n != 1 else ''} to update from {source}"
              f"{' (dry run: nothing will be written)' if args.dry_run else ''}.")
        outcome = await apply_mod.run(rep, changes, lconn, rconn, settings, yes=args.yes, dry_run=args.dry_run,
                                      show_values=args.show_values)
    finally:
        await asyncio.gather(revoke(lconn, settings), revoke(rconn, settings))
    print("\n" + apply_mod.summary(outcome, args.dry_run))
    return 0 if outcome.ok else 1


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "schema":
        from .. import exports
        schema = {"report": report_mod.schema, "export": exports.schema, "import-rules": exports.rules_schema}[args.kind]()
        print(json.dumps(schema, indent=2, ensure_ascii=False))
        return 0
    commands = {"compare": lambda: _compare(args), "apply": lambda: _apply(args),
                "export": lambda: transfer.run_export(args, _load_profile), "import": lambda: transfer.run_import(args)}
    try:
        return asyncio.run(commands[args.command]())
    except CliError as e:
        print(f"lockstep: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nlockstep: interrupted; nothing more was written.", file=sys.stderr)
        return 130

