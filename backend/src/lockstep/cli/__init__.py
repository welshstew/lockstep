"""Lockstep on the command line: compare two KV v2 locations into a report, then apply it.

  lockstep compare --left-addr https://vault-a --right-addr https://vault-b --mount app-config -o report.yaml
  (edit the actions in report.yaml)
  lockstep apply report.yaml

  lockstep export --vault-addr https://vault-a --mount app-config -o export.json   (prints a one-time key)
  lockstep import export.json --vault-addr https://vault-b --mount app-config --replace app-dev=app-test

  lockstep matrix environments.yaml   (one baseline against several environments, odd one out first)

  lockstep policy explain my-policy --vault-addr https://vault-a --mount app-config   (read-only)

Exit codes, like diff(1): compare 0 = no differences, 1 = differences, 2 = couldn't compare.
apply/import 0 = done, 1 = some secrets were skipped (changed since the report or preview, or not
writable), 2 = couldn't run (bad file, login failed, ...).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..rules import Profile, Rules
from ..vault import VaultError
from . import apply as apply_mod
from . import drift as drift_mod
from . import formats
from . import matrix as matrix_mod
from . import pushgateway
from . import report as report_mod
from . import policy as policy_mod
from . import vaultconfig as config_mod
from . import transfer
from .connect import (CliError, SIDES, add_side_args, add_tls_args, cli_settings, connect_both, default_name,
                      resolve_targets, revoke)

DIFFERENT = ("different", "left_only", "right_only", "not_compared")  # what makes compare exit 1
LABEL = {"different": "different", "left_only": "left only", "right_only": "right only",
         "not_compared": "not compared", "no_access": "no access", "error": "error", "equal": "equal"}


def _version() -> str:
    try:
        return version("lockstep")
    except PackageNotFoundError:
        return "unknown"


def _compare_args(c: argparse.ArgumentParser) -> None:
    c.add_argument("--mount", help="KV v2 mount on both sides (or --left-mount / --right-mount)")
    c.add_argument("--prefix", default=None, help="only compare under this path on both sides")
    c.add_argument("--profile", metavar="FILE|NAME",
                   help="comparison profile: a YAML/JSON file (a profile, or just its rules) or a name "
                        "from $LOCKSTEP_PROFILES")
    c.add_argument("--profile-name", metavar="NAME", help="which profile, when the --profile file holds several")
    c.add_argument("--custom-metadata", action="store_true",
                   help="also compare each secret's custom metadata (a difference makes the secret differ)")
    for which in SIDES:
        add_side_args(c, which, locations=True)
    add_tls_args(c)


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
                                   "command, and an action per key to fill in for `lockstep apply`. With "
                                   "--baseline, only drift the baseline doesn't have fails the run.")
    _compare_args(c)
    c.add_argument("-o", "--output", metavar="FILE", action="append",
                   help="write the report here ('-' for stdout). Repeat it for several formats; the format "
                        "follows the extension: .yaml, .json, .sarif, .xml (JUnit), .md, .csv, .prom")
    c.add_argument("--format", choices=formats.FORMATS,
                   help="the format of every -o, instead of following the extension")
    c.add_argument("--include-equal", action="store_true", help="list equal secrets in the report too")
    g = c.add_argument_group("drift checks")
    g.add_argument("--baseline", metavar="FILE",
                   help="accepted drift from an earlier run (`lockstep baseline update` writes it, or give a report)")
    g.add_argument("--fail-on", choices=("any", "new", "changed"),
                   help="which drift exits 1: any (the default without --baseline), new (not in the baseline; "
                        "the default with it) or changed (new, or in the baseline but resolved)")
    g.add_argument("--waivers", metavar="FILE",
                   help="accepted differences, each with path, key, owner, reason and expires; an expired one fails the run")
    g.add_argument("--require-signed", action="store_true",
                   help="refuse a baseline or waivers file that isn't signed by a key in $LOCKSTEP_PLAN_TRUSTED_KEYS "
                        "(a signed one is always checked when trusted keys are set)")
    g.add_argument("--pushgateway", metavar="URL",
                   help="push the drift gauges to this Prometheus Pushgateway (default: $LOCKSTEP_PUSHGATEWAY_URL)")
    g.add_argument("--pushgateway-job", metavar="NAME", default="lockstep", help="the Pushgateway job (default: lockstep)")
    c.add_argument("-q", "--quiet", action="store_true", help="don't print the summary")

    b = sub.add_parser("baseline", help="write the baseline a drift check compares with",
                       description="Compare two locations, like `lockstep compare`, and write what differs "
                                   "(statuses only, never values) as the baseline for `compare --baseline`. "
                                   "Check it into Git: the change shows which drift was accepted.")
    bsub = b.add_subparsers(dest="baseline_command", required=True, metavar="ACTION")
    bu = bsub.add_parser("update", help="write a fresh baseline from a comparison now",
                         description="Compare two locations and write what differs as the baseline.")
    bu.add_argument("file", help="the baseline file to write (JSON)")
    _compare_args(bu)
    bu.add_argument("--sign", action="store_true",
                    help="sign it with the plan key ($LOCKSTEP_PLAN_SIGNING_KEY), so an edit to it is caught")
    bu.add_argument("-q", "--quiet", action="store_true", help="don't print the summary")
    bs = bsub.add_parser("sign", help="sign an existing baseline with the plan key",
                         description="Sign a baseline file with the plan key ($LOCKSTEP_PLAN_SIGNING_KEY), for example "
                                     "once a change to it has been reviewed. `compare --baseline` then refuses it if "
                                     "it's edited, wherever $LOCKSTEP_PLAN_TRUSTED_KEYS has the public key.")
    bs.add_argument("file", help="the baseline file (JSON)")

    w = sub.add_parser("waivers", help="sign a waivers file", description="Waivers files for compare --waivers.")
    wsub = w.add_subparsers(dest="waivers_command", required=True, metavar="ACTION")
    ws = wsub.add_parser("sign", help="sign a waivers file with the plan key",
                         description="Check a waivers file and sign it with the plan key ($LOCKSTEP_PLAN_SIGNING_KEY). "
                                     "The signature goes at the end; comments and layout stay. Changing a waiver "
                                     "afterwards breaks it, so `compare --waivers` refuses the file until it's signed again.")
    ws.add_argument("file", help="the waivers file (YAML)")

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

    matrix_mod.add_parser(sub)
    transfer.add_parsers(sub)
    policy_mod.add_parsers(sub)
    config_mod.add_parsers(sub)

    sub.add_parser("plan-key", help="make a key pair for signing plans that travel between installations",
                   description="Print a new Ed25519 key pair for plan signing: set LOCKSTEP_PLAN_SIGNING_KEY on the "
                               "installation that makes plans, and add the public key to LOCKSTEP_PLAN_TRUSTED_KEYS on "
                               "the ones that apply them. The private key is printed once; keep it in a secret store.")

    s = sub.add_parser("schema", help="print a JSON Schema (report, export, import rules or policy profile)",
                       description=f"Print the JSON Schema of a Lockstep file. report (the default, also at "
                                   f"{report_mod.SCHEMA_URL}): editors use it to complete and check `action:` values.")
    s.add_argument("kind", nargs="?", choices=("report", "export", "import-rules", "policy-profile", "suggest-pattern"), default="report")
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
    if rep.rewrites:
        print("Rewrites: " + ", ".join(f"{r.left} ⇄ {r.right}" for r in rep.rewrites), file=out)
    rows = [s for s in rep.secrets if s.status != "equal"]
    if rows:
        width = max(len(s.path) for s in rows)
        print(file=out)
        for s in rows:
            detail = ", ".join(k.key + (f" at {', '.join(k.paths[:3])}{' …' if len(k.paths) > 3 else ''}" if k.paths else "")
                               + (" (type)" if k.type_differs else "") + (" (ignored)" if k.ignored else "")
                               + (" (not compared)" if k.status == "not_compared" else "")
                               for k in s.keys if k.status in ("different", "not_compared"))
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
                                                           "not_compared", "no_access", "error") if sm.get(k))
    print(f"\n{sm.get('total', 0)} secrets: {counts or 'none found'}.", file=out)
    if sm.get("rewritten_keys"):
        print(f"{sm['rewritten_keys']} key{'s' if sm['rewritten_keys'] != 1 else ''} equal once the profile's rewrites "
              f"are applied.", file=out)


async def _run_compare(args, include_equal: bool = False,
                       sides_out: dict | None = None) -> report_mod.Report:
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
    if sides_out is not None:
        sides_out.update(sides)

    from ..api.connections import client_for
    from ..engine import compare

    lconn, rconn = await connect_both(targets, settings, {w: sides[w].name for w in SIDES})
    try:
        sides["left"].identity, sides["right"].identity = lconn.display_name, rconn.display_name
        async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
            try:
                result = await compare(lv, sides["left"].mount, report_mod._prefix(sides["left"].prefix),
                                       rv, sides["right"].mount, report_mod._prefix(sides["right"].prefix),
                                       rules, max_secrets=settings.max_tree_secrets,
                                       custom_metadata=args.custom_metadata)
            except VaultError as e:
                raise CliError(f"Comparison failed: {e}") from e
    finally:
        await asyncio.gather(revoke(lconn, settings), revoke(rconn, settings))

    return report_mod.build(result, sides["left"], sides["right"], profile.name if profile else None,
                            include_equal=include_equal, rewrites=rules.rewrites if rules else None)


def _drift_inputs(args):
    if args.fail_on in ("new", "changed") and not args.baseline:
        raise CliError(f"--fail-on {args.fail_on} needs --baseline: without one, every difference is new.")
    if args.require_signed and not (args.baseline or args.waivers):
        raise CliError("--require-signed checks the --baseline and --waivers files: give at least one.")
    baseline = drift_mod.load_baseline(args.baseline) if args.baseline else None
    wfile = drift_mod.load_waivers_file(args.waivers) if args.waivers else None
    notes: list[str] = []
    if baseline or wfile:
        keys = drift_mod.cli_keys(cli_settings(args))
        if baseline:
            notes.append(drift_mod.check_signed("baseline", baseline.body(), baseline.issuer, baseline.signature, keys,
                                                args.baseline, args.require_signed))
        if wfile:
            notes.append(drift_mod.check_signed("waivers", wfile.body(), wfile.issuer, wfile.signature, keys,
                                                args.waivers, args.require_signed))
    outputs = args.output or []
    if outputs.count("-") > 1:
        raise CliError("Only one -o can be '-' (stdout).")
    return baseline, wfile.waivers if wfile else None, outputs, [n for n in notes if n]


async def _compare(args) -> int:
    baseline, waivers, outputs, signed = _drift_inputs(args)  # bad or tampered files fail before logging in
    gateway = args.pushgateway or os.environ.get("LOCKSTEP_PUSHGATEWAY_URL")
    started = time.perf_counter()
    sides: dict[str, report_mod.ReportSide] = {}
    try:
        rep = await _run_compare(args, include_equal=args.include_equal, sides_out=sides)
        if baseline:
            drift_mod.check_matches(baseline, rep, args.baseline)
    except CliError:
        if gateway and sides:  # tell the Pushgateway this check couldn't run; keep its last counts
            try:
                pushgateway.push(gateway, args.pushgateway_job, formats.metric_labels(sides["left"], sides["right"]),
                                 formats.prometheus_failure(time.perf_counter() - started), replace=False)
            except CliError as e:
                print(f"lockstep: {e}", file=sys.stderr)
        raise
    seconds = time.perf_counter() - started
    fail_on = args.fail_on or ("new" if baseline else "any")
    outcome = drift_mod.check(rep, fail_on, baseline, args.baseline, waivers)
    if baseline or waivers:
        drift_mod.annotate(rep, outcome)
    to_stdout = "-" in outputs
    out = sys.stderr if to_stdout else sys.stdout
    if not args.quiet:
        _print_summary(rep, out)
        for line in [*signed, *drift_mod.summary_lines(outcome)]:
            print(line, file=out)
    written = []
    for target in outputs:
        fmt = formats.format_for(target, args.format)
        text = formats.render(rep, outcome, fmt, target, seconds)
        if target == "-":
            sys.stdout.write(text)
        else:
            Path(target).write_text(text)
            written.append((target, fmt))
    if not args.quiet:
        for target, fmt in written:
            hint = f" Set actions in it, then run: lockstep apply {target}" if fmt in ("yaml", "json") else ""
            print(f"Report written to {target}.{hint}", file=out)
        if not outputs and any(s.status in DIFFERENT for s in rep.secrets):
            print("Add -o report.yaml to write a report you can act on with `lockstep apply`.")
    if gateway:
        pushgateway.push(gateway, args.pushgateway_job, formats.metric_labels(rep.left, rep.right),
                         formats.prometheus(rep, outcome, seconds, labels=False))
        if not args.quiet:
            print(f"Metrics pushed to the Pushgateway (job {args.pushgateway_job}).", file=out)
    return 1 if outcome.failed else 0


def _env_keys():
    """The plan keys from the environment, for commands that don't talk to Vault."""
    import secrets as _secrets
    from ..config import Settings
    return drift_mod.cli_keys(Settings(session_key=_secrets.token_hex(32)))


async def _baseline(args) -> int:
    if args.baseline_command == "sign":
        b = drift_mod.load_baseline(args.file)
        Path(args.file).write_text(drift_mod.dump_baseline(drift_mod.sign_baseline(b, _env_keys())))
        print(f"Signed {args.file} as {b.issuer.name} (key {b.issuer.key_id}): {len(b.drift)} accepted difference"
              f"{'s' if len(b.drift) != 1 else ''}.")
        return 0
    keys = _env_keys() if args.sign else None  # a missing key fails before comparing
    if keys and not keys.private:
        raise CliError("--sign needs the plan signing key in LOCKSTEP_PLAN_SIGNING_KEY (`lockstep plan-key` makes a key pair).")
    rep = await _run_compare(args)
    b = drift_mod.baseline_of(rep)
    if keys:
        drift_mod.sign_baseline(b, keys)
    Path(args.file).write_text(drift_mod.dump_baseline(b))
    if not args.quiet:
        _print_summary(rep, sys.stdout)
        n = len(b.drift)
        signed = f", signed as {b.issuer.name}" if b.issuer else ""
        print(f"Baseline written to {args.file}{signed}: {n} difference{'s' if n != 1 else ''} accepted. "
              f"Check it with: lockstep compare … --baseline {args.file}")
    return 0


async def _waivers(args) -> int:
    path = args.file
    wfile = drift_mod.load_waivers_file(path)  # refuses a file with mistakes
    keys = _env_keys()
    try:
        from .. import driftsign
        issuer, signature = driftsign.sign("waivers", wfile.body(), keys)
    except driftsign.SignatureProblem as e:
        raise CliError(str(e)) from e
    Path(path).write_text(drift_mod.signed_waivers_text(Path(path).read_text(), issuer, signature))
    again = drift_mod.load_waivers_file(path)
    drift_mod.check_signed("waivers", again.body(), again.issuer, again.signature, keys, path, True)  # it reads back
    print(f"Signed {path} as {issuer.name} (key {issuer.key_id}): {len(wfile.waivers)} waiver"
          f"{'s' if len(wfile.waivers) != 1 else ''}.")
    return 0


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
    if args.command == "plan-key":
        from ..plansign import generate
        private, public = generate()
        print(f"LOCKSTEP_PLAN_SIGNING_KEY={private}")
        print(f'LOCKSTEP_PLAN_TRUSTED_KEYS=[{{"name": "<this installation>", "key": "{public}"}}]')
        print("\nThe first line is secret: set it on the installation that makes plans. The second goes on the "
              "installations that apply them, with the name this one signs as (LOCKSTEP_PLAN_ISSUER).", file=sys.stderr)
        return 0
    if args.command == "schema":
        from .. import exports
        from ..policy.compare import profile_schema
        from ..policy.suggest import pattern_schema
        schema = {"report": report_mod.schema, "export": exports.schema, "import-rules": exports.rules_schema,
                  "policy-profile": profile_schema, "suggest-pattern": pattern_schema}[args.kind]()
        print(json.dumps(schema, indent=2, ensure_ascii=False))
        return 0
    commands = {"compare": lambda: _compare(args), "baseline": lambda: _baseline(args), "apply": lambda: _apply(args),
                "waivers": lambda: _waivers(args),
                "matrix": lambda: matrix_mod.run(args),
                "export": lambda: transfer.run_export(args, _load_profile), "import": lambda: transfer.run_import(args),
                "policy": lambda: policy_mod.run(args), "config": lambda: config_mod.run(args)}
    try:
        return asyncio.run(commands[args.command]())
    except CliError as e:
        print(f"lockstep: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nlockstep: interrupted; nothing more was written.", file=sys.stderr)
        return 130

