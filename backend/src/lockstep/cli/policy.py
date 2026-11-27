"""`lockstep policy explain` and `lockstep policy compare`. Read-only: never values, never writes.

explain: what Vault policies allow on each secret of a KV v2 mount. Logs in with --vault-*.
  Exit codes: 0 = explained, 1 = a policy has errors Vault would refuse (or couldn't be read or
  parsed), 2 = couldn't run.
compare: every policy on two Vaults, compared by meaning. Logs in with --left-* / --right-*.
  Exit codes, like diff(1): 0 = the same, 1 = differences, 2 = couldn't compare.
suggest: policies suggested from a mount's layout (or a suggestion pattern). Logs in with --vault-*.
export: a bundle for an admin from policy files (HCL, apply.sh, optional Terraform/OpenTofu). Offline.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..api.connections import client_for
from ..api.policies import (ExplainError, PastedPolicy, SidePolicies, compare_sets, read_all, run_compare, run_explain,
                            run_suggest)
from ..policy.bundle import BundlePolicy, TerraformOptions, build_bundle
from ..policy.compare import PolicyProfile
from ..vault import VaultError
from .connect import (CliError, SIDES, add_side_args, add_tls_args, cli_settings, connect, connect_both, default_name,
                      revoke)

MARK = {True: "✓", False: "·"}


def add_parsers(sub) -> None:
    p = sub.add_parser("policy", help="explain Vault ACL policies on a KV v2 mount",
                       description="Work with Vault ACL policies. Read-only.")
    psub = p.add_subparsers(dest="policy_command", required=True, metavar="ACTION")
    e = psub.add_parser("explain", help="show what policies allow on each secret of a mount",
                        description="Show what a set of policies allows on every secret of a KV v2 mount, in plain "
                                    "columns (see names, read, write, delete, destroy, history), which rule decided "
                                    "each one, and mistakes or risky grants. Policies come from Vault by name, from "
                                    "HCL/JSON files, or from your own token (--self).")
    e.add_argument("names", nargs="*", metavar="NAME", help="policies to read from Vault")
    e.add_argument("--file", "-f", action="append", default=[], metavar="FILE", help="a policy file (HCL or JSON); repeatable")
    e.add_argument("--self", dest="me", action="store_true", help="your token's own policies")
    e.add_argument("--mount", required=True, help="KV v2 mount")
    e.add_argument("--prefix", default="", help="only secrets under this path")
    e.add_argument("--allowed-only", action="store_true", help="only list secrets where something is allowed")
    e.add_argument("--why", metavar="PATH", help="explain one secret in detail: the deciding rule for each column")
    e.add_argument("--json", action="store_true", help="print the full result as JSON")
    add_side_args(e, "vault", locations=False)
    add_tls_args(e)

    c = psub.add_parser("compare", help="compare every policy on two Vaults",
                        description="Compare the ACL policies of two Vaults by meaning: comments, whitespace, rule "
                                    "order and how capabilities are listed don't count. A policy profile pairs names "
                                    "that differ (*-dev with *-prod), rewrites the left policies' paths before "
                                    "comparing, and leaves policies out. Exit codes: 0 same, 1 differences, 2 error.")
    c.add_argument("--profile", metavar="FILE|NAME",
                   help="a policy profile: a YAML/JSON file (one profile, or a list with --profile-name), or a name "
                        "from $LOCKSTEP_POLICY_PROFILES")
    c.add_argument("--profile-name", metavar="NAME", help="which profile, when the file holds several")
    c.add_argument("--map", action="append", default=[], metavar="LEFT=RIGHT",
                   help="pair names, with * patterns (e.g. '*-dev=*-prod'); repeatable, added to the profile")
    c.add_argument("--rewrite", action="append", default=[], metavar="FIND=REPLACE",
                   help="rewrite the left policies' paths before comparing (e.g. /dev/=/prod/); repeatable")
    c.add_argument("--show-equal", action="store_true", help="list equal policies too")
    c.add_argument("--json", action="store_true", help="print the full result as JSON")
    for which in SIDES:
        add_side_args(c, which, locations=False)
    add_tls_args(c)

    d = psub.add_parser("diff", help="compare policy files in a directory with a Vault's policies",
                        description="Compare the HCL or JSON policy files in a directory (as kept in Git) with the "
                                    "live Vault's ACL policies, by meaning: a file's name without .hcl/.json is the "
                                    "policy name. Read-only. Exit codes: 0 same, 1 differences, 2 error.")
    d.add_argument("--dir", required=True, metavar="DIR", help="the directory of policy files (searched recursively)")
    d.add_argument("--files-only", action="store_true",
                   help="only compare policies that have a file; leave out the ones only in Vault")
    d.add_argument("--ignore", action="append", default=[], metavar="NAME",
                   help="leave out policies with this name (* patterns); repeatable. root is always left out")
    d.add_argument("--profile", metavar="FILE|NAME", help="a policy profile, as for `policy compare` (files are the left side)")
    d.add_argument("--profile-name", metavar="NAME", help="which profile, when the file holds several")
    d.add_argument("--map", action="append", default=[], metavar="FILE=VAULT",
                   help="pair a file's name with a Vault policy's, with * patterns; repeatable")
    d.add_argument("--rewrite", action="append", default=[], metavar="FIND=REPLACE",
                   help="rewrite the files' paths before comparing; repeatable")
    d.add_argument("--show-equal", action="store_true", help="list equal policies too")
    d.add_argument("--json", action="store_true", help="print the full result as JSON")
    add_side_args(d, "vault", locations=False)
    add_tls_args(d)

    s = psub.add_parser("suggest", help="suggest policies from how a mount's secrets are laid out",
                        description="Detect a layout such as <app>/<env>/... (or use --pattern) and suggest policies "
                                    "for it, as HCL. --bundle writes them as a zip for an admin.")
    s.add_argument("--mount", required=True, help="KV v2 mount")
    s.add_argument("--prefix", default="", help="only look under this path")
    s.add_argument("--pattern", metavar="FILE", help="a suggestion pattern (YAML or JSON); see `lockstep schema suggest-pattern`")
    s.add_argument("--only", action="append", default=[], metavar="NAME", help="keep only these suggestions; repeatable")
    s.add_argument("--profile-out", metavar="FILE", help="write the pattern's policy profile (for `policy compare`) here")
    s.add_argument("--json", action="store_true", help="print the full result as JSON")
    _bundle_args(s)
    add_side_args(s, "vault", locations=False)
    add_tls_args(s)

    x = psub.add_parser("export", help="bundle policy files for an admin: HCL, apply.sh, optional Terraform/OpenTofu",
                        description="Bundle policy files into a zip an admin can review and apply: policies/*.hcl, "
                                    "apply.sh (vault CLI, with --dry-run), and optionally Terraform or OpenTofu with "
                                    "the hashicorp/vault provider pinned. Each policy is named after its file. "
                                    "No Vault connection needed.")
    x.add_argument("files", nargs="+", metavar="FILE", help="policy files (HCL or JSON)")
    _bundle_args(x, required=True)


def _bundle_args(p, required: bool = False) -> None:
    p.add_argument("--bundle", metavar="ZIP", required=required, help="write a zip for an admin here")
    tool = p.add_mutually_exclusive_group()
    tool.add_argument("--terraform", action="store_const", dest="tf_tool", const="terraform", help="add Terraform files")
    tool.add_argument("--opentofu", action="store_const", dest="tf_tool", const="opentofu", help="add OpenTofu files")
    p.add_argument("--provider", default="~> 5.0", choices=("~> 5.0", "~> 4.0"), help="hashicorp/vault provider pin")
    p.add_argument("--tf-files", action="store_true", help="one .tf file per policy instead of one policies.tf")


def _write_bundle(args, policies: list[BundlePolicy], existing: list[str] | None = None, source: str = "") -> None:
    from .transfer import _ver
    tf = TerraformOptions(tool=args.tf_tool, provider=args.provider,
                          layout="files" if args.tf_files else "single") if args.tf_tool else None
    Path(args.bundle).write_bytes(build_bundle(policies, version=_ver(), terraform=tf, existing=existing, source=source))
    print(f"Wrote {len(policies)} polic{'y' if len(policies) == 1 else 'ies'} to {args.bundle}"
          f"{f' with {args.tf_tool} files' if tf else ''}. Unzip it and run ./apply.sh --dry-run.")


async def run(args) -> int:
    if args.policy_command == "compare":
        return await run_compare_cli(args)
    if args.policy_command == "diff":
        return await run_diff_cli(args)
    if args.policy_command == "suggest":
        return await run_suggest_cli(args)
    if args.policy_command == "export":
        return run_export_cli(args)
    if args.policy_command != "explain":
        raise CliError(f"unknown action {args.policy_command}")
    if not (args.names or args.file or args.me):
        raise CliError("name policies, give --file, or use --self")
    pasted = []
    for f in args.file:
        try:
            pasted.append(PastedPolicy(name=Path(f).stem, text=Path(f).read_text()))
        except OSError as e:
            raise CliError(f"can't read {f}: {e.strerror}") from e

    from .connect import resolve_targets
    settings = cli_settings(args)
    t = resolve_targets(args, sides=("vault",))["vault"]
    conn = await connect(t, settings, default_name(t.addr))
    try:
        async with client_for(conn, settings) as v:
            try:
                out = await run_explain(v, args.mount, args.prefix, names=args.names, pasted=pasted, token=args.me,
                                        max_secrets=settings.max_tree_secrets)
            except ExplainError as e:
                raise CliError(e.message) from e
            except VaultError as e:
                raise CliError(f"Vault: {e}") from e
    finally:
        await revoke(conn, settings)

    bad = any(f["level"] == "error" for f in out["findings"]) or any(s.error for s in out["policies"]
                                                                     if s.origin != "token")
    if args.json:
        out["policies"] = [s.model_dump() for s in out["policies"]]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        _print(out, args)
    return 1 if bad else 0


def _print(out: dict, args) -> None:
    for s in out["policies"]:
        print(f"  {s.name} ({s.origin}): " + (s.error if s.error else f"{s.rules} rule{'s' if s.rules != 1 else ''}"))
    if out["root"]:
        print("  root: everything is allowed")
    print(f"  {out.get('product') or 'Vault'} {out.get('vault_version') or '(version unknown)'}: evaluated as {out['evaluation']}")
    if out.get("evaluation_known") is False:
        print("  Couldn't tell which policy rules this server follows: a few answers about trailing slashes "
              "and wildcards may be wrong.")
    if out["mode"] == "vault":
        print("  Some of your token's policies can't be read, so the answers below come from Vault "
              "(sys/capabilities-self), without the deciding rules.")
    for m in out["missing"]:
        print(f"  Missing right: {m}")
    print()

    cols = out["columns"]
    rows = out["rows"]
    if args.allowed_only:
        rows = [r for r in rows if any(c["ok"] for c in r["cells"].values())]
    if args.why:
        _why(out, args.why)
    else:
        width = max([len("secret")] + [len(r["path"]) for r in rows])
        print(f"{'secret':<{width}}  " + "  ".join(c["label"] for c in cols))
        for r in rows:
            cells = "  ".join(f"{('✗' if r['cells'][c['id']]['deny'] else MARK[r['cells'][c['id']]['ok']]):^{len(c['label'])}}"
                              for c in cols)
            print(f"{r['path']:<{width}}  {cells}")
        print(f"\n{len(rows)} secret{'s' if len(rows) != 1 else ''}. ✓ allowed  · not allowed  ✗ denied by a deny rule"
              + ("  (listing was cut short)" if out["truncated"] else ""))
    if out["findings"]:
        print()
        for f in out["findings"]:
            where = f"{f['policy']}" + (f":{f['line']}" if f["line"] else "")
            print(f"{f['level']:>5}  {where}  {f['path'] or ''}: {f['message']}")


def _why(out: dict, path: str) -> None:
    row = next((r for r in out["rows"] if r["path"] == path.strip("/")), None)
    if row is None:
        raise CliError(f"{path} isn't among the secrets listed under {out['mount']}/{out['prefix']}")
    print(f"{out['mount']}/{row['path']}")
    for c in out["columns"]:
        cell = row["cells"][c["id"]]
        rule = out["rules"][cell["rule"]] if cell["rule"] is not None else None
        why = ("no rule matches" if rule is None and out["mode"] == "policies"
               else "from Vault" if rule is None
               else "; ".join(f'{s["policy"]}:{s["line"] or "?"} path "{s["path"]}" {s["capabilities"]}' for s in rule["sources"]))
        print(f"  {c['label']:<10} {'yes' if cell['ok'] else 'no ':<4} {why}")


# --------------------------------------------------------------------------- compare


def load_profile(args, settings) -> PolicyProfile | None:
    prof = None
    if args.profile:
        path = Path(args.profile).expanduser()
        if path.is_file():
            try:
                raw = yaml.safe_load(path.read_text())
            except yaml.YAMLError as e:
                raise CliError(f"{args.profile} isn't valid YAML or JSON: {e}") from e
            if isinstance(raw, dict) and "profiles" in raw:
                raw = raw["profiles"]
            if isinstance(raw, list):
                names = [p.get("name") for p in raw if isinstance(p, dict)]
                if args.profile_name in names:
                    raw = raw[names.index(args.profile_name)]
                elif len(raw) == 1 and not args.profile_name:
                    raw = raw[0]
                else:
                    raise CliError(f"{args.profile} holds {', '.join(map(str, names))}: pick one with --profile-name.")
            try:
                prof = PolicyProfile.model_validate({"name": path.stem, **(raw or {})})
            except (ValidationError, TypeError) as e:
                raise CliError(f"{args.profile} isn't a valid policy profile: {e}") from e
        else:
            prof = next((p for p in settings.policy_profiles if p.name == args.profile), None)
            if prof is None:
                raise CliError(f"No policy profile file or $LOCKSTEP_POLICY_PROFILES entry named {args.profile!r}.")
    if args.map or args.rewrite:
        prof = prof.model_copy(deep=True) if prof else PolicyProfile(name="command line")
        try:
            for m in args.map:
                left, _, right = m.partition("=")
                prof.mappings.append(PolicyProfile.model_validate({"name": "x", "mappings": [{"left": left, "right": right}]}).mappings[0])
            for r in args.rewrite:
                find, sep, replace = r.partition("=")
                if not sep or not find:
                    raise CliError(f"--rewrite needs FIND=REPLACE, got {r!r}")
                prof.rewrites.append(PolicyProfile.model_validate({"name": "x", "rewrites": [{"find": find, "replace": replace}]}).rewrites[0])
        except ValidationError as e:
            raise CliError(f"--map: {e.errors()[0]['msg']}") from e
    return prof


async def run_compare_cli(args) -> int:
    from .connect import resolve_targets
    settings = cli_settings(args)
    profile = load_profile(args, settings)
    targets = resolve_targets(args)
    lconn, rconn = await connect_both(targets, settings, {w: default_name(targets[w].addr) for w in SIDES})
    try:
        async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
            out = await run_compare(lv, rv, profile)
    except VaultError as e:
        raise CliError(f"Vault: {e}") from e
    finally:
        await asyncio.gather(revoke(lconn, settings), revoke(rconn, settings))

    for side in ("left", "right"):
        if out[side].error:
            raise CliError(f"{side}: {out[side].error}")
    return _report_pairs(out, args)


def _report_pairs(out: dict, args, label: dict[str, str] | None = None) -> int:
    if args.json:
        print(json.dumps({**out, "left": out["left"].model_dump(), "right": out["right"].model_dump(),
                          "pairs": [p.model_dump() for p in out["pairs"]]}, indent=2, ensure_ascii=False))
    else:
        label = label or {"equal": "equal", "different": "different", "left_only": "left only",
                          "right_only": "right only", "error": "error"}
        width = max(11, *(len(v) for v in label.values()))
        for p in out["pairs"]:
            if p.status == "equal" and not args.show_equal:
                continue
            name = p.left if p.left == p.right or not p.right else p.right if not p.left else f"{p.left} ⇄ {p.right}"
            extra = " (formatting differs)" if p.formatting else ""
            print(f"{label[p.status]:<{width}} {name}{extra}" + (f"  [{p.note}]" if p.note else ""))
            for r in p.rules:
                if r["change"] == "same":
                    continue
                caps = lambda c: "—" if c is None else "[" + ", ".join(c) + "]"  # noqa: E731
                print(f"{'':<{width + 3}}path \"{r['path']}\"  {caps(r['left'])} → {caps(r['right'])}")
        s = out["summary"]
        print(f"\n{sum(s.values())} policies: " + ", ".join(f"{n} {label[k]}" for k, n in s.items() if n) + ".")
        for m in out["missing"]:
            print(f"Missing right: {m}")
        for w in out.get("warnings", []):
            print(f"Warning: {w}")
    s = out["summary"]
    return 1 if s["different"] or s["left_only"] or s["right_only"] or s["error"] else 0


POLICY_SUFFIXES = (".hcl", ".json")
MAX_POLICY_FILE = 256 * 1024


def read_policy_dir(path: str) -> tuple[dict[str, str | None], dict[str, str], list[str]]:
    """{name: text} from the .hcl and .json files under a directory, the read errors, and warnings."""
    root = Path(path).expanduser()
    if not root.is_dir():
        raise CliError(f"{path} isn't a directory.")
    texts: dict[str, str | None] = {}
    errors: dict[str, str] = {}
    where: dict[str, Path] = {}
    warnings = []
    for f in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in POLICY_SUFFIXES):
        name = f.stem
        if name in where:
            raise CliError(f"Two files are policy {name!r}: {where[name].relative_to(root)} and {f.relative_to(root)}.")
        where[name] = f
        if f.stat().st_size > MAX_POLICY_FILE:
            texts[name], errors[name] = None, f"{f.relative_to(root)} is larger than 256 KB"
            continue
        try:
            texts[name] = f.read_text()
        except (OSError, UnicodeDecodeError) as e:
            texts[name], errors[name] = None, f"can't read {f.relative_to(root)}: {e}"
    if not texts:
        warnings.append(f"No .hcl or .json files under {path}.")
    return texts, errors, warnings


async def run_diff_cli(args) -> int:
    from .connect import resolve_targets
    settings = cli_settings(args)
    profile = load_profile(args, settings) or PolicyProfile(name="command line")
    profile = profile.model_copy(update={"ignore": [*profile.ignore, *args.ignore]})
    ftexts, ferrors, warnings = read_policy_dir(args.dir)
    t = resolve_targets(args, sides=("vault",))["vault"]
    conn = await connect(t, settings, default_name(t.addr))
    missing: list[str] = []
    try:
        async with client_for(conn, settings) as v:
            vault = await read_all(v, "right", missing)
    except VaultError as e:
        raise CliError(f"Vault: {e}") from e
    finally:
        await revoke(conn, settings)
    if vault[2].error:
        raise CliError(f"Vault: {vault[2].error}")
    out = compare_sets((ftexts, ferrors, SidePolicies(count=len(ftexts))), vault, profile, missing)
    if args.files_only:
        out["pairs"] = [p for p in out["pairs"] if p.status != "right_only"]
        out["summary"]["right_only"] = 0
    out["warnings"] = warnings
    label = {"equal": "equal", "different": "different", "left_only": "only in files",
             "right_only": "only in Vault", "error": "error"}
    rc = _report_pairs(out, args, label)
    return rc


# --------------------------------------------------------------------------- suggest, export


async def run_suggest_cli(args) -> int:
    from .connect import resolve_targets
    pattern = None
    if args.pattern:
        try:
            pattern = Path(args.pattern).read_text()
        except OSError as e:
            raise CliError(f"can't read {args.pattern}: {e.strerror}") from e
    settings = cli_settings(args)
    t = resolve_targets(args, sides=("vault",))["vault"]
    conn = await connect(t, settings, default_name(t.addr))
    try:
        async with client_for(conn, settings) as v:
            try:
                out = await run_suggest(v, args.mount, args.prefix, pattern, settings.max_tree_secrets)
            except ValueError as e:
                raise CliError(f"--pattern {e}") from e
            except VaultError as e:
                raise CliError(f"Vault: {e}") from e
            existing = None
            if args.bundle:
                try:
                    existing = await v.policy_names()
                except VaultError:
                    pass  # can't tell which exist: no import blocks
    finally:
        await revoke(conn, settings)
    sugg = [x for x in out["suggestions"] if not args.only or x.name in args.only]
    if args.json:
        print(json.dumps({**out, "suggestions": [x.model_dump() for x in sugg],
                          "profile": out["profile"].model_dump() if out["profile"] else None}, indent=2))
    else:
        print(f"Layout: {out['layout']}  ({out['secrets']} secrets)")
        for w in out["why"] + out["notes"]:
            print(f"  {w}")
        print()
        for x in sugg:
            print(f"--- {x.name}" + (f": {x.description}" if x.description else ""))
            print(x.hcl)
    if args.profile_out and out["profile"]:
        Path(args.profile_out).write_text(json.dumps(out["profile"].model_dump(), indent=2) + "\n")
        print(f"Policy profile written to {args.profile_out} (use it with `lockstep policy compare --profile`).")
    if args.bundle:
        _write_bundle(args, [BundlePolicy(name=x.name, text=x.hcl) for x in sugg], existing, conn.name)
    return 0


def run_export_cli(args) -> int:
    from ..policy.hcl import PolicyParseError, parse_policy
    policies = []
    for f in args.files:
        path = Path(f)
        try:
            text = path.read_text()
            parse_policy(text, path.stem)
            policies.append(BundlePolicy(name=path.stem, text=text))
        except OSError as e:
            raise CliError(f"can't read {f}: {e.strerror}") from e
        except PolicyParseError as e:
            raise CliError(f"{f} can't be parsed: {e}") from e
        except ValidationError as e:
            raise CliError(f"{f}: the file name isn't a valid policy name ({e.errors()[0]['msg']})") from e
    _write_bundle(args, policies)
    return 0
