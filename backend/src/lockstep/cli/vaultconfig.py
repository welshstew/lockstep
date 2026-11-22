"""`lockstep config compare`: two Vaults' secrets engines and auth methods, compared.

Exit codes, like diff(1): 0 = the same, 1 = differences, 2 = couldn't compare.
"""

from __future__ import annotations

import asyncio
import json

from ..api.connections import client_for
from ..api.vaultconfig import run_compare
from ..vault import VaultError
from .connect import CliError, SIDES, add_side_args, add_tls_args, cli_settings, connect_both, default_name, revoke

LABEL = {"equal": "equal", "different": "different", "left_only": "left only", "right_only": "right only"}


def add_parsers(sub) -> None:
    p = sub.add_parser("config", help="compare two Vaults' configuration (secrets engines, auth methods)",
                       description="Vault configuration. Read-only.")
    psub = p.add_subparsers(dest="config_command", required=True, metavar="ACTION")
    c = psub.add_parser("compare", help="compare the secrets engines and auth methods of two Vaults",
                        description="Compare two Vaults' secrets engines and auth methods: type, plugin version, "
                                    "tuning (TTLs, listing visibility, audit settings), options, auth method "
                                    "configuration, and the roles and keys of engines both have (PKI, database, "
                                    "Transit, SSH, Kubernetes, AWS), with sensitive fields left out. Exit codes: 0 same, 1 differences, "
                                    "2 error.")
    c.add_argument("--include-system", action="store_true", help="also compare sys/, identity/, cubbyhole/ and token/")
    c.add_argument("--show-equal", action="store_true", help="list equal ones too")
    c.add_argument("--json", action="store_true", help="print the full result as JSON")
    for which in SIDES:
        add_side_args(c, which, locations=False)
    add_tls_args(c)


async def run(args) -> int:
    from .connect import resolve_targets
    settings = cli_settings(args)
    targets = resolve_targets(args)
    lconn, rconn = await connect_both(targets, settings, {w: default_name(targets[w].addr) for w in SIDES})
    try:
        async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
            out = await run_compare(lv, rv)
    except VaultError as e:
        raise CliError(f"Vault: {e}") from e
    finally:
        await asyncio.gather(revoke(lconn, settings), revoke(rconn, settings))
    rows = ([("secrets engine", p) for p in out["mounts"]] + [("auth method", p) for p in out["auth"]]
            + [({"keys": "key", "config": "connection"}.get(p["path"].rsplit("/", 2)[-2], "role"), p) for p in out["engines"]])
    rows = [(k, p) for k, p in rows if args.include_system or not p["system"]]
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        lo, ro = out["overview"]["left"], out["overview"]["right"]
        print(f"Vault {lo.get('version')} ⇄ Vault {ro.get('version')}" + ("  (versions differ)" if lo.get("version") != ro.get("version") else ""))
        for kind, p in rows:
            if p["status"] == "equal" and not args.show_equal:
                continue
            print(f"{LABEL[p['status']]:<11} {kind} {p['path']} ({p['type']})")
            for f in p["fields"]:
                print(f"              {f['field']}: {f['left'] if f['left'] is not None else '—'} → {f['right'] if f['right'] is not None else '—'}")
        counts = {s: sum(p["status"] == s for _, p in rows) for s in LABEL}
        print(f"\n{len(rows)} compared: " + ", ".join(f"{n} {LABEL[s]}" for s, n in counts.items() if n) + ".")
        for side in ("left", "right"):
            for m in out["missing"][side]:
                print(f"Missing right ({side}): {m}")
    return 1 if any(p["status"] != "equal" for _, p in rows) else 0
