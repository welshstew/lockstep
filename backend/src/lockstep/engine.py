"""Comparing two KV v2 locations: shared by the web API and the CLI.

Reads both sides, pairs the paths under a profile's rules and diffs each pair. Values are
read to compare them and dropped once each pair has been diffed; nothing returned here
holds a value.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .analyze.detect import badge
from .diff import SecretDiff, SideInfo, diff_secret, summarize
from .rules import Rules, pair_paths
from .vault import TreeResult, VaultClient, VaultError

READ_CONCURRENCY = 16


@dataclass
class Comparison:
    secrets: list[SecretDiff]
    left_tree: TreeResult
    right_tree: TreeResult
    summary: dict[str, int]


def _hidden(denied: list[str], full_path: str) -> bool:
    return any(full_path.startswith(d) for d in denied)


async def _read_side(v: VaultClient, sem: asyncio.Semaphore, mount: str, full_path: str,
                     listed: bool, tree: TreeResult) -> tuple[SideInfo, dict | None]:
    if not listed:
        if _hidden(tree.denied, full_path):
            return SideInfo(state="no_access"), None
        return SideInfo(state="absent"), None
    try:
        async with sem:
            s = await v.kv_read(mount, full_path)
    except VaultError as e:
        if e.denied:
            return SideInfo(state="no_access"), None
        return SideInfo(state="error", error=e.message), None
    return SideInfo(state=s.state, version=s.version, updated=s.updated), s.data


async def compare(lv: VaultClient, lmount: str, lprefix: str,
                  rv: VaultClient, rmount: str, rprefix: str,
                  rules: Rules | None = None, max_secrets: int = 5000) -> Comparison:
    """Compare lmount/lprefix on one Vault with rmount/rprefix on another (or the same).
    Prefixes are "" or end in "/". Listing errors other than "permission denied" raise
    VaultError; unreadable folders and secrets are reported per secret instead."""
    ltree, rtree = await asyncio.gather(lv.kv_tree(lmount, lprefix, max_secrets=max_secrets),
                                        rv.kv_tree(rmount, rprefix, max_secrets=max_secrets))
    lrel = {s[len(lprefix):] for s in ltree.secrets}
    rrel = {s[len(rprefix):] for s in rtree.secrets}
    rules = rules or Rules()
    pairs, collisions, ignored_paths = pair_paths(lrel, rrel, rules)
    lsem, rsem = asyncio.Semaphore(READ_CONCURRENCY), asyncio.Semaphore(READ_CONCURRENCY)

    async def one(key: str) -> SecretDiff:
        lp, rp = pairs[key]
        if key in collisions:
            none = SideInfo(state="error", error="mapping collision")
            d = diff_secret(key, none, None, none, None, left_path=lp, right_path=rp)
            d.note = (f"The mappings send several left paths here ({', '.join(collisions[key])}). "
                      f"Fix the profile so each target has one source.")
            return d
        (li, ld), (ri, rd) = await asyncio.gather(
            _read_side(lv, lsem, lmount, lprefix + lp, lp in lrel, ltree),
            _read_side(rv, rsem, rmount, rprefix + rp, rp in rrel, rtree))
        d = diff_secret(key, li, ld, ri, rd, ignored=lambda k: rules.key_ignored(k, lp, rp),
                        left_path=lp, right_path=rp)
        for name in (kd.key for kd in d.keys):
            lb = badge(ld[name]) if ld and name in ld else None
            rb = badge(rd[name]) if rd and name in rd else None
            if lb or rb:
                d.badges[name] = {"left": lb, "right": rb}
        return d  # values are dropped once this returns

    diffs = list(await asyncio.gather(*(one(k) for k in sorted(pairs))))
    totals = summarize(diffs)
    totals["ignored_paths"] = ignored_paths
    totals["ignored_keys"] = sum(d.ignored_keys for d in diffs)
    totals["mapped"] = sum(d.left_path != d.right_path for d in diffs)
    return Comparison(secrets=diffs, left_tree=ltree, right_tree=rtree, summary=totals)
