"""The environment matrix: one baseline (say prod) compared with several environments.

Each environment is compared with the baseline by the pairwise engine, under its own comparison
profile. The baseline is read once and shared by every pair. The result is a grid: a row per
secret (is it there?) and per key (does it match?), a column per environment, sorted so the odd
one out comes first: a key that differs in only one environment is the likeliest mistake.

An environment can carry **accepted drift**: a drift baseline (`lockstep baseline update`, the
drift check's base.json) for its pair. A difference listed there with the same status is marked
accepted: it's shown, but doesn't make the environment the odd one out. The baseline itself can be
an export file instead of a Vault (the caller passes a FileVault).

Like the pairwise comparison, nothing here returns a value.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from . import engine
from .diff import SecretDiff
from .rules import Rules
from .vault import VaultError

MAX_ENVIRONMENTS = 12
PAIR_CONCURRENCY = 3  # environments compared at once (each pair reads with its own concurrency)

# equal: the same as the baseline. absent: neither the baseline nor this environment has it.
# missing: the baseline has it and this environment doesn't. extra: the other way round.
# not_compared: couldn't tell (unreadable, a keystore without its password, the comparison failed).
Cell = Literal["equal", "different", "missing", "extra", "not_compared", "absent"]
DEVIATING = ("different", "missing", "extra")


class MatrixCell(BaseModel):
    status: Cell
    reason: str = ""  # a few words, never a value
    accepted: bool = False  # a deviation listed in this environment's accepted drift


class MatrixRow(BaseModel):
    path: str  # the baseline's form of the path, relative to its prefix
    key: str | None = None  # None: the secret itself (is it there?)
    cells: list[MatrixCell]  # one per environment, in order
    odd: int  # environments that differ from the baseline here (accepted drift aside)
    unknown: int  # environments where it couldn't be told
    known: int = 0  # environments that differ here as their accepted drift says


class MatrixEnv(BaseModel):
    name: str
    mount: str
    prefix: str
    kv_version: str = "2"
    secret_count: int = 0
    truncated: bool = False
    denied: list[str] = []
    error: str | None = None  # the comparison failed: every cell is not_compared
    counts: dict[str, int] = {}  # cells by status, over the rows shown and hidden; "known": accepted ones
    accepted: str | None = None  # the accepted drift file's name, when one was given
    accepted_unused: int = 0  # differences it lists that aren't there any more (resolved)
    accepted_signer: str | None = None  # who signed the accepted drift file, when it's signed and checked


class MatrixBaseline(BaseModel):
    kind: Literal["vault", "file"] = "vault"
    name: str
    mount: str
    prefix: str
    kv_version: str = "2"
    secret_count: int = 0
    truncated: bool = False
    denied: list[str] = []


class Matrix(BaseModel):
    baseline: MatrixBaseline
    environments: list[MatrixEnv]
    rows: list[MatrixRow]
    summary: dict[str, int]


@dataclass
class EnvInput:
    name: str
    client: object  # a VaultClient
    mount: str
    prefix: str  # "" or ending in "/"
    rules: Rules | None = None
    accepted: dict[tuple[str, str | None], str] | None = None  # accepted drift: (path, key) -> status
    accepted_name: str | None = None
    accepted_signer: str | None = None  # who signed the accepted drift (checked)


KEY_CELL = {"equal": "equal", "different": "different", "left_only": "missing", "right_only": "extra",
            "not_compared": "not_compared", "unknown": "not_compared"}


def _cells_of(d: SecretDiff) -> tuple[MatrixCell, dict[str, MatrixCell]]:
    """One pair's secret: the secret's cell, and a cell per key."""
    if d.status in ("no_access", "error"):
        why = d.note or d.left.error or d.right.error or ("can't be read" if d.status == "no_access" else "error")
        side = "the baseline" if d.left.state in ("no_access", "error") else "this environment"
        cell = MatrixCell(status="not_compared", reason=f"{side}: {why}" if d.status == "error" else f"{side} can't be read")
        return cell, {k.key: MatrixCell(status="not_compared", reason=cell.reason) for k in d.keys}
    if d.status == "left_only":
        why = "deleted here" if d.right.state == "deleted" else ""
        return MatrixCell(status="missing", reason=why), {}
    if d.status == "right_only":
        why = "deleted in the baseline" if d.left.state == "deleted" else ""
        return MatrixCell(status="extra", reason=why), {}
    if d.left.state != "present":  # neither side has it (both deleted)
        return MatrixCell(status="absent"), {}
    keys = {}
    for k in d.keys:
        if k.ignored:
            keys[k.key] = MatrixCell(status="equal", reason="ignored by the profile")
        else:
            reason = k.reason if k.status != "equal" or k.rewritten else ""
            keys[k.key] = MatrixCell(status=KEY_CELL[k.status], reason=reason)
    return MatrixCell(status="equal"), keys


def _accept(d: SecretDiff, cell: MatrixCell, keys: dict[str, MatrixCell],
            accepted: dict[tuple[str, str | None], str]) -> set[tuple[str, str | None]]:
    """Mark the cells that this environment's accepted drift lists with the same status. Returns
    the findings used (the rest of the file is resolved drift)."""
    used = set()
    if cell.status in ("missing", "extra") and accepted.get((d.path, None)) == d.status:
        cell.accepted = True
        used.add((d.path, None))
    for k in d.keys:
        kc = keys.get(k.key)
        if kc is not None and kc.status in DEVIATING and accepted.get((d.path, k.key)) == k.status:
            kc.accepted = True
            used.add((d.path, k.key))
    return used


def _rank(row: MatrixRow, compared: int) -> tuple:
    if row.odd == 0:
        return (3, 0) if row.unknown else (4, 0)  # only unknowns, then only accepted drift
    if row.odd == 1 and compared > 1:
        return (0, 1)  # the odd one out
    if row.odd < compared:
        return (1, row.odd)
    return (2, row.odd)  # every environment differs: often on purpose (a per-environment value)


def build(baseline: MatrixBaseline, envs: list[MatrixEnv], results: list[list[SecretDiff] | None],
          include_equal: bool = False,
          accepted: list[dict[tuple[str, str | None], str] | None] | None = None) -> Matrix:
    """The grid from each environment's pairwise result (None: that comparison failed), with each
    environment's accepted drift, if any ((path, key) -> status)."""
    n = len(envs)
    secret_cells: dict[str, list[MatrixCell | None]] = {}
    key_cells: dict[tuple[str, str], list[MatrixCell | None]] = {}
    for i, diffs in enumerate(results):
        acc = accepted[i] if accepted else None
        used: set[tuple[str, str | None]] = set()
        for d in diffs or []:
            path = d.left_path or d.path
            cell, keys = _cells_of(d)
            if acc:
                used |= _accept(d, cell, keys, acc)
            secret_cells.setdefault(path, [None] * n)[i] = cell
            for k, kc in keys.items():
                key_cells.setdefault((path, k), [None] * n)[i] = kc
        if acc is not None and diffs is not None:
            envs[i].accepted_unused = len(set(acc) - used)

    def fill(cells: list[MatrixCell | None], key: str | None, path: str) -> list[MatrixCell]:
        out = []
        for i, c in enumerate(cells):
            if envs[i].error is not None:
                out.append(MatrixCell(status="not_compared", reason="the comparison failed"))
            elif c is not None:
                out.append(c)
            elif key is None:
                out.append(MatrixCell(status="absent"))
            else:  # the secret isn't on both sides here, so its keys weren't compared
                sc = secret_cells[path][i]
                out.append(MatrixCell(status="absent" if sc is None or sc.status != "not_compared" else "not_compared",
                                      reason=sc.reason if sc is not None and sc.status == "not_compared" else ""))
        return out

    rows: list[MatrixRow] = []
    for path, cells in secret_cells.items():
        rows.append(_row(path, None, fill(cells, None, path)))
    for (path, key), cells in key_cells.items():
        rows.append(_row(path, key, fill(cells, key, path)))

    for i, e in enumerate(envs):
        counts = dict.fromkeys(("equal", "different", "missing", "extra", "not_compared", "known"), 0)
        for r in rows:
            c = r.cells[i]
            if c.accepted:
                counts["known"] += 1
            elif c.status != "absent":
                counts[c.status] += 1
        e.counts = counts

    compared = sum(e.error is None for e in envs)
    rows.sort(key=lambda r: (_rank(r, compared), r.path, r.key is not None, r.key or ""))
    summary = {
        "environments": n, "failed": n - compared, "rows": len(rows),
        "odd_one_out": sum(1 for r in rows if _rank(r, compared)[0] == 0),
        "differing_rows": sum(1 for r in rows if r.odd),
        "unknown_rows": sum(1 for r in rows if r.unknown and not r.odd),
        "known_rows": sum(1 for r in rows if r.known and not r.odd and not r.unknown),
    }
    if not include_equal:
        rows = [r for r in rows if r.odd or r.unknown or r.known]
    return Matrix(baseline=baseline, environments=envs, rows=rows, summary=summary)


def _row(path: str, key: str | None, cells: list[MatrixCell]) -> MatrixRow:
    return MatrixRow(path=path, key=key, cells=cells,
                     odd=sum(c.status in DEVIATING and not c.accepted for c in cells),
                     known=sum(c.status in DEVIATING and c.accepted for c in cells),
                     unknown=sum(c.status == "not_compared" and c.reason != "the comparison failed" for c in cells))


async def run(baseline_name: str, base_client, base_mount: str, base_prefix: str, envs: list[EnvInput],
              max_secrets: int = 5000, include_equal: bool = False, base_kind: str = "vault") -> Matrix:
    """Compare the baseline with each environment and build the grid. The baseline is read once
    for every pair. Raises VaultError only when the baseline itself can't be listed; a failing
    environment is reported in its column."""
    base = engine.ReadOnce(base_client)
    try:
        tree = await base.kv_tree(base_mount, base_prefix, max_secrets=max_secrets)
        version = await _kv_version(base_client, base_mount)
        sem = asyncio.Semaphore(PAIR_CONCURRENCY)

        async def one(e: EnvInput):
            async with sem:
                try:
                    c = await engine.compare(base, base_mount, base_prefix, e.client, e.mount, e.prefix, e.rules,
                                             max_secrets=max_secrets)
                    return c, await _kv_version(e.client, e.mount), None
                except VaultError as err:
                    return None, "2", err.message

        outcomes = await asyncio.gather(*(one(e) for e in envs))
    finally:
        base.clear()

    baseline = MatrixBaseline(kind=base_kind, name=baseline_name, mount=base_mount, prefix=base_prefix.rstrip("/"), kv_version=version,
                              secret_count=len(tree.secrets), truncated=tree.truncated,
                              denied=[d[len(base_prefix):] for d in tree.denied])
    menvs, results = [], []
    for e, (c, ver, err) in zip(envs, outcomes):
        me = MatrixEnv(name=e.name, mount=e.mount, prefix=e.prefix.rstrip("/"), kv_version=ver, error=err,
                       accepted=e.accepted_name if e.accepted is not None else None,
                       accepted_signer=e.accepted_signer if e.accepted is not None else None)
        if c is not None:
            me.secret_count, me.truncated = len(c.right_tree.secrets), c.right_tree.truncated
            me.denied = [d[len(e.prefix):] for d in c.right_tree.denied]
        menvs.append(me)
        results.append(c.secrets if c is not None else None)
    return build(baseline, menvs, results, include_equal, [e.accepted for e in envs])


async def _kv_version(client, mount: str) -> str:
    f = getattr(client, "kv_version", None)
    return await f(mount) if f else "2"


SYMBOL = {"equal": "=", "different": "≠", "missing": "missing", "extra": "extra", "not_compared": "?", "absent": "·"}
