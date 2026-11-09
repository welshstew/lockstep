"""`lockstep apply`: carry out a report's actions, asking before each key is written."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, TextIO

from ..api.compare import Side
from ..api.sync import Change, KeyPlan, _Ctx, apply_changes, evaluate
from ..config import Settings
from ..session import Connection
from .report import Report, ReportSecret

ARROW = {"left_to_right": "→", "right_to_left": "←"}
MAX_SHOWN = 300


@dataclass
class Outcome:
    applied: list[str] = field(default_factory=list)  # target descriptions
    keys_written: int = 0
    stale: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)  # denied, invalid, error
    unchanged: list[str] = field(default_factory=list)
    declined: int = 0  # keys the user said no to
    would_write: list[str] = field(default_factory=list)  # dry run
    quit: bool = False

    @property
    def ok(self) -> bool:
        return not (self.stale or self.failed)


class Asker:
    """Per-key confirmation: y(es), n(o), a(ll remaining), q(uit)."""

    def __init__(self, yes: bool, read: Callable[[str], str], out: TextIO):
        self.all = yes
        self.read = read
        self.out = out

    def ask(self, question: str) -> str:
        if self.all:
            return "y"
        while True:
            try:
                ans = self.read(f"{question} [y]es / [n]o / [a]ll / [q]uit: ").strip().lower()
            except EOFError:
                return "q"
            if ans in ("y", "yes", "n", "no", "a", "all", "q", "quit"):
                ans = ans[0]
                if ans == "a":
                    self.all = True
                    return "y"
                return ans
            print("  Please answer y, n, a or q.", file=self.out)


def _shown(v: Any, exact: bool = False) -> str:
    """A value for the terminal. `exact` shows JSON, so "5432" and 5432 look different."""
    s = v if isinstance(v, str) and not exact else json.dumps(v, ensure_ascii=False)
    s = s.replace("\n", "\\n")
    return s if len(s) <= MAX_SHOWN else s[:MAX_SHOWN] + f"… ({len(s)} characters)"


def _describe_key(k: KeyPlan, show_values: bool) -> list[str]:
    verb = {"add": "add   ", "update": "update"}[k.action]
    lines = [f"    {verb} {k.key}" + ("  (type changes)" if k.type_change else "")]
    if show_values:
        if k.action == "update":
            lines.append(f"             now: {_shown(k.target_value, k.type_change)}")
        lines.append(f"             new: {_shown(k.source_value, k.type_change)}")
    return lines


async def run(report: Report, changes: list[tuple[ReportSecret, Change]], lconn: Connection,
              rconn: Connection, settings: Settings, *, yes: bool, dry_run: bool, show_values: bool,
              out: TextIO | None = None, read: Callable[[str], str] = input) -> Outcome:
    out = out or sys.stdout
    result = Outcome()
    asker = Asker(yes or dry_run, read, out)
    left = Side(conn_id=lconn.id, mount=report.left.mount, prefix=report.left.prefix)
    right = Side(conn_id=rconn.id, mount=report.right.mount, prefix=report.right.prefix)

    def say(*lines: str) -> None:
        for line in lines:
            print(line, file=out)

    async with _Ctx.direct(lconn, rconn, left, right, settings) as ctx:
        for secret, change in changes:
            ev, _, _ = await evaluate(ctx, change, reveal=show_values)
            where = f"{ev.target.name} · {ev.target.mount}/{ev.target.path}"
            src = f"{ev.source.name} · {ev.source.mount}/{ev.source.path}"
            say("", f"{ARROW[change.direction]} {where}   from {src}")
            source_moved = (change.expected_source_version is not None and ev.source.state == "present"
                            and ev.source.version != change.expected_source_version)
            if ev.status == "conflict" or source_moved:
                which = "target" if ev.status == "conflict" else "source"
                was = change.expected_target_version if which == "target" else change.expected_source_version
                now = ev.target.version if which == "target" else ev.source.version
                say(f"  Skipped: the {which} changed since the report was made (v{was or '—'} → v{now or '—'}). "
                    f"Run lockstep compare again.")
                result.stale.append(where)
                continue
            if ev.status in ("denied", "invalid", "error"):
                say(f"  Skipped: {'; '.join(ev.problems) or ev.status}")
                result.failed.append(where)
                continue
            if ev.status == "noop":
                say("  Already the same: nothing to write.")
                result.unchanged.append(where)
                continue

            todo = [k for k in ev.keys if k.action != "unchanged"]
            new_version = f"v{ev.target.version} → v{(ev.target.version or 0) + 1}" if ev.target.version \
                else "new secret"
            say(f"  {len(todo)} key{'s' if len(todo) != 1 else ''} to write ({new_version}):")
            confirmed: list[str] = []
            for k in todo:
                say(*_describe_key(k, show_values))
                if dry_run:
                    confirmed.append(k.key)
                    continue
                ans = asker.ask(f"  Write {k.key}?")
                if ans == "q":
                    result.quit = True
                    break
                if ans == "y":
                    confirmed.append(k.key)
                else:
                    result.declined += 1
            if result.quit:
                say("  Stopped: nothing more was written.")
                break
            if not confirmed:
                continue
            if dry_run:
                result.would_write.append(where)
                continue
            done = (await apply_changes(ctx, [change.model_copy(update={"keys": confirmed})])).results[0]
            if done.status == "applied":
                say(f"  Written: v{done.new_version} ({len(done.keys)} key{'s' if len(done.keys) != 1 else ''}).")
                result.applied.append(where)
                result.keys_written += len(done.keys)
            elif done.status == "conflict":
                say(f"  Skipped: {done.message} Run lockstep compare again.")
                result.stale.append(where)
            elif done.status == "noop":
                result.unchanged.append(where)
            else:
                say(f"  Failed: {done.message or done.status}")
                result.failed.append(where)
    return result


def summary(o: Outcome, dry_run: bool) -> str:
    parts = []
    if dry_run:
        parts.append(f"Dry run: {len(o.would_write)} secret{'s' if len(o.would_write) != 1 else ''} would be written.")
    else:
        parts.append(f"Wrote {o.keys_written} key{'s' if o.keys_written != 1 else ''} to {len(o.applied)} "
                     f"secret{'s' if len(o.applied) != 1 else ''}.")
    if o.unchanged:
        parts.append(f"{len(o.unchanged)} already the same.")
    if o.declined:
        parts.append(f"{o.declined} key{'s' if o.declined != 1 else ''} declined.")
    if o.stale:
        parts.append(f"{len(o.stale)} skipped because they changed since the report: compare again.")
    if o.failed:
        parts.append(f"{len(o.failed)} couldn't be written.")
    if o.quit:
        parts.append("Stopped early.")
    return " ".join(parts)
