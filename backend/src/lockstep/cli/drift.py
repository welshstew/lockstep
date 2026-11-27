"""Drift checks for CI: a baseline of accepted drift, waivers, and which drift fails the run.

A **finding** is one thing that differs: a key (`billing/db` key `password`, different) or a whole
secret (`billing/queue`, left only). It's identified by its path and key, and carries its status.
A **baseline** is the findings of an earlier run, statuses only, never values. A run compares its
findings with the baseline:

- new: not in the baseline, or in it with another status;
- known: in the baseline with the same status;
- resolved: in the baseline but gone now;
- waived: a waiver in waivers.yaml accepts it (until the waiver expires).

`--fail-on any` fails on any finding (the default without a baseline), `new` on new ones (the
default with one), `changed` on new or resolved ones. An expired waiver always fails the run.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..rules import _glob
from . import report as report_mod
from .connect import CliError

BASELINE_FORMAT = 1
# The statuses that count as drift (and make `compare` exit 1), secret and key alike
DRIFT = ("different", "left_only", "right_only", "not_compared")
FailOn = Literal["any", "new", "changed"]
State = Literal["new", "known", "waived"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    key: str | None = None  # None: the whole secret (left only, right only, or nothing listed per key)
    status: str

    @property
    def id(self) -> tuple[str, str | None]:
        return self.path, self.key

    def label(self) -> str:
        return self.path + (f" key {self.key}" if self.key is not None else "")


class BaselineSide(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = ""
    mount: str
    prefix: str = ""


class Baseline(BaseModel):
    """Accepted drift: what differed when the baseline was written. Statuses only, never values."""

    model_config = ConfigDict(extra="ignore")
    lockstep_baseline: int = BASELINE_FORMAT
    created: str = ""
    left: BaselineSide
    right: BaselineSide
    profile: str | None = None
    drift: list[Finding] = []


class Waiver(BaseModel):
    """An accepted difference, with who accepted it, why, and until when."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, description="Secret path, as in the report; `*` and `**` globs work.")
    key: str | None = Field(default=None, description="One key; leave out to waive the whole secret.")
    owner: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    expires: dt.date

    def covers(self, f: Finding) -> bool:
        return bool(_glob(self.path).fullmatch(f.path)) and (self.key is None or self.key == f.key)

    def label(self) -> str:
        return self.path + (f" key {self.key}" if self.key else "")


@dataclass
class Outcome:
    """What a drift check found, for the summary, the report formats and the exit code."""

    fail_on: FailOn
    baseline: str | None = None
    states: dict[tuple[str, str | None], State] = field(default_factory=dict)
    new: list[Finding] = field(default_factory=list)
    known: list[Finding] = field(default_factory=list)
    waived: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    expired: list[Waiver] = field(default_factory=list)
    unused: list[Waiver] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        if self.expired:
            return True
        if self.fail_on == "any":
            return bool(self.new or self.known)
        if self.fail_on == "changed":
            return bool(self.new or self.resolved)
        return bool(self.new)

    waivers: list[Waiver] = field(default_factory=list)  # the ones in force

    def waivers_for(self, path: str, key: str | None) -> list[Waiver]:
        f = Finding(path=path, key=key, status="different")
        return [w for w in self.waivers if w.covers(f)]

    def state(self, path: str, key: str | None) -> State | None:
        return self.states.get((path, key))

    def fails(self, path: str, key: str | None) -> bool:
        """Whether this finding is one that fails the run."""
        state = self.state(path, key)
        return state == "new" or (state == "known" and self.fail_on == "any")


# --------------------------------------------------------------------------- findings


def pairs(rep: report_mod.Report) -> list[tuple[report_mod.ReportSecret, report_mod.ReportKey | None]]:
    """Everything that differs, as (secret, key): one per differing key, or the secret alone
    when it's on one side only or no key is named."""
    out = []
    for s in rep.secrets:
        if s.status not in DRIFT:
            continue
        keys = [k for k in s.keys if k.status in DRIFT and not k.ignored]
        if s.status in ("left_only", "right_only") or not keys:
            out.append((s, None))
        else:
            out += [(s, k) for k in keys]
    return out


def findings(rep: report_mod.Report) -> list[Finding]:
    out = [Finding(path=s.path, key=k.key if k else None, status=(k or s).status) for s, k in pairs(rep)]
    return sorted(out, key=lambda f: (f.path, f.key or ""))


# --------------------------------------------------------------------------- baseline


def baseline_of(rep: report_mod.Report) -> Baseline:
    side = lambda s: BaselineSide(name=s.name, mount=s.mount, prefix=s.prefix)  # noqa: E731
    return Baseline(created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), left=side(rep.left),
                    right=side(rep.right), profile=rep.profile, drift=findings(rep))


def dump_baseline(b: Baseline) -> str:
    """Stable, sorted JSON, so a baseline checked into Git diffs cleanly."""
    return json.dumps(b.model_dump(exclude_none=True), indent=2, ensure_ascii=False) + "\n"


def load_baseline(path: str) -> Baseline:
    p = Path(path)
    if not p.is_file():
        raise CliError(f"No baseline at {path}. Write one with: lockstep baseline update {path} "
                       f"(and the same options as compare).")
    try:
        raw = yaml.safe_load(p.read_text())  # JSON is YAML
    except yaml.YAMLError as e:
        raise CliError(f"{path} isn't valid JSON or YAML: {e}") from e
    if isinstance(raw, dict) and "lockstep_report" in raw:  # an earlier report works as a baseline too
        return baseline_of(report_mod.load(p.read_text(), path))
    if not isinstance(raw, dict) or "lockstep_baseline" not in raw:
        raise CliError(f"{path} isn't a Lockstep baseline or report.")
    if raw["lockstep_baseline"] != BASELINE_FORMAT:
        raise CliError(f"{path}: unsupported baseline format {raw['lockstep_baseline']} "
                       f"(this lockstep reads {BASELINE_FORMAT}).")
    try:
        return Baseline.model_validate(raw)
    except ValidationError as e:
        raise CliError(f"{path} isn't a valid baseline: {e}") from e


def check_matches(b: Baseline, rep: report_mod.Report, path: str) -> None:
    """A baseline of other mounts or prefixes would make everything new (or hide drift): refuse it."""
    for which in ("left", "right"):
        bs, rs = getattr(b, which), getattr(rep, which)
        if (bs.mount, bs.prefix) != (rs.mount, rs.prefix):
            raise CliError(f"The baseline {path} is for {which} {bs.mount}/{bs.prefix}".rstrip("/")
                           + f", but this run compares {rs.mount}/{rs.prefix}".rstrip("/")
                           + ". Use the baseline for these locations, or write a new one.")


# --------------------------------------------------------------------------- waivers


def load_waivers(path: str) -> list[Waiver]:
    p = Path(path)
    if not p.is_file():
        raise CliError(f"No waivers file at {path}.")
    try:
        raw = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        raise CliError(f"{path} isn't valid YAML: {e}") from e
    if isinstance(raw, dict):
        raw = raw.get("waivers")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise CliError(f"{path} should hold a list of waivers (or `waivers:` with one).")
    out, problems = [], []
    for i, w in enumerate(raw):
        try:
            out.append(Waiver.model_validate(w))
        except ValidationError as e:
            fields = ", ".join(".".join(map(str, err["loc"])) + f": {err['msg']}" for err in e.errors())
            problems.append(f"  waiver {i + 1}: {fields}")
    if problems:
        raise CliError(f"{path} has mistakes:\n" + "\n".join(problems))
    return out


# --------------------------------------------------------------------------- check


def check(rep: report_mod.Report, fail_on: FailOn, baseline: Baseline | None = None,
          baseline_path: str | None = None, waivers: list[Waiver] | None = None,
          today: dt.date | None = None) -> Outcome:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    now = findings(rep)
    before = {f.id: f for f in (baseline.drift if baseline else [])}
    active = [w for w in waivers or [] if w.expires >= today]
    used: set[int] = set()
    out = Outcome(fail_on=fail_on, baseline=baseline_path,
                  expired=[w for w in waivers or [] if w.expires < today], waivers=active)
    for f in now:
        hit = next((i for i, w in enumerate(active) if w.covers(f)), None)
        if hit is not None:
            used.add(hit)
            out.states[f.id] = "waived"
            out.waived.append(f)
        elif baseline is not None and f.id in before and before[f.id].status == f.status:
            out.states[f.id] = "known"
            out.known.append(f)
        else:  # without a baseline, everything that isn't waived is new
            out.states[f.id] = "new"
            out.new.append(f)
    ids = {f.id for f in now}
    out.resolved = [f for f in (baseline.drift if baseline else []) if f.id not in ids]
    out.unused = [w for i, w in enumerate(active) if i not in used]
    return out


def summary_lines(o: Outcome) -> list[str]:
    lines = []
    if o.baseline is not None or o.waived or o.expired:
        parts = [f"{len(o.new)} new"]
        if o.baseline is not None:
            parts.append(f"{len(o.known)} known (in the baseline)")
        if o.waived:
            parts.append(f"{len(o.waived)} waived")
        if o.baseline is not None:
            parts.append(f"{len(o.resolved)} resolved")
        lines.append("Drift: " + ", ".join(parts) + ".")
        for f in o.new:
            lines.append(f"  new       {f.label()}: {f.status.replace('_', ' ')}")
        for f in o.resolved:
            lines.append(f"  resolved  {f.label()}: was {f.status.replace('_', ' ')}")
    for w in o.expired:
        lines.append(f"Waiver for {w.label()} expired on {w.expires} (owner {w.owner}); renew or remove it.")
    for w in o.unused:
        lines.append(f"Waiver for {w.label()} matches nothing now; remove it if the difference is fixed.")
    return lines


def annotate(rep: report_mod.Report, o: Outcome) -> None:
    """Mark each finding in the report new, known or waived, and add the run's drift check."""
    for s, k in pairs(rep):
        (k or s).drift = o.state(s.path, k.key if k else None)
    rep.drift_check = report_mod.DriftCheck(
        fail_on=o.fail_on, baseline=o.baseline, failed=o.failed, new=len(o.new), known=len(o.known),
        waived=len(o.waived), resolved=[f.label() for f in o.resolved],
        expired_waivers=[w.label() for w in o.expired])
