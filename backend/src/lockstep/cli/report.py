"""The CLI's comparison report: a YAML file people read, edit and hand back to `lockstep apply`.

It never holds secret values. For each secret that differs it records both sides' versions,
a Vault UI link and a `vault kv get` command for looking at the values, and an `action`
for every key that differs. Set actions, then run `lockstep apply` on the file: it reads
the values fresh from the source and skips any secret that changed since the report.
"""

from __future__ import annotations

import re
import shlex
import time
from typing import Literal
from urllib.parse import quote

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..diff import SecretDiff
from ..engine import Comparison
from ..api.sync import Change, Direction
from .connect import CliError

FORMAT = 1
# JSON Schema for the report, so editors can complete and check `action:` values. Published
# at this URL by the website build (scripts/build_site.py); `lockstep schema` prints it.
SCHEMA_URL = "https://getlockstep.cloud/schemas/lockstep-report-v1.json"
KeyAction = Literal["skip", "copy-to-right", "copy-to-left"]
SecretAction = Literal["per-key", "skip", "copy-to-right", "copy-to-left"]
_KEY_ACTIONS = {
    "skip": "Leave this key alone (the default).",
    "copy-to-right": "Write the left side's value to the right side. The key must exist on the left.",
    "copy-to-left": "Write the right side's value to the left side. The key must exist on the right.",
}
_SECRET_ACTIONS = {
    "per-key": "Use the actions set on this secret's keys (the default).",
    "skip": "Leave the whole secret alone, whatever its keys say.",
    "copy-to-right": "Copy every key the left side has to the right side, including keys that are already equal.",
    "copy-to-left": "Copy every key the right side has to the left side, including keys that are already equal.",
}


def _enum_help(options: dict[str, str]) -> dict:
    """Per-value hover text for editors (VS Code / yaml-language-server)."""
    return {"enumDescriptions": list(options.values()),
            "markdownEnumDescriptions": [f"`{k}`: {v}" for k, v in options.items()]}
DIRECTION: dict[str, Direction] = {"copy-to-right": "left_to_right", "copy-to-left": "right_to_left"}
# A key can be copied from the side that has it
COPYABLE = {"copy-to-right": ("left_only", "different"), "copy-to-left": ("right_only", "different")}

HEADER = """\
# yaml-language-server: $schema={schema}
# Lockstep comparison report
#
# Lists every secret that differs between the two sides, without any values. To look at
# the values, open a secret's `ui` link or run its `cli` command (after `vault login`).
#
# To change things, set `action` and then run:   lockstep apply {file}
#   on a key:     skip | copy-to-right | copy-to-left
#   on a secret:  per-key (use the keys' actions) | skip | copy-to-right | copy-to-left (every key)
# copy-to-right writes the left side's value to the right side, and copy-to-left the reverse.
# Keys that exist only on the target are kept; nothing is deleted. `lockstep apply` asks
# before writing each key (unless you pass --yes), reads the values fresh from the source,
# and skips any secret that changed in Vault since this report was made.
"""


# --------------------------------------------------------------------------- model


class ReportSide(BaseModel):
    """One side of the comparison."""

    model_config = ConfigDict(extra="ignore")
    name: str = Field(description="Label for this side, used in messages.")
    addr: str = Field(description="Vault address. `lockstep apply` connects here unless you pass --left-addr/--right-addr.")
    namespace: str | None = Field(default=None, description="Vault Enterprise namespace.")
    mount: str = Field(min_length=1, description="KV v2 mount.")
    prefix: str = Field(default="", description="Path prefix that was compared (empty: the whole mount).")
    ui_addr: str | None = Field(default=None, description="Address of the Vault UI, if it differs from addr.")
    identity: str = Field(default="", description="Who compared this side (Vault's display name for the token).")


class SecretSide(BaseModel):
    """One side of a secret, as it was when the report was made."""

    model_config = ConfigDict(extra="ignore")
    path: str = Field(description="Full path within the mount (prefix included).")
    state: str = Field(description="present, absent, deleted, no_access or error.")
    version: int | None = Field(default=None, description="KV v2 version when compared. `apply` skips the secret if it has changed since.")
    updated: str | None = Field(default=None, description="When that version was written.")
    ui: str | None = Field(default=None, description="The secret in the Vault web UI.")
    cli: str | None = Field(default=None, description="Command to see its values with the vault CLI.")


class ReportKey(BaseModel):
    """A key that isn't equal on both sides."""

    model_config = ConfigDict(extra="forbid")  # catches typos such as `acton:`
    key: str = Field(description="Key name.")
    status: str = Field(description="different, left_only or right_only (unknown if a side couldn't be read).")
    type_differs: bool = Field(default=False, description='The values have different JSON types, e.g. 5432 vs "5432".')
    ignored: bool = Field(default=False, description="A profile rule says this difference doesn't count.")
    left_holds: str | None = Field(default=None, description="What the left value is (certificate, keystore...), without the value.")
    right_holds: str | None = Field(default=None, description="What the right value is, without the value.")
    action: KeyAction = Field(default="skip", description="What `lockstep apply` does with this key.",
                              json_schema_extra=_enum_help(_KEY_ACTIONS))


class ReportSecret(BaseModel):
    """A secret that differs (or every secret, with --include-equal)."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(description="The secret's path relative to the prefixes (the right side's form under a mapping).")
    status: str = Field(description="equal, different, left_only, right_only, no_access or error.")
    action: SecretAction = Field(default="per-key", description="What `lockstep apply` does with the whole secret.",
                                 json_schema_extra=_enum_help(_SECRET_ACTIONS))
    note: str | None = Field(default=None, description="Why the comparison couldn't be completed for this secret.")
    left: SecretSide
    right: SecretSide
    equal_keys: int = Field(default=0, description="How many keys are equal (not listed).")
    keys: list[ReportKey] = Field(default=[], description="Keys that differ, each with an action.")


class Report(BaseModel):
    """A Lockstep comparison report: what differs between two Vault KV v2 locations, never values.
    Set `action` on keys or secrets, then run `lockstep apply` on the file."""

    model_config = ConfigDict(extra="ignore", title="Lockstep comparison report")
    lockstep_report: int = Field(description=f"Report format version ({FORMAT}).",
                                 json_schema_extra={"const": FORMAT})
    created: str = Field(description="When the comparison ran (UTC).")
    left: ReportSide
    right: ReportSide
    profile: str | None = Field(default=None, description="Comparison profile used, if any.")
    summary: dict[str, int] = Field(default={}, description="Counts per status.")
    warnings: list[str] = Field(default=[], description="Folders that couldn't be listed, truncation.")
    secrets: list[ReportSecret] = Field(default=[], description="Secrets that differ.")

    @model_validator(mode="after")
    def _version(self):
        if self.lockstep_report != FORMAT:
            raise ValueError(f"unsupported report format {self.lockstep_report} (this lockstep reads {FORMAT})")
        return self


def schema() -> dict:
    """The report's JSON Schema (draft 2020-12), published at SCHEMA_URL."""
    out = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": SCHEMA_URL,
           **Report.model_json_schema()}
    return out


# --------------------------------------------------------------------------- links


def ui_url(base: str, namespace: str | None, mount: str, path: str) -> str:
    """The secret's page in the Vault web UI (Vault 1.15 and later)."""
    url = f"{base.rstrip('/')}/ui/vault/secrets/{quote(mount, safe='')}/kv/{quote(path, safe='')}/details"
    return url + (f"?namespace={quote(namespace, safe='')}" if namespace else "")


def cli_command(addr: str, namespace: str | None, mount: str, path: str) -> str:
    parts = ["vault", "kv", "get", f"-address={addr}"]
    if namespace:
        parts.append(f"-namespace={namespace}")
    parts += [f"-mount={mount}", path]
    return shlex.join(parts)


def _holds(b: dict | None) -> str | None:
    if not b:
        return None
    return b["label"] + (f", {b['detail']}" if b.get("detail") else "")


# --------------------------------------------------------------------------- build / write


def _prefix(p: str) -> str:
    p = p.strip("/")
    return f"{p}/" if p else ""


def build(result: Comparison, left: ReportSide, right: ReportSide, profile: str | None,
          include_equal: bool = False) -> Report:
    def side(s: ReportSide, rel: str, info) -> SecretSide:
        full = _prefix(s.prefix) + rel
        visible = info.state in ("present", "deleted")
        return SecretSide(path=full, state=info.state, version=info.version, updated=info.updated,
                          ui=ui_url(s.ui_addr or s.addr, s.namespace, s.mount, full) if visible else None,
                          cli=cli_command(s.addr, s.namespace, s.mount, full) if visible else None)

    def secret(d: SecretDiff) -> ReportSecret:
        keys = [ReportKey(key=k.key, status=k.status, type_differs=k.type_differs, ignored=k.ignored,
                          left_holds=_holds((d.badges.get(k.key) or {}).get("left")),
                          right_holds=_holds((d.badges.get(k.key) or {}).get("right")))
                for k in d.keys if k.status != "equal"]
        return ReportSecret(path=d.path, status=d.status, note=d.note or (d.left.error or d.right.error),
                            left=side(left, d.left_path, d.left), right=side(right, d.right_path, d.right),
                            equal_keys=sum(k.status == "equal" for k in d.keys), keys=keys)

    warnings = []
    for which, s, tree in (("left", left, result.left_tree), ("right", right, result.right_tree)):
        p = _prefix(s.prefix)
        if tree.denied:
            warnings.append(f"The {which} side can't list {', '.join(d[len(p):] or '/' for d in tree.denied)}, "
                            f"so secrets there are missing from this report.")
        if tree.truncated:
            warnings.append(f"The {which} side has more secrets than the limit (LOCKSTEP_MAX_TREE_SECRETS); "
                            f"compare a narrower prefix.")
    return Report(lockstep_report=FORMAT, created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  left=left, right=right, profile=profile, summary=result.summary, warnings=warnings,
                  secrets=[secret(d) for d in result.secrets if include_equal or d.status != "equal"])


_ACTION_LINE = re.compile(r"^(\s*(?:- )?action: )(per-key|skip)$", re.M)


def dump(report: Report, filename: str) -> str:
    data = report.model_dump(exclude_none=True, exclude_defaults=False)
    if not data["warnings"]:
        del data["warnings"]
    for s in data["secrets"]:  # keep the file short: drop empty/false noise per key
        for k in s["keys"]:
            for f in ("type_differs", "ignored"):
                if not k[f]:
                    del k[f]
        if not s["keys"]:
            del s["keys"]
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1000, default_flow_style=False)

    def hint(m: re.Match) -> str:
        options = "per-key | skip | copy-to-right | copy-to-left" if m.group(2) == "per-key" \
            else "skip | copy-to-right | copy-to-left"
        return f"{m.group(1)}{m.group(2)}  # {options}"

    return HEADER.format(file=filename, schema=SCHEMA_URL) + _ACTION_LINE.sub(hint, body)


# --------------------------------------------------------------------------- load / plan


def load(text: str, source: str) -> Report:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise CliError(f"{source} isn't valid YAML: {e}") from e
    if not isinstance(raw, dict) or "lockstep_report" not in raw:
        raise CliError(f"{source} isn't a Lockstep report (no lockstep_report field).")
    try:
        return Report.model_validate(raw)
    except ValidationError as e:
        lines = []
        for err in e.errors():
            where = _where(raw, err["loc"])
            lines.append(f"  {where}: {err['msg']}")
        raise CliError(f"{source} has mistakes:\n" + "\n".join(lines)) from e


def _where(raw: dict, loc: tuple) -> str:
    """'secrets[3].keys[0].action' plus the secret path and key name, for error messages."""
    out = ".".join(str(p) if not isinstance(p, int) else f"[{p}]" for p in loc).replace(".[", "[")
    try:
        if loc[0] == "secrets":
            s = raw["secrets"][loc[1]]
            out += f" (secret {s.get('path')}"
            if len(loc) > 3 and loc[2] == "keys":
                out += f", key {s['keys'][loc[3]].get('key')}"
            out += ")"
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return out


def _rel(side: ReportSide, s: SecretSide, which: str, path: str) -> str:
    p = _prefix(side.prefix)
    if not s.path.startswith(p):
        raise CliError(f"Secret {path}: its {which} path {s.path} isn't under the {which} prefix {side.prefix!r}.")
    return s.path[len(p):]


def plan(report: Report) -> list[tuple[ReportSecret, Change]]:
    """Turn the actions in a report into sync changes, checking every action first.
    Raises CliError listing all mistakes, so nothing is written for a half-valid file."""
    out: list[tuple[ReportSecret, Change]] = []
    problems: list[str] = []
    for s in report.secrets:
        key_actions = {k.key: k.action for k in s.keys if k.action != "skip"}
        if s.action == "skip" or (s.action == "per-key" and not key_actions):
            continue
        if s.status in ("no_access", "error"):
            problems.append(f"{s.path}: can't copy, the comparison couldn't read both sides ({s.status}).")
            continue
        if s.action != "per-key" and key_actions:
            problems.append(f"{s.path}: set either the secret's action or its keys' actions, not both.")
            continue
        by_dir: dict[Direction, list[str] | None] = {}
        if s.action != "per-key":
            src = s.left if s.action == "copy-to-right" else s.right
            if src.state != "present":
                problems.append(f"{s.path}: {s.action} needs the {'left' if s.action == 'copy-to-right' else 'right'} "
                                f"side to have the secret, but it's {src.state}.")
                continue
            by_dir[DIRECTION[s.action]] = None  # every key the source has
        else:
            statuses = {k.key: k.status for k in s.keys}
            for key, action in key_actions.items():
                if statuses[key] not in COPYABLE[action]:
                    side = "left" if action == "copy-to-right" else "right"
                    problems.append(f"{s.path}: key {key} can't be {action} (it's {statuses[key].replace('_', ' ')}, "
                                    f"so the {side} side has no value to copy).")
                    continue
                by_dir.setdefault(DIRECTION[action], []).append(key)
        try:
            lrel = _rel(report.left, s.left, "left", s.path)
            rrel = _rel(report.right, s.right, "right", s.path)
        except CliError as e:
            problems.append(str(e))
            continue
        for direction, keys in by_dir.items():
            src, tgt = (s.left, s.right) if direction == "left_to_right" else (s.right, s.left)
            out.append((s, Change(path=lrel, right_path=rrel if rrel != lrel else None, direction=direction,
                                  keys=keys,
                                  expected_target_version=tgt.version if tgt.state in ("present", "deleted") else None,
                                  expected_source_version=src.version)))
    if problems:
        raise CliError("The report's actions have mistakes; nothing was written:\n"
                       + "\n".join(f"  {p}" for p in problems))
    return out
