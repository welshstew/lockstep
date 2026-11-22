"""Suggesting policies from how a mount's secrets are laid out.

A *suggestion pattern* says what each level of the tree means (`{app}/{env}/**`) and which
policies to make for each match. Lockstep detects a layout and builds a pattern itself, or uses
one the user gives. Each `{name}` in a policy's name is filled in from the tree: one policy per
distinct value (or combination). A pattern can also produce the policy profile for comparing
two of its environments.
"""

from __future__ import annotations

import itertools
import re
from collections import Counter, defaultdict
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .build import Rule, build_hcl
from .compare import NameMapping, PolicyProfile, Rewrite

DEV = ("dev", "develop", "development", "sandbox", "local", "int", "integration", "feature", "preview")
TEST = ("test", "testing", "qa", "uat", "stage", "staging", "preprod", "pre-prod", "perf", "nonprod", "non-prod")
PROD = ("prod", "production", "live", "prd")
ENVS = DEV + TEST + PROD
VAR = re.compile(r"\{([a-z][a-z0-9_]*)\}")


class PolicyTemplate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=500)
    rules: list[dict[str, Any]] = Field(min_length=1, max_length=100)  # {where, can}; where may hold {vars}


class ComparePair(BaseModel):
    pair: dict[str, list[str]]  # {var: [left value, right value]}

    @field_validator("pair")
    @classmethod
    def _one(cls, v):
        if len(v) != 1 or any(len(x) != 2 for x in v.values()):
            raise ValueError('compare.pair is one variable with two values, e.g. {env: [dev, prod]}')
        return v


class SuggestPattern(BaseModel):
    name: str = Field(default="my pattern", max_length=128)
    layout: str = Field(min_length=1, max_length=512)  # e.g. "{app}/{env}/**", "services/{app}/{env}/**"
    values: dict[str, list[str]] = {}  # limit or order the values of a variable
    policies: list[PolicyTemplate] = Field(min_length=1, max_length=50)
    compare: ComparePair | None = None


class Suggestion(BaseModel):
    name: str
    description: str
    rules: list[Rule]
    hcl: str
    template: str  # the policy name pattern it came from


def env_kind(v: str) -> str | None:
    v = v.lower()
    return "dev" if v in DEV else "test" if v in TEST else "prod" if v in PROD else None


# --------------------------------------------------------------------------- detection


def detect(secrets: list[str]) -> tuple[SuggestPattern, list[str]]:
    """A pattern for this tree, and why. `secrets` are paths relative to the starting folder."""
    folders = [s.split("/")[:-1] for s in secrets]
    depth = max((len(f) for f in folders), default=0)
    why: list[str] = []
    env_level = None
    for d in range(depth):
        vals = [f[d] for f in folders if len(f) > d]
        parents = {tuple(f[:d]) for f in folders if len(f) > d}
        envs = [v for v in vals if env_kind(v)]
        if vals and len(envs) / len(vals) >= 0.8 and (len(parents) >= 2 or len(set(envs)) >= 2):
            env_level = d
            shown = ", ".join(sorted(set(envs))[:6])
            why.append(f"Level {d + 1} holds environment names ({shown}) under {len(parents)} different "
                       f"folder{'s' if len(parents) != 1 else ''}.")
            break

    if env_level is not None:
        layout = []
        for d in range(env_level):
            at = {f[d] for f in folders if len(f) > env_level}
            if d == env_level - 1:
                layout.append("{app}")
            else:
                layout.append(next(iter(at)) if len(at) == 1 else "*")
        if env_level == 0:
            apps = {f[1] for f in folders if len(f) > 1}
            layout = ["{env}", "{app}"] if len(apps) >= 2 else ["{env}"]
        else:
            layout.append("{env}")
        envs = sorted({f[env_level] for f in folders if len(f) > env_level and env_kind(f[env_level])},
                      key=lambda e: (["dev", "test", "prod"].index(env_kind(e) or "test"), e))
        if "{app}" in layout:
            apps = sorted({f[layout.index("{app}")] for f in folders if len(f) > env_level})
            where = "below" if env_level == 0 else "above"
            why.append(f"The level {where} them names {len(apps)} app{'s' if len(apps) != 1 else ''}: "
                       f"{', '.join(apps[:6])}{'…' if len(apps) > 6 else ''}.")
        return _pattern("/".join(layout) + "/**", envs), why

    tops = Counter(f[0] for f in folders if f)
    if len(tops) >= 2:
        why.append(f"No environment names found; the {len(tops)} top-level folders are treated as apps.")
        return _pattern("{app}/**", []), why
    why.append("No folder structure to go by: only mount-wide policies are suggested.")
    return _pattern("**", []), why


def _pattern(layout: str, envs: list[str]) -> SuggestPattern:
    has_app, has_env = "{app}" in layout, "{env}" in layout
    base = layout[:-3] if layout.endswith("/**") else ""
    policies: list[PolicyTemplate] = []
    if has_app and has_env:
        dev_rules = []
        for e in envs:
            kind = env_kind(e)
            where = base.replace("{env}", e) + "/**"
            can = (["names", "read", "write", "delete", "history"] if kind == "dev"
                   else ["names", "read", "history"] if kind == "test" else ["names"])
            dev_rules.append({"where": where, "can": can})
        if dev_rules:
            does = {"dev": "change", "test": "read", "prod": "see names in"}
            parts = [f"{does[env_kind(e) or 'test']} {e}" for e in envs]
            policies.append(PolicyTemplate(name="{app}-developer", rules=dev_rules,
                                           description="Developers of an app: " + ", ".join(parts)))
        policies.append(PolicyTemplate(name="{app}-{env}-app", rules=[{"where": layout, "can": ["read", "history"]}],
                                       description="The app itself in one environment (for its Kubernetes or CI role)"))
    elif has_env:
        policies.append(PolicyTemplate(name="{env}-read", rules=[{"where": layout, "can": ["names", "read", "history"]}],
                                       description="Read one environment"))
    elif has_app:
        policies.append(PolicyTemplate(name="{app}-read", rules=[{"where": layout, "can": ["names", "read", "history"]}],
                                       description="Read one app's secrets"))
        policies.append(PolicyTemplate(name="{app}-write", rules=[{"where": layout, "can": ["names", "read", "write", "delete", "history"]}],
                                       description="Change one app's secrets"))
    policies.append(PolicyTemplate(name="{mount}-read", rules=[{"where": "**", "can": ["names", "read", "history"]}],
                                   description="Read everything, change nothing: auditors and drift checks in CI"))
    policies.append(PolicyTemplate(name="{mount}-admin", rules=[{"where": "**", "can": ["names", "read", "write", "delete", "history"]}],
                                   description="Everything except destroying"))
    dev = next((e for e in envs if env_kind(e) == "dev"), None)
    prod = next((e for e in envs if env_kind(e) == "prod"), None)
    pair = ComparePair(pair={"env": [dev, prod]}) if has_env and dev and prod else None
    return SuggestPattern(name="detected", layout=layout, values={"env": envs} if envs else {},
                          policies=policies, compare=pair)


# --------------------------------------------------------------------------- applying a pattern


def _layout_regex(layout: str) -> tuple[re.Pattern, list[str]]:
    parts = layout.strip("/").split("/")
    names: list[str] = []
    rx = []
    for i, p in enumerate(parts):
        if p == "**" and i == len(parts) - 1:
            rx.append("(?:/.*)?" if rx else ".*")
            continue
        seg = ""
        for piece in re.split(r"(\{[a-z][a-z0-9_]*\})", p):
            m = VAR.fullmatch(piece)
            if m:
                if m.group(1) in names:
                    seg += f"(?P={m.group(1)})"
                else:
                    names.append(m.group(1))
                    seg += f"(?P<{m.group(1)}>[^/]+)"
            elif piece == "*":
                seg += "[^/]+"
            else:
                seg += re.escape(piece)
        rx.append(("/" if rx else "") + seg)
    return re.compile("^" + "".join(rx) + "$"), names


def matches(layout: str, secrets: list[str]) -> list[dict[str, str]]:
    """Every distinct binding of the layout's variables found in the tree."""
    rx, names = _layout_regex(layout)
    seen: dict[tuple, dict[str, str]] = {}
    for s in secrets:
        m = rx.match(s)
        if m:
            b = {n: m.group(n) for n in names}
            seen.setdefault(tuple(b[n] for n in names), b)
    return list(seen.values())


def _fill(text: str, values: dict[str, str]) -> str:
    return VAR.sub(lambda m: values.get(m.group(1), m.group(0)), text)


def apply_pattern(pattern: SuggestPattern, secrets: list[str], mount: str, prefix: str = "") -> tuple[list[Suggestion], list[str]]:
    """Fill the pattern in from the tree. `secrets` are relative to `prefix`; rules get the prefix back."""
    notes: list[str] = []
    found = matches(pattern.layout, secrets)
    if not found and VAR.search(pattern.layout):
        notes.append(f"The layout {pattern.layout} doesn't match any secret here.")
    values: dict[str, list[str]] = defaultdict(list)
    for b in found:
        for k, v in b.items():
            if v not in values[k]:
                values[k].append(v)
    for k, wanted in pattern.values.items():
        if k in values:
            values[k] = [v for v in wanted if v in values[k]] + ([] if wanted else values[k])
    # {mount} in a name: the mount, plus the folder suggestions were made for
    fixed = {"mount": "-".join(x for x in (mount.strip("/"), prefix.strip("/")) if x).replace("/", "-")}
    pre = f"{prefix.strip('/')}/" if prefix.strip("/") else ""
    out: list[Suggestion] = []
    for t in pattern.policies:
        name_vars = [v for v in dict.fromkeys(VAR.findall(t.name)) if v not in fixed]
        missing = [v for v in name_vars if v not in values]
        if missing:
            notes.append(f"{t.name}: the layout has no {{{missing[0]}}}, so it's left out.")
            continue
        combos = ([dict(zip(name_vars, c)) for c in itertools.product(*(values[v] for v in name_vars))]
                  if name_vars else [{}])
        # Only combinations that exist in the tree (an app without a prod folder gets no -prod policy)
        combos = [c for c in combos if not c or any(all(b.get(k) == v for k, v in c.items()) for b in found)]
        for combo in combos:
            vals = fixed | combo
            rules: list[Rule] = []
            for r in t.rules:
                where = str(r.get("where", ""))
                rest = [v for v in dict.fromkeys(VAR.findall(where)) if v not in vals]
                for extra in (itertools.product(*(values.get(v, []) for v in rest)) if rest else [()]):
                    w = _fill(where, vals | dict(zip(rest, extra)))
                    if VAR.search(w):
                        continue
                    try:
                        rules.append(Rule(where=pre + w, can=r.get("can", [])))
                    except ValueError as e:
                        notes.append(f"{t.name}: {e}")
            if not rules:
                continue
            name = _fill(t.name, vals)
            out.append(Suggestion(name=name, description=_fill(t.description, vals), rules=rules, template=t.name,
                                  hcl=build_hcl(mount, rules, name=name, note=_fill(t.description, vals))))
    return out, notes


def compare_profile(pattern: SuggestPattern) -> PolicyProfile | None:
    """The policy profile for comparing two of the pattern's values (e.g. dev with prod)."""
    if not pattern.compare:
        return None
    (var, (left, right)), = pattern.compare.pair.items()
    mappings = []
    for t in pattern.policies:
        if f"{{{var}}}" not in t.name:
            continue
        glob = VAR.sub(lambda m: "*" if m.group(1) != var else m.group(0), t.name)
        lname, rname = glob.replace(f"{{{var}}}", left), glob.replace(f"{{{var}}}", right)
        if lname.count("*") == rname.count("*"):
            mappings.append(NameMapping(left=lname, right=rname))
    return PolicyProfile(name=f"{left} vs {right}", description=f"From the suggestion pattern {pattern.name}",
                         mappings=mappings, rewrites=[Rewrite(find=f"/{left}/", replace=f"/{right}/")])


def pattern_schema() -> dict:
    s = SuggestPattern.model_json_schema()
    s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    s["title"] = "Lockstep suggestion pattern"
    return s
