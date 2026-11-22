"""Kubernetes and JWT/OIDC auth roles: reading them in plain terms, checking them, comparing them
across Vaults, and building new ones from templates.

A role's fields are normalised before showing or comparing: fields at their default are left
out, lists are sorted, and durations are seconds. So a role written with and without
`token_ttl = 0` compares equal, as the policy builder proposal asks.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from .compare import PolicyProfile, _regex

Kind = Literal["kubernetes", "jwt", "approle"]  # jwt covers both jwt and oidc mounts (one plugin)
AUTH_TYPES = {"kubernetes": "kubernetes", "jwt": "jwt", "oidc": "jwt", "approle": "approle"}

TOKEN_FIELDS = {
    "token_policies": [], "token_ttl": 0, "token_max_ttl": 0, "token_explicit_max_ttl": 0, "token_period": 0,
    "token_type": "default", "token_bound_cidrs": [], "token_no_default_policy": False, "token_num_uses": 0,
}
FIELDS: dict[str, dict[str, Any]] = {
    "kubernetes": {
        "bound_service_account_names": [], "bound_service_account_namespaces": [],
        "bound_service_account_namespace_selector": "", "audience": "", "alias_name_source": "serviceaccount_uid",
        **TOKEN_FIELDS,
    },
    "jwt": {
        "role_type": "oidc", "user_claim": "", "user_claim_json_pointer": False, "bound_audiences": [],
        "bound_subject": "", "bound_claims": {}, "bound_claims_type": "string", "claim_mappings": {},
        "groups_claim": "", "allowed_redirect_uris": [], "oidc_scopes": [], "max_age": 0,
        "clock_skew_leeway": 0, "expiration_leeway": 0, "not_before_leeway": 0, "verbose_oidc_logging": False,
        **TOKEN_FIELDS,
    },
    "approle": {
        "bind_secret_id": True, "secret_id_bound_cidrs": [], "secret_id_num_uses": 0, "secret_id_ttl": 0,
        "local_secret_ids": False, **TOKEN_FIELDS,
    },
}
LABELS = {
    "bound_service_account_names": "Service accounts", "bound_service_account_namespaces": "Namespaces",
    "bound_service_account_namespace_selector": "Namespace selector", "audience": "Audience",
    "alias_name_source": "Alias from", "role_type": "Role type", "user_claim": "User claim",
    "bound_audiences": "Audiences", "bound_subject": "Subject", "bound_claims": "Bound claims",
    "bound_claims_type": "Bound claims match", "claim_mappings": "Claim mappings", "groups_claim": "Groups claim",
    "allowed_redirect_uris": "Redirect URIs", "oidc_scopes": "OIDC scopes", "token_policies": "Policies",
    "token_ttl": "Token TTL", "token_max_ttl": "Max TTL", "token_explicit_max_ttl": "Explicit max TTL",
    "token_period": "Period", "token_type": "Token type", "token_bound_cidrs": "Allowed from (CIDR)",
    "token_no_default_policy": "Without the default policy", "token_num_uses": "Uses per token", "max_age": "Max auth age",
    "bind_secret_id": "Needs a secret ID", "secret_id_bound_cidrs": "Secret IDs usable from (CIDR)",
    "secret_id_num_uses": "Uses per secret ID", "secret_id_ttl": "Secret ID TTL", "local_secret_ids": "Secret IDs local to this cluster",
}
DAY = 86400


def kind_of(auth_type: str) -> Kind | None:
    return AUTH_TYPES.get(auth_type)  # type: ignore[return-value]


_DUR = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d)")


def seconds(v: Any) -> Any:
    """Vault accepts "1h", "90m", "3600" or 3600 and returns seconds: normalise to seconds."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        s = v.replace(" ", "")
        if s.isdigit():
            return int(s)
        parts = _DUR.findall(s)
        if parts and "".join(a + b for a, b in parts) == s:
            mult = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": DAY}
            return int(sum(float(a) * mult[b] for a, b in parts))
    return v


def normalise(kind: Kind, role: dict[str, Any]) -> dict[str, Any]:
    """The role's meaningful fields: defaults left out, lists sorted, durations in seconds."""
    known = FIELDS[kind]
    out: dict[str, Any] = {}
    data = dict(role)
    if "policies" in data and not data.get("token_policies"):
        data["token_policies"] = data["policies"]  # the legacy field
    for k, default in known.items():
        if k not in data:
            continue
        v = data[k]
        if k.endswith("ttl") or k in ("token_period", "max_age") or k.endswith("leeway"):
            v = seconds(v)
        if isinstance(v, list):
            v = sorted(str(x) for x in v if x not in ("", None))
        if isinstance(v, dict):
            v = {kk: (sorted(vv) if isinstance(vv, list) else vv) for kk, vv in sorted(v.items())}
        if v in (default, None) or v == [] or v == {}:
            continue
        out[k] = v
    return out


def policies_of(role: dict[str, Any]) -> list[str]:
    """The policies a login with this role gets (default included unless turned off)."""
    pols = list(role.get("token_policies") or [])
    if not role.get("token_no_default_policy") and "default" not in pols:
        pols.append("default")
    return pols


class Finding(BaseModel):
    level: Literal["error", "warn", "info"]
    message: str
    field: str | None = None


def lint(kind: Kind, role: dict[str, Any], existing: set[str] | None = None) -> list[Finding]:
    """Common mistakes in a (normalised) role."""
    f: list[Finding] = []
    add = lambda level, msg, field=None: f.append(Finding(level=level, message=msg, field=field))  # noqa: E731
    if kind == "kubernetes":
        names = role.get("bound_service_account_names") or []
        nss = role.get("bound_service_account_namespaces") or []
        if not names:
            add("error", "No service accounts: Vault refuses a Kubernetes role without bound service account names.",
                "bound_service_account_names")
        if not nss and not role.get("bound_service_account_namespace_selector"):
            add("error", "No namespaces: Vault refuses a Kubernetes role without namespaces or a namespace selector.",
                "bound_service_account_namespaces")
        if "*" in names and "*" in nss:
            add("warn", "Any service account in any namespace can log in with this role.", "bound_service_account_names")
        elif "*" in names:
            add("warn", "Any service account in these namespaces can log in.", "bound_service_account_names")
        elif "*" in nss:
            add("warn", "These service accounts can log in from any namespace.", "bound_service_account_namespaces")
        if not role.get("audience"):
            add("info", "No audience: any service account token is accepted, whatever it was issued for. "
                        "Setting one (e.g. vault) limits it to tokens meant for Vault.", "audience")
    elif kind == "approle":
        if role.get("bind_secret_id") is False and not (role.get("secret_id_bound_cidrs") or role.get("token_bound_cidrs")):
            add("error", "No secret ID and no CIDR limits: anyone who learns the role ID can log in.", "bind_secret_id")
        elif role.get("bind_secret_id") is False:
            add("warn", "No secret ID: the role ID and the allowed networks are all that protect this role.", "bind_secret_id")
        if not role.get("secret_id_ttl"):
            add("warn", "Secret IDs never expire: set a secret ID TTL so a leaked one stops working.", "secret_id_ttl")
        if not role.get("secret_id_num_uses") and not role.get("secret_id_bound_cidrs"):
            add("info", "Secret IDs can be used any number of times from anywhere: consider uses or CIDR limits.", "secret_id_num_uses")
    else:
        jwt = role.get("role_type", "oidc") == "jwt"
        if jwt and not (role.get("bound_claims") or role.get("bound_subject") or role.get("bound_audiences")):
            add("error", "Nothing ties this JWT role to a workload: anyone with any token from this issuer can log in. "
                         "Bind claims (e.g. project_path and ref for GitLab CI), a subject or an audience.", "bound_claims")
        elif jwt and not (role.get("bound_claims") or role.get("bound_subject")):
            add("warn", "Only the audience is checked: every workload whose token has this audience can log in.",
                "bound_claims")
        if not role.get("user_claim"):
            add("error", "user_claim is required.", "user_claim")
        if role.get("bound_claims_type") == "glob":
            for k, v in (role.get("bound_claims") or {}).items():
                vals = v if isinstance(v, list) else [v]
                if any(str(x).strip() == "*" for x in vals):
                    add("warn", f"bound_claims.{k} is * with glob matching: it matches anything.", "bound_claims")
        if not jwt:
            uris = role.get("allowed_redirect_uris") or []
            if not uris:
                add("error", "An OIDC role needs at least one allowed redirect URI.", "allowed_redirect_uris")
            for u in uris:
                if u.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1)(:|/)", u):
                    add("warn", f"{u} is plain HTTP: the authorization code travels unencrypted.", "allowed_redirect_uris")
    ttl, max_ttl = role.get("token_ttl", 0), role.get("token_max_ttl", 0)
    if isinstance(ttl, int) and ttl > DAY:
        add("info", f"Tokens live {ttl // 3600} hours: shorter TTLs limit what a leaked token can do.", "token_ttl")
    if isinstance(max_ttl, int) and max_ttl > 7 * DAY:
        add("info", f"Tokens can be renewed for {max_ttl // DAY} days.", "token_max_ttl")
    pols = role.get("token_policies") or []
    if not pols:
        add("warn", "No policies: tokens get only the default policy" + (" (and not even that)" if role.get("token_no_default_policy") else "") + ".",
            "token_policies")
    if "root" in pols:
        add("error", "root can't be given through a role.", "token_policies")
    if existing is not None:
        missing = [p for p in pols if p not in existing and p not in ("default", "root")]
        if missing:
            add("warn", f"No such polic{'y' if len(missing) == 1 else 'ies'} on this Vault: {', '.join(missing)}. "
                        "Logins get nothing from them until they exist.", "token_policies")
    return f


# --------------------------------------------------------------------------- compare


def rewrite(value: Any, profile: PolicyProfile | None) -> Any:
    if not profile or not profile.rewrites:
        return value
    if isinstance(value, str):
        for r in profile.rewrites:
            value = value.replace(r.find, r.replace)
        return value
    if isinstance(value, list):
        return sorted(rewrite(v, profile) for v in value)
    if isinstance(value, dict):
        return {k: rewrite(v, profile) for k, v in value.items()}
    return value


def map_name(name: str, profile: PolicyProfile | None) -> str | None:
    for m in profile.mappings if profile else []:
        hit = _regex(m.left).match(name)
        if hit:
            parts = iter(hit.groups())
            return "".join(p + (next(parts) if i < m.right.count("*") else "") for i, p in enumerate(m.right.split("*")))
    return None


def compare_roles(left: dict[str, dict], right: dict[str, dict], profile: PolicyProfile | None) -> list[dict]:
    """Pair roles by name (or the profile's mappings) and compare them field by field.
    `left`/`right`: name -> normalised role."""
    out = []
    taken: set[str] = set()
    for name in sorted(left):
        target = map_name(name, profile)
        rname = target if target in right else (name if target is None and name in right else None)
        if rname:
            taken.add(rname)
        lrole = {k: rewrite(v, profile) for k, v in left[name].items()}
        rrole = right.get(rname) if rname else None
        fields = []
        if rrole is not None:
            for k in sorted(set(lrole) | set(rrole)):
                a, b = lrole.get(k), rrole.get(k)
                if a != b:
                    fields.append({"field": k, "label": LABELS.get(k, k), "left": left[name].get(k), "right": b})
        out.append({"left": name, "right": rname, "mapped": target is not None,
                    "status": "left_only" if rrole is None else "different" if fields else "equal",
                    "fields": fields, "note": f"expected {target} on the right" if target and not rname else ""})
    out += [{"left": None, "right": n, "mapped": False, "status": "right_only", "fields": [], "note": ""}
            for n in sorted(right) if n not in taken]
    return out


# --------------------------------------------------------------------------- templates and Terraform


TEMPLATES: dict[str, dict[str, Any]] = {
    "kubernetes": {"kind": "kubernetes", "label": "Kubernetes service account",
                   "body": {"bound_service_account_names": ["my-app"], "bound_service_account_namespaces": ["my-app-dev"],
                            "audience": "vault", "token_policies": [], "token_ttl": 3600}},
    "gitlab-ci": {"kind": "jwt", "label": "GitLab CI job (id_tokens)",
                  "body": {"role_type": "jwt", "user_claim": "user_email", "bound_audiences": ["https://vault.example.com"],
                           "bound_claims_type": "glob",
                           "bound_claims": {"project_path": "mygroup/my-app", "ref": "main", "ref_type": "branch", "ref_protected": "true"},
                           "token_policies": [], "token_ttl": 900}},
    "github-actions": {"kind": "jwt", "label": "GitHub Actions workflow",
                       "body": {"role_type": "jwt", "user_claim": "actor", "bound_audiences": ["https://github.com/my-org"],
                                "bound_claims_type": "glob",
                                "bound_claims": {"repository": "my-org/my-app", "ref": "refs/heads/main"},
                                "token_policies": [], "token_ttl": 900}},
    "k8s-issuer": {"kind": "jwt", "label": "Kubernetes service account through JWT auth",
                   "body": {"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["vault"],
                            "bound_subject": "system:serviceaccount:my-app-dev:my-app", "token_policies": [], "token_ttl": 3600}},
    "approle-ci": {"kind": "approle", "label": "A CI pipeline or app with AppRole",
                   "body": {"secret_id_ttl": 86400, "secret_id_num_uses": 0, "token_policies": [], "token_ttl": 900,
                            "token_max_ttl": 3600}},
    "oidc-group": {"kind": "jwt", "label": "People in an identity-provider group (OIDC)",
                   "body": {"role_type": "oidc", "user_claim": "email", "groups_claim": "groups", "oidc_scopes": ["openid", "email", "profile"],
                            "bound_claims": {"groups": ["developers"]},
                            "allowed_redirect_uris": ["https://vault.example.com/ui/vault/auth/oidc/oidc/callback",
                                                      "http://localhost:8250/oidc/callback"],
                            "token_policies": [], "token_ttl": 28800}},
}

TF_RESOURCE = {"kubernetes": "vault_kubernetes_auth_backend_role", "jwt": "vault_jwt_auth_backend_role",
               "approle": "vault_approle_auth_backend_role"}


class RoleSpec(BaseModel):
    kind: Kind
    mount: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    body: dict[str, Any]


def _hcl(v: Any, indent: int = 2) -> str:
    import json
    if isinstance(v, dict):
        pad = " " * (indent + 2)
        return "{\n" + "".join(f"{pad}{json.dumps(k)} = {_hcl(x, indent + 2)}\n" for k, x in v.items()) + " " * indent + "}"
    return json.dumps(v)


def terraform_block(spec: RoleSpec, tf_name: str) -> str:
    body = normalise(spec.kind, spec.body)
    lines = [f'resource "{TF_RESOURCE[spec.kind]}" "{tf_name}" {{', f'  backend   = "{spec.mount.strip("/")}"',
             f'  role_name = "{spec.name}"']
    for k, v in body.items():
        if spec.kind == "jwt" and k == "bound_claims":
            v = {kk: (",".join(vv) if isinstance(vv, list) else vv) for kk, vv in v.items()}  # the provider takes strings
        lines.append(f"  {k} = {_hcl(v)}")
    return "\n".join(lines) + "\n}\n"
