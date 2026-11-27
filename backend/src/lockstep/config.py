"""Runtime configuration. Everything comes from environment variables (12-factor)."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .policy.compare import ConfigProfile, PolicyProfile
from .policy.suggest import SuggestPattern
from .rules import Profile


class PresetConnection(BaseModel):
    name: str
    url: str  # address the backend uses to reach Vault
    browser_url: str | None = None  # address shown to / reachable by the user, if different
    namespace: str | None = None
    timeout_seconds: float | None = Field(default=None, gt=0, le=600)  # default: LOCKSTEP_VAULT_TIMEOUT_SECONDS
    # Write policy (lockstep.writepolicy), on top of Vault's own policies and LOCKSTEP_READ_ONLY:
    writable: bool = True  # false: compare and read only, write nothing here
    allow_destroy: bool | None = None  # None: LOCKSTEP_ALLOW_DESTROY decides
    write_paths: list[str] = []  # if set, writes only to these paths (`kv/apps/**`, `sys/policies/acl/app-*`)
    deny_paths: list[str] = []  # never write to these, even inside write_paths
    # 1: secrets are written here only through sync plans someone other than their creator approved
    approvals: int = Field(default=0, ge=0, le=1)
    # Exports from this Vault: "any", "encrypted" or "off". None: LOCKSTEP_EXPORT_MODE decides
    export: Literal["any", "encrypted", "off"] | None = None


class ExportTeam(BaseModel):
    name: str = Field(min_length=1, max_length=100)  # shown in the Export panel
    recipients: list[str] = Field(min_length=1, max_length=50)  # age public keys (age1…)

    @field_validator("recipients")
    @classmethod
    def _age_keys(cls, v: list[str]) -> list[str]:
        import pyrage
        from pyrage import x25519
        for key in v:
            try:
                x25519.Recipient.from_str(key.strip())
            except pyrage.RecipientError as e:
                raise ValueError(f"{key[:20]}… isn't an age public key (age1…): {e}") from e
        return [k.strip() for k in v]


class TrustedKey(BaseModel):
    name: str = Field(min_length=1, max_length=100)  # the installation that signs with it
    key: str = Field(min_length=1)  # Ed25519 public key: base64 of the 32 raw bytes, or PEM


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOCKSTEP_")

    public_url: str = "http://localhost:8080"
    session_key: str  # required: used to encrypt session cookies
    cookie_secure: bool = True
    session_ttl_seconds: int = 8 * 3600
    preset_connections: list[PresetConnection] = []
    # Let users type their own Vault address (off by default: the presets are the safe set)
    allow_custom_connections: bool = False
    # If set, a custom address's origin (scheme://host[:port]) must fully match one of these regexes.
    custom_url_patterns: Annotated[list[str], NoDecode] = []
    # Custom addresses may resolve to private, loopback and link-local addresses (an internal Vault)
    custom_allow_private: bool = False
    max_tree_secrets: int = 5000
    # How long one call to a Vault may take (per preset: "timeout_seconds"). Reads are retried
    # twice on connection errors and 429/502/503/504; writes never are.
    vault_timeout_seconds: float = Field(default=15.0, gt=0, le=600)
    # Secret-engine exports (they hold values): "encrypted" allows encrypted exports only, "any"
    # lets users choose plain or encrypted, "off" disables exporting. Import is unaffected. A
    # preset's "export" replaces this for that Vault.
    export_mode: Literal["any", "encrypted", "off"] = "encrypted"
    # Teams an export can be encrypted to, by name: their members open it with their own age key
    export_recipients: Annotated[list[ExportTeam], NoDecode] = []
    # Destroying secrets (every version and the metadata, can't be undone) from the compare view.
    # Vault's policies still decide who may; this turns the feature off for everyone.
    allow_destroy: bool = True
    # Writing ACL policies and auth roles from the Policies tab: "on", or "off" where Terraform (or
    # another source of truth) owns them. Building and exporting for an admin always works.
    policy_apply: Literal["on", "off"] = "on"
    # Creating userpass users and resetting their passwords: for development Vaults, off by default
    user_write: Literal["on", "off"] = "off"
    # Audit-log a secret.reveal event whenever a response carries secret values (who saw what, never values)
    audit_reveals: Literal["on", "off"] = "off"
    # The interactive API documentation (Swagger UI at /api/docs, and /api/openapi.json)
    api_docs: Literal["on", "off"] = "on"
    # Plans that travel between installations (lockstep.plansign): this installation's Ed25519
    # private key, the public keys of installations whose plans it accepts, its name in plans
    # (default: LOCKSTEP_PUBLIC_URL's host), and how long a new plan is valid.
    plan_signing_key: str = ""
    plan_trusted_keys: Annotated[list[TrustedKey], NoDecode] = []
    plan_issuer: str = ""
    plan_ttl_hours: int = Field(default=168, gt=0, le=24 * 90)
    # 1: a sync plan applied here needs an approval from someone other than its creator (four-eyes,
    # as a check against mistakes). A preset's "approvals" asks for it for that Vault only.
    plan_approvals: int = Field(default=0, ge=0, le=1)
    # Refuse every write (copies, edits, imports, plan applies, destroys): for look-only installs
    read_only: bool = False
    # Offer a Copy button next to shown values (an admin may prefer not to)
    allow_clipboard: bool = True
    # Optional notice shown at the top of the UI (e.g. for a public demo)
    demo_banner: str = ""
    # Prometheus metrics at /metrics (requests, Vault calls, sign-ins, 429s; never paths or users)
    metrics: Literal["on", "off"] = "off"
    # When set, /metrics needs `Authorization: Bearer <this>`
    metrics_token: str = ""
    # Per-client limit on API requests (0: off), for installs open to anyone. A token bucket per
    # client address, in memory, per process: rate_limit_per_minute sustained, rate_limit_burst at
    # once (default: a quarter of a minute's worth, at least 20). Over it, the API answers 429.
    rate_limit_per_minute: int = 0
    # Failed sign-ins (passwords, tokens, second factors) per client address and per user on a Vault:
    # this many in the window and sign-in answers 429 until the oldest is older than the window. 0: off.
    signin_max_failures: int = Field(default=10, ge=0)
    signin_window_seconds: int = Field(default=300, gt=0)
    rate_limit_burst: int = 0
    # Server log: debug | info | warning | error. debug adds every call Lockstep makes to a Vault.
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    # text: one readable line per event; json: one JSON object per line, for log collectors
    log_format: Literal["text", "json"] = "text"
    # Shared comparison profiles (JSON list), offered read-only to every user
    profiles: Annotated[list[Profile], NoDecode] = []
    # Shared policy profiles (JSON list): how to pair and rewrite policies between two Vaults
    policy_profiles: Annotated[list[PolicyProfile], NoDecode] = []
    # Shared configuration profiles (JSON list): how to pair mounts and rewrite values between two Vaults
    config_profiles: Annotated[list[ConfigProfile], NoDecode] = []
    # Shared suggestion patterns (JSON list): how to suggest policies from a mount's layout
    policy_patterns: Annotated[list[SuggestPattern], NoDecode] = []

    # Kubernetes auth: log in to Vault as the pod's own service account. Off by default,
    # because anyone who can open the UI then gets that service account's Vault access.
    k8s_auth_enabled: bool = False
    k8s_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    k8s_auth_mount: str = "kubernetes"  # default shown in the UI
    k8s_auth_roles: Annotated[list[str], NoDecode] = []  # if set, only these Vault role names may be used

    @field_validator("k8s_auth_roles", "custom_url_patterns", mode="before")
    @classmethod
    def _parse_list(cls, v):
        if isinstance(v, str):
            v = v.strip()
            return json.loads(v) if v.startswith("[") else [x.strip() for x in v.split(",") if x.strip()]
        return v
    vault_tls_verify: bool = True
    vault_ca_bundle: str | None = None  # path to a CA bundle for talking to Vault
    static_dir: str | None = None  # built SPA, served at /

    @field_validator("profiles", "policy_profiles", "config_profiles", "policy_patterns", "plan_trusted_keys",
                     "export_recipients", mode="before")
    @classmethod
    def _parse_profiles(cls, v):
        return json.loads(v) if isinstance(v, str) else v

    @field_validator("preset_connections", mode="before")
    @classmethod
    def _parse_presets(cls, v):
        return json.loads(v) if isinstance(v, str) else v

    @field_validator("session_key")
    @classmethod
    def _key_len(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("LOCKSTEP_SESSION_KEY must be at least 32 characters")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
