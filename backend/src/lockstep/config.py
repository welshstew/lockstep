"""Runtime configuration. Everything comes from environment variables (12-factor)."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .rules import Profile


class PresetConnection(BaseModel):
    name: str
    url: str  # address the backend uses to reach Vault
    browser_url: str | None = None  # address shown to / reachable by the user, if different
    namespace: str | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOCKSTEP_")

    public_url: str = "http://localhost:8080"
    session_key: str  # required: used to encrypt session cookies
    cookie_secure: bool = True
    session_ttl_seconds: int = 8 * 3600
    preset_connections: list[PresetConnection] = []
    allow_custom_connections: bool = True
    # If set, custom Vault URLs must fully match one of these regexes (limits SSRF exposure).
    custom_url_patterns: Annotated[list[str], NoDecode] = []
    max_tree_secrets: int = 5000
    # Secret-engine exports (they hold values): "any" lets users choose plain or encrypted,
    # "encrypted" allows encrypted exports only, "off" disables exporting. Import is unaffected.
    export_mode: Literal["any", "encrypted", "off"] = "any"
    # Optional notice shown at the top of the UI (e.g. for a public demo)
    demo_banner: str = ""
    # Shared comparison profiles (JSON list), offered read-only to every user
    profiles: Annotated[list[Profile], NoDecode] = []

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

    @field_validator("profiles", mode="before")
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
