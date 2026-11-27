"""Per-preset write policy: "compare prod, write dev" without making all of Lockstep read-only.

A preset can say
    {"name": "Prod", "url": "…", "writable": false}                  nothing is written from here
    {"name": "Dev", "url": "…", "write_paths": ["kv/apps/**"],
     "deny_paths": ["kv/apps/*/break-glass/**"], "allow_destroy": false}

Paths are what a write changes, as Vault names it without the API's own parts: a KV secret is
`<mount>/<path>` (no `data/`), anything else its API path (`sys/policies/acl/web`,
`auth/kubernetes/role/ci`, `pki/issue/web`). `*` is one path segment, `**` any number.
These rules come on top of Vault's own policies: every write still uses the user's token.

A connection to a preset's address that was typed in by hand (or opened in a namespace from a
preset connection) gets the same rules, so typing the address doesn't get round them.
"""

from __future__ import annotations

import json
import logging
import time

from fastapi import HTTPException

from .config import PresetConnection, Settings
from .rules import compile_glob
from .session import Connection

audit = logging.getLogger("lockstep.audit")


def _norm(url: str) -> str:
    return url.rstrip("/").lower()


def preset_of(settings: Settings, conn: Connection) -> PresetConnection | None:
    """The preset whose rules apply to this connection: its own, or the strictest one at its address."""
    if conn.preset_id is not None and 0 <= conn.preset_id < len(settings.preset_connections):
        return settings.preset_connections[conn.preset_id]
    same = [p for p in settings.preset_connections if _norm(p.url) == _norm(conn.url)]
    if not same:
        return None
    # Several presets at one address (namespaces, say): the most restrictive wins
    return sorted(same, key=lambda p: (p.writable, not p.deny_paths, p.allow_destroy is not False, not p.write_paths))[0]


def _match(patterns: list[str], path: str) -> bool:
    path = path.strip("/")
    return any(compile_glob(p.strip("/")).match(path) for p in patterns)


def refusal(settings: Settings, conn: Connection, path: str, action: str = "write") -> str | None:
    """Why this write is refused by the preset's rules, or None. `action` is "write" or "destroy"."""
    p = preset_of(settings, conn)
    if p is None:
        return None
    if not p.writable:
        return f"{p.name} is read-only on this Lockstep server: nothing can be written to it from here."
    if action == "destroy" and p.allow_destroy is False:
        return f"Destroying secrets is turned off for {p.name} on this Lockstep server."
    if p.deny_paths and _match(p.deny_paths, path):
        return f"{path} is protected on {p.name}: this Lockstep server doesn't write there."
    if p.write_paths and not _match(p.write_paths, path):
        return f"{path} is outside the paths this Lockstep server may write on {p.name} ({', '.join(p.write_paths)})."
    return None


_EXPORT_STRICTNESS = {"off": 0, "encrypted": 1, "any": 2}


def export_mode(settings: Settings, conn: Connection) -> tuple[str, PresetConnection | None]:
    """Which exports this connection allows ("any", "encrypted" or "off"), and the preset that
    decided it (None: LOCKSTEP_EXPORT_MODE did). A preset's `export` replaces the server's setting
    for that Vault; a typed-in address of several presets gets the strictest of them."""
    if conn.preset_id is not None and 0 <= conn.preset_id < len(settings.preset_connections):
        p = settings.preset_connections[conn.preset_id]
        return (p.export, p) if p.export else (settings.export_mode, None)
    same = [p for p in settings.preset_connections if _norm(p.url) == _norm(conn.url)]
    modes = [(p.export or settings.export_mode, p if p.export else None) for p in same]
    if not modes:
        return settings.export_mode, None
    return min(modes, key=lambda m: _EXPORT_STRICTNESS[m[0]])


def approvals_for(settings: Settings, conn: Connection) -> int:
    """How many approvals a sync plan writing to this connection's Vault needs."""
    p = preset_of(settings, conn)
    return max(settings.plan_approvals, p.approvals if p else 0)


def needs_plan(settings: Settings, conn: Connection) -> str | None:
    """Why a direct secret write here is refused: the preset says its secrets change only through
    approved plans. None when direct writes are fine."""
    p = preset_of(settings, conn)
    if p and p.approvals:
        return (f"Secrets on {p.name} change only through approved plans on this Lockstep server: save the "
                "changes as a plan, and have someone else approve it.")
    return None


def check(settings: Settings, conn: Connection, paths: list[str] | str, action: str = "write", event: str = "write") -> None:
    """Refuse the request (403) if the preset's rules forbid any of these paths, and audit-log it."""
    for path in [paths] if isinstance(paths, str) else paths:
        if why := refusal(settings, conn, path, action):
            log_refusal(conn, path, action, event, why)
            raise HTTPException(403, detail={"message": why, "write_policy": True})


def log_refusal(conn: Connection, path: str, action: str, event: str, why: str) -> None:
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "write.refused", "outcome": "refused", "action": action, "request": event,
        "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
        "target": {"vault": conn.name, "url": conn.url, "path": path.strip("/")},
        "message": why,
    }, sort_keys=True))


def summary(settings: Settings, conn: Connection) -> tuple[str, bool]:
    """For the UI: ("all" | "some" | "none", whether destroying is allowed) on this connection."""
    p = preset_of(settings, conn)
    destroy = settings.allow_destroy and not settings.read_only
    if settings.read_only:
        return "none", False
    if p is None:
        return "all", destroy
    if not p.writable:
        return "none", False
    if p.allow_destroy is not None:
        destroy = destroy and p.allow_destroy
    return ("some" if p.write_paths or p.deny_paths else "all"), destroy
