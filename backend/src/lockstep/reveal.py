"""The secret.reveal audit event: who was shown which secrets' values (LOCKSTEP_AUDIT_REVEALS=on).

One event per request, never per key, with the secrets and key names whose values the response
carried. Never the values themselves. Off by default: showing values is routine, and a security
team that wants "who looked at a production secret" turns it on.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from . import logs
from .config import Settings
from .session import Connection

audit = logging.getLogger("lockstep.audit")
MAX_SECRETS = 200  # per event; the rest are counted in "more"


@dataclass
class Shown:
    conn: Connection
    mount: str
    path: str
    keys: list[str] = field(default_factory=list)
    version: int | None = None


def reveal(settings: Settings, how: str, shown: list[Shown]) -> None:
    """Log that a response carried these secrets' values. `how` names the feature
    (browse.show, browse.diff, compare.show, sync.preview, inspect, unwrap…)."""
    shown = [s for s in shown if s.keys]
    if settings.audit_reveals != "on" or not shown:
        return
    actors = {(s.conn.name, s.conn.display_name, s.conn.auth_method): None for s in shown}
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "secret.reveal",
        "how": how,
        "request_id": logs.request_id.get(),
        "actor": [{"vault": v, "identity": i, "auth": a} for v, i, a in actors],
        "secrets": [{"vault": s.conn.name, "url": s.conn.url, "mount": s.mount, "path": s.path,
                     "version": s.version, "keys": sorted(set(s.keys))} for s in shown[:MAX_SECRETS]],
        "more": max(0, len(shown) - MAX_SECRETS),
    }, sort_keys=True))
