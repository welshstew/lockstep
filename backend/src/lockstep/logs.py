"""Server logging: timestamps, levels, a request ID on every line, one line per API request.

Never logged: secret values, tokens, passwords, request or response bodies, query strings.
Paths are logged; they name secrets but don't hold them (the audit log records them too).

Lines go to stderr. The audit log (`lockstep.audit`, JSON on stdout) is separate and unchanged.
"""
from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
from datetime import datetime, timezone

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}
# Third-party loggers that would log every outgoing HTTP call (with full URLs) or event-loop chatter.
QUIET = ("httpx", "httpcore", "hpack", "multipart", "asyncio")
_HANDLER_MARK = "_lockstep"


def _ts(record: logging.LogRecord) -> str:
    return datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{int(record.msecs):03d}Z"


class _RequestId(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id.get()
        if record.name == "uvicorn.error":  # uvicorn's main logger, despite the name
            record.name = "uvicorn"
        return True


class TextFormatter(logging.Formatter):
    """`2026-11-25T10:04:31.207Z INFO  lockstep.http [3f9c1a2b] GET /api/config 200 4ms`"""

    def format(self, record: logging.LogRecord) -> str:
        line = f"{_ts(record)} {record.levelname:<7} {record.name} [{record.request_id}] {record.getMessage()}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": _ts(record), "level": record.levelname.lower(), "logger": record.name,
               "request_id": record.request_id, "msg": record.getMessage()}
        out.update(getattr(record, "fields", None) or {})
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def setup(level: str = "info", fmt: str = "text") -> None:
    """Route Lockstep's and uvicorn's loggers through one handler. Safe to call more than once."""
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, _HANDLER_MARK, False):
            root.removeHandler(h)
    h = logging.StreamHandler(sys.stderr)
    setattr(h, _HANDLER_MARK, True)
    h.addFilter(_RequestId())
    h.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root.addHandler(h)
    root.setLevel(LEVELS.get(level, logging.INFO))

    # uvicorn configures its own handlers before the app loads; send its lines through ours.
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(logging.NOTSET)
    # lockstep.http replaces uvicorn's access log: it has timings and the request ID.
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    access.disabled = True
    for name in QUIET:
        logging.getLogger(name).setLevel(logging.WARNING)


class Timer:
    def __init__(self) -> None:
        self.start = time.perf_counter()

    @property
    def seconds(self) -> float:
        return time.perf_counter() - self.start

    @property
    def ms(self) -> int:
        return round((time.perf_counter() - self.start) * 1000)
