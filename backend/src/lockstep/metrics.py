"""Prometheus metrics for the server (`LOCKSTEP_METRICS=on`, served at /metrics).

A small, dependency-free implementation of counters and histograms in the Prometheus text
format. Labels never hold a secret path, a user or a token: API routes are their templates
(`/api/browse/{conn_id}/read`), Vaults are their host names.

Counts are per process, like the rate limiter; Prometheus adds them up across replicas.
"""

from __future__ import annotations

import math
import threading
from collections import defaultdict

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_lock = threading.Lock()


def escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def labels_text(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{escape(str(v))}"' for k, v in labels.items()) + "}"


def number(v: float) -> str:
    if v == math.inf:
        return "+Inf"
    return repr(float(v)) if not float(v).is_integer() else str(int(v))


class Counter:
    def __init__(self, name: str, help: str, labels: tuple[str, ...]):
        self.name, self.help, self.labels = name, help, labels
        self._values: dict[tuple, float] = defaultdict(float)

    def inc(self, *values: str, by: float = 1.0) -> None:
        with _lock:
            self._values[values] += by

    def value(self, *values: str) -> float:
        return self._values.get(values, 0.0)

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        for key, v in sorted(self._values.items()):
            out.append(f"{self.name}{labels_text(dict(zip(self.labels, key)))} {number(v)}")
        return out


class Histogram:
    def __init__(self, name: str, help: str, labels: tuple[str, ...], buckets=LATENCY_BUCKETS):
        self.name, self.help, self.labels, self.buckets = name, help, labels, buckets
        self._counts: dict[tuple, list[int]] = {}
        self._sums: dict[tuple, float] = defaultdict(float)

    def observe(self, seconds: float, *values: str) -> None:
        with _lock:
            counts = self._counts.setdefault(values, [0] * (len(self.buckets) + 1))
            for i, b in enumerate(self.buckets):
                if seconds <= b:
                    counts[i] += 1
            counts[-1] += 1  # +Inf, which is also the count
            self._sums[values] += seconds

    def count(self, *values: str) -> int:
        c = self._counts.get(values)
        return c[-1] if c else 0

    def render(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        for key, counts in sorted(self._counts.items()):
            base = dict(zip(self.labels, key))
            for b, c in zip((*self.buckets, math.inf), counts):
                out.append(f"{self.name}_bucket{labels_text({**base, 'le': number(b)})} {c}")
            out.append(f"{self.name}_sum{labels_text(base)} {number(round(self._sums[key], 6))}")
            out.append(f"{self.name}_count{labels_text(base)} {counts[-1]}")
        return out


REQUESTS = Counter("lockstep_http_requests_total", "API requests, by route template, method and status.",
                   ("route", "method", "status"))
REQUEST_SECONDS = Histogram("lockstep_http_request_duration_seconds", "API request latency, by route template.",
                            ("route", "method"))
VAULT_CALLS = Counter("lockstep_vault_requests_total",
                      "Calls Lockstep made to a Vault, by Vault (host:port) and status (0: couldn't reach it).",
                      ("vault", "status"))
VAULT_SECONDS = Histogram("lockstep_vault_request_duration_seconds", "Latency of calls to a Vault, by host.",
                          ("vault",))
SIGNINS = Counter("lockstep_signins_total", "Sign-ins to a Vault through Lockstep, by method and outcome.",
                  ("method", "outcome"))
RATE_LIMITED = Counter("lockstep_rate_limited_total",
                       "Requests refused with 429: by the per-client API limit (api) or the sign-in throttle (signin).",
                       ("limit",))
ALL = (REQUESTS, REQUEST_SECONDS, VAULT_CALLS, VAULT_SECONDS, SIGNINS, RATE_LIMITED)

enabled = False  # set by the app at start-up from LOCKSTEP_METRICS


def vault_call(host: str, status: int, seconds: float) -> None:
    if enabled:
        VAULT_CALLS.inc(host, str(status))
        VAULT_SECONDS.observe(seconds, host)


def signin(method: str, ok: bool) -> None:
    if enabled:
        SIGNINS.inc(method, "success" if ok else "failure")


def rate_limited(limit: str) -> None:
    if enabled:
        RATE_LIMITED.inc(limit)


def render() -> str:
    lines: list[str] = []
    with _lock:
        for m in ALL:
            lines += m.render()
    return "\n".join(lines) + "\n"


def reset() -> None:
    """For tests."""
    with _lock:
        for m in ALL:
            if isinstance(m, Counter):
                m._values.clear()
            else:
                m._counts.clear()
                m._sums.clear()
