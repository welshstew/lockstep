"""Push a drift check's gauges to a Prometheus Pushgateway.

The grouping key is the job plus the check's labels (left, right, mount, prefix), so several
checks pushing to one Pushgateway don't overwrite each other. A successful run replaces its
group (PUT); a failed one only updates `lockstep_compare_success` and the duration (POST), so
the last drift counts and `lockstep_compare_last_success_timestamp_seconds` stay for alerts.
"""

from __future__ import annotations

import base64

import httpx

from .connect import CliError


def _segment(name: str, value: str) -> str:
    # base64 form: label values may hold slashes, and an empty value is written "="
    return f"{name}@base64/{base64.urlsafe_b64encode(value.encode()).decode() or '='}"


def group_url(base: str, job: str, labels: dict[str, str]) -> str:
    parts = [_segment("job", job), *(_segment(k, v) for k, v in labels.items())]
    return base.rstrip("/") + "/metrics/" + "/".join(parts)


def push(base: str, job: str, labels: dict[str, str], body: str, replace: bool = True,
         transport: httpx.BaseTransport | None = None) -> None:
    url = group_url(base, job, labels)
    try:
        with httpx.Client(timeout=15, transport=transport) as c:
            r = c.request("PUT" if replace else "POST", url, content=body.encode(),
                          headers={"Content-Type": "text/plain; version=0.0.4"})
    except httpx.HTTPError as e:
        raise CliError(f"Couldn't push metrics to {httpx.URL(base).host}: {e.__class__.__name__}: {e}") from e
    if r.status_code >= 300:
        raise CliError(f"The Pushgateway answered {r.status_code}: {r.text.strip()[:200]}")
