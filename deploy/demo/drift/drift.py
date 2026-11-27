"""The public demo's drift check: `lockstep compare` on the seeded pairs every few minutes, and
a static page of the results at /drift/ on the main site.

Runs in the Lockstep image (no shell), as the read-only demo user bob. Each pair is compared
under its shared comparison profile against a baseline recorded right after each hourly reset
of the demo data, so a run goes red only for drift a visitor made since. Nothing here holds or
shows a value: the reports have paths, key names, statuses and reasons.

    /marks/<group>        written by the seed after each reset (SEED_MARKER)
    /data/state/          baselines and 24 hours of results (not served)
    /data/site/           index.html and drift.css, served by Caddy at /drift/

DRIFT_INTERVAL (seconds, default 300) between runs; DRIFT_ONCE=1 runs once and exits (tests).
"""

from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
DATA = Path(os.environ.get("DRIFT_DATA", "/data"))
MARKS = Path(os.environ.get("DRIFT_MARKS", "/marks"))
STATE, SITE = DATA / "state", DATA / "site"
INTERVAL = int(os.environ.get("DRIFT_INTERVAL", "300"))
KEEP = 24 * 3600
WINDOW = 12 * 3600  # the strip on each card: the last 12 hours, a fixed slot per run
TIMEOUT = 120
POLL = 15

VAULTS = ("http://vault-a:8200", "http://vault-b:8200")
BAOS = ("http://openbao-a:8200", "http://openbao-b:8200")
SERVICES, APPS = "Prod ↔ staging services", "Test ↔ dev: apps (ELP rename)"
# What each mount's comparison looks like in Lockstep (README screenshots, served at /images/)
SHOTS = {
    "app-config": ("09-profile", "Compare on Vault A ↔ Vault B, app-config, under “Prod ↔ staging services”: "
                   "each Different, Left only or Right only row is drift, and base.json accepts it."),
    "apps": ("31-rename-compare", "Compare on Vault A ↔ Vault B, apps, under “Test ↔ dev: apps (ELP rename)”: "
             "the renamed paths are paired, and ignored or rewritten keys don't count as drift."),
}
# id, label, mount, profile, (left, right), the seed marker that resets it
PAIRS = [
    ("vault-app-config", "Vault A ↔ Vault B", "app-config", SERVICES, VAULTS, "vault"),
    ("vault-apps", "Vault A ↔ Vault B", "apps", APPS, VAULTS, "vault"),
    ("openbao-app-config", "OpenBao A ↔ OpenBao B", "app-config", SERVICES, BAOS, "openbao"),
    ("openbao-apps", "OpenBao A ↔ OpenBao B", "apps", APPS, BAOS, "openbao"),
]
LABEL = {"clean": "No drift", "known": "Known drift only", "new": "New drift", "error": "Couldn't run",
         "waiting": "Waiting for the demo data"}


def now_iso(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))


def args(pair) -> list[str]:
    _, _, mount, profile, (left, right), _ = pair
    return ["--left-addr", left, "--right-addr", right, "--left-auth", "userpass", "--left-user", "bob",
            "--right-auth", "userpass", "--right-user", "bob", "--mount", mount, "--profile", profile]


def lockstep(*a: str) -> subprocess.CompletedProcess:
    return subprocess.run(["lockstep", *a], capture_output=True, text=True, timeout=TIMEOUT, cwd="/tmp")


def last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:300] if lines else "no output"


_retry_after: dict[str, float] = {}


def refresh_baselines(history: list[dict]) -> None:
    """Record a pair's baseline again once its data has been reset since the last one. After a
    failure, try again only a run interval later, so an unreachable server doesn't fill the log."""
    for pair in PAIRS:
        pid, group = pair[0], pair[5]
        mark, base = MARKS / group, STATE / f"{pid}.baseline.json"
        if not mark.exists() or (base.exists() and base.stat().st_mtime >= mark.stat().st_mtime):
            continue
        if time.time() < _retry_after.get(pid, 0):
            continue
        _retry_after[pid] = time.time() + INTERVAL
        try:
            r = lockstep("baseline", "update", str(base), *args(pair))
        except subprocess.TimeoutExpired:
            print(f"{pid}: recording the baseline timed out", flush=True)
            continue
        if r.returncode == 0:
            history.append({"t": now_iso(), "pair": pid, "event": "baseline"})
            print(f"{pid}: baseline recorded after a reset", flush=True)
        else:
            print(f"{pid}: couldn't record the baseline: {last_line(r.stderr or r.stdout)}", flush=True)


def check(pair) -> dict:
    pid = pair[0]
    base = STATE / f"{pid}.baseline.json"
    rec = {"t": now_iso(), "pair": pid}
    if not base.exists():
        return rec | {"status": "waiting"}
    out = Path("/tmp") / f"{pid}.json"
    start = time.monotonic()
    try:
        r = lockstep("compare", *args(pair), "--baseline", str(base), "--fail-on", "new", "-o", str(out))
    except subprocess.TimeoutExpired:
        return rec | {"status": "error", "error": f"took longer than {TIMEOUT} seconds", "secs": TIMEOUT}
    rec["secs"] = round(time.monotonic() - start, 1)
    if r.returncode not in (0, 1) or not out.exists():
        return rec | {"status": "error", "error": last_line(r.stderr or r.stdout)}
    report = json.loads(out.read_text())
    out.unlink()
    dc = report.get("drift_check") or {}
    items = [{"path": s["path"], "key": k.get("key"), "status": k.get("status") or s["status"], "reason": k.get("reason", "")}
             for s in report.get("secrets", []) for k in (s.get("keys") or [{}])
             if k.get("drift", s.get("drift")) == "new"]
    status = "new" if dc.get("new") else "known" if dc.get("known") else "clean"
    return rec | {"status": status, "new": dc.get("new", 0), "known": dc.get("known", 0),
                  "resolved": len(dc.get("resolved") or []), "summary": report.get("summary", {}), "items": items[:50]}


# --------------------------------------------------------------------------- the page

def ago(t: str) -> str:
    secs = time.time() - datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    return "just now" if secs < 60 else f"{int(secs // 60)} min ago" if secs < 3600 else f"{secs / 3600:.1f} h ago"


RANK = {"waiting": 0, "clean": 1, "known": 2, "new": 3, "error": 4}


def _epoch(t: str) -> float:
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def strip(runs: list[dict], now: float | None = None) -> str:
    """The last 12 hours as fixed slots, one per run interval, oldest on the left: the strip stays
    the same length and slides along. Hovering a slot shows when that run was and what it found."""
    now = time.time() if now is None else now
    step = max(60, INTERVAL)
    n = WINDOW // step
    end = (int(now) // step + 1) * step  # the slot the current run falls in is the last one
    start = end - n * step
    slots: list[dict | None] = [None] * n
    for r in runs:
        i = int((_epoch(r["t"]) - start) // step)
        if 0 <= i < n and (slots[i] is None or RANK[r["status"]] >= RANK[slots[i]["status"]]):
            slots[i] = r
    cells = []
    for i, r in enumerate(slots):
        when = time.strftime("%a %d %b, %H:%M UTC", time.gmtime(_epoch(r["t"]) if r else start + i * step))
        what = "no run" if r is None else LABEL[r["status"]] + (f', {r["new"]} new' if r.get("new") else "")
        edge = " l" if i < n // 6 else " r" if i >= n - n // 6 else ""
        tip = html.escape(f"{when}: {what}", quote=True)
        cells.append(f'<span class="cell {r["status"] if r else "none"}{edge}" title="{tip}" data-tip="{tip}"></span>')
    return (f'<div class="strip" role="img" aria-label="The last 12 hours, one mark per run">{"".join(cells)}</div>'
            '<div class="axis" aria-hidden="true"><span>12 h ago</span><span>6 h ago</span><span>now</span></div>')


def shot(mount: str, open_: bool) -> str:
    """A screenshot of the same comparison in Lockstep's Compare tab, to link the check to what it compares."""
    if mount not in SHOTS:
        return ""
    name, caption = SHOTS[mount]
    return (f'<details class="shot"{" open" if open_ else ""}><summary>See this comparison in Lockstep</summary>'
            f'<figure><a href="/images/{name}-light.png"><picture>'
            f'<source media="(prefers-color-scheme: dark)" srcset="/images/{name}-dark.png">'
            f'<img src="/images/{name}-light.png" alt="{html.escape(caption, quote=True)}" loading="lazy"></picture></a>'
            f'<figcaption>{html.escape(caption)} The check runs the same comparison from the command line.</figcaption>'
            '</figure></details>')


def card(pair, runs: list[dict], events: list[dict], first: bool = False) -> str:
    pid, label, mount, profile = pair[:4]
    e = html.escape
    head = f'<h2>{e(label)} <span class="where">{e(mount)}</span></h2><p class="profile">Profile: {e(profile)}</p>'
    if not runs:
        return f'<section class="pair">{head}<p class="status waiting">No runs yet</p>{shot(mount, first)}</section>'
    last = runs[-1]
    counts = ""
    if last["status"] in ("clean", "known", "new"):
        s = last.get("summary", {})
        counts = (f'<p class="counts">{s.get("total", 0)} secrets: {s.get("equal", 0)} equal, {s.get("different", 0)} different, '
                  f'{s.get("left_only", 0)} left only, {s.get("right_only", 0)} right only. '
                  f'Drift: <strong>{last["new"]} new</strong>, {last["known"]} known'
                  + (f', {last["resolved"]} resolved' if last["resolved"] else "") + ".</p>")
    detail = ""
    if last.get("items"):
        rows = "".join(f'<tr><td class="mono">{e(i["path"])}</td><td class="mono">{e(i["key"] or "")}</td>'
                       f'<td>{e(i["status"].replace("_", " "))}</td><td>{e(i["reason"])}</td></tr>' for i in last["items"])
        detail = ('<table><caption>New since the last reset</caption><thead><tr><th>Secret</th><th>Key</th><th>Status</th>'
                  f'<th>Why</th></tr></thead><tbody>{rows}</tbody></table>')
    elif last["status"] == "error":
        detail = f'<p class="error">{e(last.get("error", ""))}</p>'
    reset = next((ev["t"] for ev in reversed(events) if ev["pair"] == pid), None)
    return (f'<section class="pair {last["status"]}">{head}'
            f'<p class="status {last["status"]}"><span class="dot" aria-hidden="true"></span>{LABEL[last["status"]]}'
            f' <span class="when">· {ago(last["t"])}</span></p>{counts}{strip(runs)}{detail}'
            + (f'<p class="fine">Baseline recorded after the reset at {reset[11:16]} UTC.</p>' if reset else "")
            + baseline_view(pid) + shot(mount, first) + "</section>")


def baseline_view(pid: str) -> str:
    """The pair's baseline file, the base.json the check runs against, to expand on the page and
    download. It holds paths, keys and statuses: no values."""
    try:
        text = (STATE / f"{pid}.baseline.json").read_text()
        accepted = len(json.loads(text).get("drift", []))
    except (OSError, ValueError, AttributeError):
        return ""
    name = f"{pid}.base.json"
    (SITE / f"{name}.tmp").write_text(text)
    os.replace(SITE / f"{name}.tmp", SITE / name)
    return (f'<details class="baseline"><summary>View <code>base.json</code>: {accepted} accepted '
            f'difference{"" if accepted == 1 else "s"}</summary>'
            f'<pre><code>{html.escape(text)}</code></pre>'
            f'<p class="fine"><a href="{name}" download>Download it</a>. Each entry is a path, a key and a status; '
            f'the check exits 1 only for drift that isn\'t listed here.</p></details>')


PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="{refresh}">
  <meta name="robots" content="noindex">
  <title>Drift checks on the demo · Lockstep</title>
  <link rel="icon" href="/icon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/site.css">
  <link rel="stylesheet" href="/drift/drift.css">
</head>
<body>
  <header class="top">
    <div class="wrap top-row">
      <a class="brand" href="/"><span class="mark" aria-hidden="true"><i></i><i></i></span>Lockstep</a>
      <nav aria-label="Main">
        <a href="/docs/">Docs</a>
        <a href="https://github.com/welshstew/lockstep">GitHub</a>
        <a class="btn small" href="https://demo.getlockstep.cloud">Try the demo</a>
      </nav>
    </div>
  </header>
  <main id="main" class="wrap drift">
    <h1>Drift checks on the demo</h1>
    <p class="lede">Every {minutes} minutes, a read-only job runs <code>lockstep compare</code> on the demo's seeded pairs,
    each under its shared comparison profile, against a baseline recorded after the hourly reset. The demo has drift on
    purpose; the baseline accepts it. <strong>Change a value in the <a href="https://demo.getlockstep.cloud">demo</a></strong>
    (sign in as <code>alice</code>, password <code>password</code>) and the next run turns red, naming the key. At the next
    reset it's green again. Values are never shown, here or in the job's reports.</p>
    <div class="pairs">{cards}</div>
    <h2 class="how">What a check compares</h2>
    <figure class="wide">
      <a href="/images/31-rename-compare-light.png"><picture>
        <source media="(prefers-color-scheme: dark)" srcset="/images/31-rename-compare-dark.png">
        <img src="/images/31-rename-compare-light.png" alt="Lockstep's Compare tab: Vault A apps against Vault B apps under the profile Test ↔ dev: apps (ELP rename). Renamed paths are paired; rows are Different, Left only, Right only or Equal, with ignored and rewritten keys marked." loading="lazy">
      </picture></a>
      <figcaption>The <strong>Vault A ↔ Vault B, apps</strong> card's comparison, in Lockstep's Compare tab under the same
      profile. The renamed paths are paired (<code>enterprise-logging-app/…</code> ⇄ <code>ELP/…</code>), and keys the
      profile ignores or rewrites don't count. Each Different, Left only or Right only key is a line in that card's
      <code>base.json</code>: accepted now, so the card stays green until something else changes. Each card has its own
      screenshot under <strong>See this comparison in Lockstep</strong>.</figcaption>
    </figure>
    <h2 class="how">How it runs</h2>
<pre><code>lockstep baseline update base.json --left-addr http://vault-a:8200 --right-addr http://vault-b:8200 \\
    --left-auth userpass --left-user bob --right-auth userpass --right-user bob \\
    --mount app-config --profile "Prod ↔ staging services"      # after each reset: the drift it accepts
lockstep compare … --baseline base.json --fail-on new -o run.json   # every {minutes} minutes: exit 1 on new drift</code></pre>
    <p>Each pair's <code>base.json</code> is under <strong>View base.json</strong> on its card. Commit yours next to
    the pipeline: its diff in a pull request shows which drift was accepted.</p>
    <p>The same check runs in CI (<a href="/guides/detect-vault-secret-drift-in-ci/">guide</a>) or on a schedule in
    Kubernetes (<a href="/docs/drift-monitoring/">drift monitoring</a>).</p>
    <p class="fine">Updated {updated} UTC. This page refreshes itself after each run, every {minutes} minutes. Each card's strip is the last 12 hours, one mark per run: point at one to see when it ran and what it found.</p>
  </main>
</body>
</html>
"""


def render(history: list[dict]) -> None:
    runs = [h for h in history if "status" in h]
    events = [h for h in history if h.get("event") == "baseline"]
    SITE.mkdir(parents=True, exist_ok=True)
    cards = "".join(card(p, [r for r in runs if r["pair"] == p[0]], events) for p in PAIRS)
    shutil.copyfile(HERE / "drift.css", SITE / "drift.css.tmp")
    os.replace(SITE / "drift.css.tmp", SITE / "drift.css")
    page = PAGE.replace("{refresh}", str(max(60, INTERVAL))).replace("{minutes}", str(max(1, INTERVAL // 60))).replace("{cards}", cards).replace("{updated}", now_iso()[:16].replace("T", " "))
    (SITE / "index.tmp").write_text(page)
    os.replace(SITE / "index.tmp", SITE / "index.html")


# --------------------------------------------------------------------------- the loop

def load() -> list[dict]:
    try:
        return json.loads((STATE / "history.json").read_text())
    except (OSError, ValueError):
        return []


def save(history: list[dict]) -> list[dict]:
    cutoff = now_iso(time.time() - KEEP)
    history = [h for h in history if h["t"] >= cutoff]
    (STATE / "history.tmp").write_text(json.dumps(history))
    os.replace(STATE / "history.tmp", STATE / "history.json")
    return history


def main() -> int:
    STATE.mkdir(parents=True, exist_ok=True)
    history = load()
    next_run = 0.0
    while True:
        refresh_baselines(history)
        if time.time() >= next_run:
            next_run = time.time() + INTERVAL
            for pair in PAIRS:
                rec = check(pair)
                history.append(rec)
                if rec["status"] in ("new", "error"):
                    print(f'{rec["pair"]}: {LABEL[rec["status"]]} {rec.get("new", "")} {rec.get("error", "")}'.rstrip(), flush=True)
            history = save(history)
            render(history)
        if os.environ.get("DRIFT_ONCE"):
            return 0
        time.sleep(POLL)


if __name__ == "__main__":
    sys.exit(main())
