"""The compare report in formats other tools read: SARIF, JUnit, Markdown and CSV.

Like the YAML report, none of them holds a value: paths, key names, statuses and reasons only.
Only the YAML and JSON reports can be handed to `lockstep apply`.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import xml.etree.ElementTree as ET
from importlib.metadata import PackageNotFoundError, version

from . import report as report_mod
from .. import metrics as prom
from .drift import DRIFT, Outcome, pairs as rows

FORMATS = ("yaml", "json", "sarif", "junit", "markdown", "csv", "prometheus")
_BY_SUFFIX = {".yaml": "yaml", ".yml": "yaml", ".json": "json", ".sarif": "sarif", ".xml": "junit",
              ".md": "markdown", ".markdown": "markdown", ".csv": "csv",
              ".prom": "prometheus"}
STATUS = {"different": "different", "left_only": "left only", "right_only": "right only",
          "not_compared": "not compared"}
RULES = {
    "different": "The secret or key has different values on the two sides.",
    "left_only": "The secret or key exists only on the left side.",
    "right_only": "The secret or key exists only on the right side.",
    "not_compared": "The key couldn't be compared, e.g. a keystore whose password isn't in the secret.",
}
MARKDOWN_ROWS = 200  # a PR comment holds about 65,000 characters


def format_for(filename: str, given: str | None) -> str:
    if given:
        return given
    for suffix, fmt in _BY_SUFFIX.items():
        if filename.lower().endswith(suffix):
            return fmt
    return "yaml"


def _version() -> str:
    try:
        return version("lockstep")
    except PackageNotFoundError:
        return "unknown"


def _status(s, k) -> str:
    return (k or s).status


def _reason(s, k) -> str:
    if k is not None:
        return k.reason or ", ".join(k.paths)
    return s.note or ""


def _where(rep: report_mod.Report) -> str:
    def side(x: report_mod.ReportSide) -> str:
        return f"{x.name} {x.mount}" + (f"/{x.prefix}" if x.prefix else "")
    return f"{side(rep.left)} → {side(rep.right)}"


def _message(s, k) -> str:
    what = f"{s.path}" + (f" key {k.key}" if k is not None else "")
    reason = _reason(s, k)
    return f"{what}: {STATUS[_status(s, k)]}" + (f" ({reason})" if reason else "")


# --------------------------------------------------------------------------- SARIF


def sarif(rep: report_mod.Report, o: Outcome) -> str:
    """SARIF 2.1.0, for GitHub code scanning and other SARIF viewers. Drift that fails the run is
    an error; accepted drift (in the baseline) a note; waived drift is suppressed with the reason."""
    rule_ids = {st: f"drift/{st.replace('_', '-')}" for st in RULES}
    run_id = f"lockstep/{rep.left.mount}/{rep.left.prefix}:{rep.right.mount}/{rep.right.prefix}"
    results = []
    for s, k in rows(rep):
        key = k.key if k is not None else None
        state = o.state(s.path, key)
        fp = hashlib.sha256(json.dumps([run_id, s.path, key]).encode()).hexdigest()
        r = {
            "ruleId": rule_ids[_status(s, k)],
            "level": "error" if o.fails(s.path, key) else "note",
            "message": {"text": _message(s, k)},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f"{rep.right.mount}/{s.right.path}",
                                                          "uriBaseId": "VAULT"}},
                "logicalLocations": [{"fullyQualifiedName": s.path + (f"#{key}" if key is not None else ""),
                                      "kind": "member" if key is not None else "object"}],
            }],
            "partialFingerprints": {"lockstepFinding/v1": fp},
        }
        if o.baseline is not None:
            r["baselineState"] = "unchanged" if state == "known" else "new"
        if state == "waived":
            w = next(w for w in o.waivers_for(s.path, key))
            r["suppressions"] = [{"kind": "external", "status": "accepted",
                                  "justification": f"{w.reason} (owner {w.owner}, until {w.expires})"}]
        results.append(r)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Lockstep", "version": _version(), "informationUri": "https://getlockstep.cloud",
                "rules": [{"id": rule_ids[st], "name": st, "shortDescription": {"text": text},
                           "defaultConfiguration": {"level": "error"}} for st, text in RULES.items()],
            }},
            "automationDetails": {"id": run_id + "/"},
            "originalUriBaseIds": {"VAULT": {"description": {"text": f"The right side, {rep.right.name} "
                                                                     f"({rep.right.addr})"}}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- JUnit


def junit(rep: report_mod.Report, o: Outcome) -> str:
    """JUnit XML, for any CI's test tab: one test case per secret in the report. Drift that fails
    the run is a failure; accepted or waived drift is skipped with why."""
    by_secret: dict[str, list] = {}
    for s, k in rows(rep):
        by_secret.setdefault(s.path, []).append((s, k))
    name = f"lockstep compare {_where(rep)}"
    suite = ET.Element("testsuite", name=name, timestamp=rep.created)
    counts = {"tests": 0, "failures": 0, "skipped": 0, "errors": 0}
    for s in rep.secrets:
        counts["tests"] += 1
        case = ET.SubElement(suite, "testcase", classname=f"{rep.left.name} → {rep.right.name}", name=s.path)
        found = by_secret.get(s.path, [])
        failing = [(x, k) for x, k in found if o.fails(x.path, k.key if k else None)]
        if failing:
            counts["failures"] += 1
            el = ET.SubElement(case, "failure", message=_message(*failing[0]),
                               type=_status(*failing[0]))
            el.text = "\n".join(_message(x, k) for x, k in failing)
        elif found:
            counts["skipped"] += 1
            states = {o.state(x.path, k.key if k else None) for x, k in found}
            why = "waived" if states == {"waived"} else "accepted in the baseline"
            ET.SubElement(case, "skipped", message=f"{why}: " + "; ".join(_message(x, k) for x, k in found))
        elif s.status in ("no_access", "error"):
            counts["skipped"] += 1
            ET.SubElement(case, "skipped", message=f"couldn't compare: {s.note or s.status.replace('_', ' ')}")
    for k, v in counts.items():
        suite.set(k, str(v))
    root = ET.Element("testsuites", name="lockstep", tests=str(counts["tests"]),
                      failures=str(counts["failures"]), skipped=str(counts["skipped"]), errors="0")
    root.append(suite)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


# --------------------------------------------------------------------------- Markdown


def _md(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _code(text: str) -> str:
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def markdown(rep: report_mod.Report, o: Outcome) -> str:
    """A summary for a pull request comment."""
    sm = rep.summary
    failed = o.failed
    lines = [f"### Lockstep: {'drift found' if failed else 'no new drift' if o.baseline else 'no drift'}", "",
             f"{_md(_where(rep))}" + (f", profile {_code(rep.profile)}" if rep.profile else ""), ""]
    counts = ", ".join(f"{sm[k]} {STATUS.get(k, k.replace('_', ' '))}" for k in
                       ("equal", "different", "left_only", "right_only", "not_compared", "no_access", "error")
                       if sm.get(k))
    lines.append(f"{sm.get('total', 0)} secrets: {counts or 'none found'}.")
    if o.baseline is not None or o.waived:
        parts = [f"**{len(o.new)} new**"]
        if o.baseline is not None:
            parts.append(f"{len(o.known)} known (in the baseline)")
        if o.waived:
            parts.append(f"{len(o.waived)} waived")
        if o.baseline is not None:
            parts.append(f"{len(o.resolved)} resolved")
        lines.append("Drift: " + ", ".join(parts) + ".")
    found = rows(rep)
    if found:
        state_label = {"new": "**new**", "known": "known", "waived": "waived"}
        lines += ["", "| | Secret | Key | Status | Why |", "|---|---|---|---|---|"]
        order = {"new": 0, "known": 1, "waived": 2}
        found.sort(key=lambda r: (order.get(o.state(r[0].path, r[1].key if r[1] else None) or "new", 0),
                                  r[0].path))
        for s, k in found[:MARKDOWN_ROWS]:
            st = o.state(s.path, k.key if k else None) or "new"
            lines.append(f"| {state_label[st]} | {_code(s.path)} | {_code(k.key) if k else ''} | "
                         f"{STATUS[_status(s, k)]} | {_md(_reason(s, k))} |")
        if len(found) > MARKDOWN_ROWS:
            lines.append(f"\nand {len(found) - MARKDOWN_ROWS} more; see the full report.")
    if o.resolved:
        lines += ["", "Resolved since the baseline: "
                  + ", ".join(_code(f.label()) for f in o.resolved[:50])
                  + (f" and {len(o.resolved) - 50} more" if len(o.resolved) > 50 else "") + "."]
    for w in o.expired:
        lines += ["", f"**Expired waiver:** {_code(w.label())}, owner {_md(w.owner)}, expired {w.expires}."]
    for w in rep.warnings:
        lines += ["", f"Warning: {_md(w)}"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- CSV


def _cell(text: str) -> str:
    """Keep spreadsheets from running a cell as a formula."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def csv_(rep: report_mod.Report, o: Outcome) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["secret", "key", "status", "drift", "reason", "left_path", "right_path"])
    for s, k in rows(rep):
        key = k.key if k else None
        w.writerow([_cell(x) for x in (s.path, key or "", _status(s, k), o.state(s.path, key) or "new",
                                       _reason(s, k), s.left.path, s.right.path)])
    return buf.getvalue()


# --------------------------------------------------------------------------- Prometheus


def metric_labels(left: report_mod.ReportSide, right: report_mod.ReportSide) -> dict[str, str]:
    """What tells one drift check from another: the two sides' names, the mount and the prefix
    (written `left → right` when they differ)."""
    def both(a: str, b: str) -> str:
        return a if a == b else f"{a} → {b}"
    return {"left": left.name, "right": right.name, "mount": both(left.mount, right.mount),
            "prefix": both(left.prefix, right.prefix)}


def _gauges(rows_: list[tuple[str, str, dict[str, str], float]], labels: dict[str, str]) -> str:
    out, seen = [], set()
    for name, help_, extra, value in rows_:
        if name not in seen:
            out += [f"# HELP {name} {help_}", f"# TYPE {name} gauge"]
            seen.add(name)
        out.append(f"{name}{prom.labels_text({**labels, **extra})} {prom.number(value)}")
    return "\n".join(out) + "\n"


def prometheus(rep: report_mod.Report, o: Outcome, seconds: float | None = None, labels: bool = True,
               now: float | None = None) -> str:
    """Gauges for a successful run, in the Prometheus text format: for the Pushgateway, or a
    node_exporter textfile. `labels=False` leaves out the labels a Pushgateway push puts in its
    grouping key."""
    import time
    base = metric_labels(rep.left, rep.right) if labels else {}
    counts = {st: 0 for st in DRIFT}
    for s, k in rows(rep):
        counts[(k or s).status] += 1
    g = [("lockstep_drift_keys", "Differences found by the last comparison, by status (a key, or a secret "
          "on one side only).", {"status": st}, n) for st, n in counts.items()]
    g += [
        ("lockstep_drift_new_keys", "Differences that fail the drift check: not in the baseline and not waived.",
         {}, len(o.new)),
        ("lockstep_drift_check_failed", "1 when the last comparison failed the drift check (exit code 1).", {},
         int(o.failed)),
        ("lockstep_compare_success", "1 when the last comparison ran, 0 when it couldn't (exit code 2).", {}, 1),
        ("lockstep_compare_last_success_timestamp_seconds", "When a comparison last ran (Unix time).", {},
         round(now or time.time())),
    ]
    if seconds is not None:
        g.append(("lockstep_compare_duration_seconds", "How long the last comparison took.", {}, round(seconds, 3)))
    return _gauges(g, base)


def prometheus_failure(seconds: float, labels: dict[str, str] | None = None) -> str:
    """Only the gauges a failed run changes, so a Pushgateway keeps the last drift counts."""
    return _gauges([
        ("lockstep_compare_success", "1 when the last comparison ran, 0 when it couldn't (exit code 2).", {}, 0),
        ("lockstep_compare_duration_seconds", "How long the last comparison took.", {}, round(seconds, 3)),
    ], labels or {})


def render(rep: report_mod.Report, o: Outcome, fmt: str, filename: str, seconds: float | None = None) -> str:
    if fmt == "yaml":
        return report_mod.dump(rep, filename)
    if fmt == "json":
        return json.dumps(report_mod.as_data(rep), indent=2, ensure_ascii=False) + "\n"
    if fmt == "prometheus":
        return prometheus(rep, o, seconds)
    return {"sarif": sarif, "junit": junit, "markdown": markdown, "csv": csv_}[fmt](rep, o)
