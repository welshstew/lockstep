#!/usr/bin/env python3
"""Read every scanner report in reports/, apply the gate, write summary.md, exit 1 on failure.

The gate lives here rather than in each tool's exit code, so local and CI runs
fail on exactly the same findings.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

GATE_SEV = {"HIGH", "CRITICAL"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


@dataclass
class Finding:
    id: str
    severity: str
    where: str  # package@version or file:line
    fix: str = ""
    title: str = ""
    gating: bool = False


@dataclass
class Section:
    name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    note: str = ""

    @property
    def failed(self) -> bool:
        return self.error is not None or any(f.gating for f in self.findings)


def load(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"{path.name} missing: the scanner did not run or failed")
    text = path.read_text().strip()
    return json.loads(text) if text else None


def trivy(path: Path, name: str) -> Section:
    sec = Section(name)
    try:
        data = load(path) or {}
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    if name.startswith("Trivy image") and (data.get("Metadata") or {}).get("OS", {}).get("Family") in (None, "", "none"):
        sec.note = ("Trivy did not detect the image OS (Hummingbird / Red Hat Hardened Images are not "
                    "supported yet), so it covers language packages only. Grype covers the OS packages.")
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN")
            fix = v.get("FixedVersion") or ""
            sec.findings.append(Finding(
                id=v["VulnerabilityID"], severity=sev,
                where=f"{v['PkgName']}@{v.get('InstalledVersion', '?')} ({res.get('Target')})",
                fix=fix, title=(v.get("Title") or "")[:90], gating=sev in GATE_SEV and bool(fix)))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            sev = m.get("Severity", "UNKNOWN")
            sec.findings.append(Finding(
                id=m.get("AVDID") or m.get("ID", "?"), severity=sev, where=res.get("Target", "?"),
                fix=(m.get("Resolution") or "")[:80], title=m.get("Title", ""), gating=sev in GATE_SEV))
    return sec


def grype(path: Path) -> Section:
    sec = Section("Grype image (app)")
    try:
        data = load(path) or {}
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    distro = data.get("distro") or {}
    if not distro.get("name"):
        # Without a detected OS, OS packages are silently unscanned: treat as a failure.
        sec.error = "Grype did not detect the image OS, so OS packages were not scanned"
        return sec
    sec.note = f"OS detected: {distro.get('name')} {distro.get('version', '')}".strip()
    seen = set()
    for m in data.get("matches") or []:
        v, a = m["vulnerability"], m["artifact"]
        key = (v["id"], a["name"], a["version"])
        if key in seen:
            continue
        seen.add(key)
        sev = (v.get("severity") or "Unknown").upper()
        sev = sev if sev in SEV_ORDER else "UNKNOWN"
        fix = v.get("fix") or {}
        fixed = fix.get("state") == "fixed" and bool(fix.get("versions"))
        cve = next((r["id"] for r in m.get("relatedVulnerabilities") or [] if r["id"].startswith("CVE-") and r["id"] != v["id"]), "")
        sec.findings.append(Finding(
            id=v["id"] + (f" / {cve}" if cve else ""), severity=sev,
            where=f"{a['name']}@{a['version']} ({a.get('type')})",
            fix=", ".join(fix.get("versions") or []) if fixed else f"({fix.get('state', 'unknown')})",
            title=(v.get("description") or "")[:90].replace("\n", " "),
            gating=sev in GATE_SEV and fixed))
    return sec


def cosign(path: Path) -> Section:
    sec = Section("cosign (base image signatures)", note="Gate: every Red Hat Hardened Image referenced must verify against Red Hat's key.")
    try:
        data = load(path) or []
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    if not data:
        sec.error = "no Red Hat Hardened Image references found to verify"
    for d in data:
        if not d["verified"]:
            sec.findings.append(Finding(id="signature", severity="HIGH", where=d["image"],
                                        title="signature verification FAILED", gating=True))
    sec.note += f" Verified {sum(d['verified'] for d in data)}/{len(data)}."
    return sec


def chart(sec: Section) -> Section:
    """A chart scan that found nothing to scan means the chart failed to render: an error."""
    if sec.error is None:
        try:
            data = load(Path("reports") / ("trivy-chart-minimal.json" if "minimal" in sec.name else "trivy-chart-full.json")) or {}
        except Exception:  # noqa: BLE001
            data = {}
        if not any(r.get("Class") == "config" for r in data.get("Results") or []):
            sec.error = "Trivy rendered no Kubernetes objects from the chart (it may have failed to render)"
    return sec


def pip_audit(path: Path) -> Section:
    sec = Section("pip-audit (backend)", note="pip-audit has no severities; any vulnerability with a fix version fails the gate.")
    try:
        data = load(path) or {}
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    for dep in data.get("dependencies") or []:
        for v in dep.get("vulns") or []:
            fixes = v.get("fix_versions") or []
            alias = next((a for a in v.get("aliases") or [] if a.startswith("CVE-")), "")
            sec.findings.append(Finding(
                id=v["id"] + (f" / {alias}" if alias else ""), severity="UNKNOWN",
                where=f"{dep['name']}@{dep['version']}", fix=", ".join(fixes),
                title=(v.get("description") or "")[:90], gating=bool(fixes)))
    return sec


def npm_audit(full: Path, prod: Path) -> Section:
    sec = Section("npm audit (frontend)", note="Gate: HIGH/CRITICAL in production dependencies with a fix. Dev-only findings are listed for information.")
    try:
        data = load(full) or {}
        prod_names = set(((load(prod) or {}).get("vulnerabilities") or {}).keys())
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    if "error" in data:
        sec.error = json.dumps(data["error"])[:200]
        return sec
    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = (v.get("severity") or "unknown").upper()
        sev = "MEDIUM" if sev == "MODERATE" else sev
        fa = v.get("fixAvailable")
        fix = (f"{fa.get('name')}@{fa.get('version')}" if isinstance(fa, dict) else "yes" if fa else "")
        advisories = [x for x in v.get("via") or [] if isinstance(x, dict)]
        ids = ", ".join(sorted({(a.get("url") or "").rsplit("/", 1)[-1] for a in advisories} - {""})) or name
        in_prod = name in prod_names
        sec.findings.append(Finding(
            id=ids, severity=sev, where=f"{name} {v.get('range', '')}" + ("" if in_prod else " (dev)"),
            fix=fix, title=(advisories[0].get("title", "") if advisories else "via " + ", ".join(map(str, v.get("via") or [])))[:90],
            gating=in_prod and sev in GATE_SEV and bool(fa)))
    return sec


def bandit(path: Path) -> Section:
    sec = Section("bandit (Python SAST)", note="Gate: HIGH severity with MEDIUM or HIGH confidence.")
    try:
        data = load(path) or {}
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    for r in data.get("results") or []:
        sev, conf = r["issue_severity"], r["issue_confidence"]
        sec.findings.append(Finding(
            id=f"{r['test_id']} ({r['test_name']})", severity=sev,
            where=f"{r['filename']}:{r['line_number']}", title=f"[{conf} confidence] {r['issue_text']}"[:110],
            gating=sev == "HIGH" and conf in ("MEDIUM", "HIGH")))
    return sec


def gitleaks(path: Path) -> Section:
    sec = Section("gitleaks (git history)", note="Gate: any finding. Values are redacted.")
    try:
        data = load(path) or []
    except Exception as e:  # noqa: BLE001
        sec.error = str(e)
        return sec
    for f in data:
        sec.findings.append(Finding(
            id=f["RuleID"], severity="HIGH", where=f"{f['File']}:{f['StartLine']} @ {f['Commit'][:8]}",
            title=f.get("Description", ""), gating=True))
    return sec


def counts(sec: Section) -> str:
    c = {s: 0 for s in SEV_ORDER}
    for f in sec.findings:
        c[f.severity if f.severity in c else "UNKNOWN"] += 1
    return " · ".join(f"{s.title()} {n}" for s, n in c.items() if n) or "none"


def grype_allowlist(path: Path) -> Section:
    """Enforce expiry on .grype.yaml entries (Grype itself has no expiry field)."""
    import datetime as dt
    import re
    sec = Section("Grype allowlist expiry", note="Gate: every .grype.yaml entry needs 'until YYYY-MM-DD' in its reason, still in the future.")
    if not path.exists():
        return sec
    entries = re.split(r"\n\s*-\s+vulnerability:", "\n" + path.read_text().split("ignore:", 1)[-1])[1:]
    today = dt.date.today()
    for e in entries:
        vid = e.split()[0]
        m = re.search(r"until (\d{4}-\d{2}-\d{2})", e)
        if not m:
            sec.findings.append(Finding(id=vid, severity="HIGH", where=".grype.yaml", title="allowlist entry has no 'until YYYY-MM-DD'", gating=True))
            continue
        until = dt.date.fromisoformat(m.group(1))
        expired = until < today
        sec.findings.append(Finding(id=vid, severity="HIGH" if expired else "LOW", where=".grype.yaml",
                                    fix=f"until {until}", title="EXPIRED: review or remove" if expired else "accepted (time-boxed)",
                                    gating=expired))
    return sec


def main(rdir: str) -> int:
    r = Path(rdir)
    sections = [
        cosign(r / "cosign.json"),
        grype(r / "grype-image.json"),
        grype_allowlist(Path(".grype.yaml")),
        trivy(r / "trivy-image.json", "Trivy image (app)"),
        trivy(r / "trivy-fs.json", "Trivy filesystem"),
        trivy(r / "trivy-dev.json", "Trivy dev/ tooling"),
        chart(trivy(r / "trivy-chart-minimal.json", "Trivy Helm chart (minimal values)")),
        chart(trivy(r / "trivy-chart-full.json", "Trivy Helm chart (all options on)")),
        pip_audit(r / "pip-audit.json"),
        npm_audit(r / "npm-audit.json", r / "npm-audit-prod.json"),
        bandit(r / "bandit.json"),
        gitleaks(r / "gitleaks.json"),
    ]
    out = ["# Security scan summary", "",
           "| Scanner | Result | Findings | Gating |", "|---|---|---|---|"]
    for s in sections:
        status = "⚠️ error" if s.error else ("❌ fail" if s.failed else "✅ pass")
        out.append(f"| {s.name} | {status} | {counts(s)} | {sum(f.gating for f in s.findings)} |")
    for s in sections:
        out += ["", f"## {s.name}"]
        if s.note:
            out.append(f"_{s.note}_")
        if s.error:
            out.append(f"\n**Error:** {s.error}")
            continue
        if not s.findings:
            out.append("\nNo findings.")
            continue
        out += ["", "| Gate | Severity | ID | Where | Fix | Title |", "|---|---|---|---|---|---|"]
        for f in sorted(s.findings, key=lambda f: (not f.gating, SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 9, f.id)):
            out.append(f"| {'❌' if f.gating else ''} | {f.severity} | {f.id} | {f.where} | {f.fix} | {f.title.replace('|', '/')} |")
    text = "\n".join(out) + "\n"
    (r / "summary.md").write_text(text)
    print(text)
    failed = [s.name for s in sections if s.failed]
    print(f"GATE: {'FAIL (' + ', '.join(failed) + ')' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "reports"))
