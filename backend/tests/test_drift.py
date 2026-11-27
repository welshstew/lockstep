"""Drift checks: baselines, --fail-on, waivers and the report formats (no Vault needed)."""

import csv
import datetime as dt
import io
import json
import xml.etree.ElementTree as ET

import pytest
import yaml

from lockstep.cli import drift, formats
from lockstep.cli import report as rpt
from lockstep.cli.connect import CliError

TODAY = dt.date(2026, 11, 26)


def side(path):
    return {"path": f"pre/{path}", "state": "present", "version": 1}


def report(*secrets, prefix="pre") -> rpt.Report:
    return rpt.Report.model_validate({
        "lockstep_report": 1, "created": "2026-11-26T00:00:00Z",
        "left": {"name": "prod", "addr": "http://a", "mount": "m", "prefix": prefix},
        "right": {"name": "stage", "addr": "http://b", "mount": "m", "prefix": prefix},
        "summary": {"total": len(secrets)},
        "secrets": list(secrets)})


def secret(path, status="different", keys=(), **kw):
    return {"path": path, "status": status, "left": side(path), "right": side(path),
            "keys": [{"key": k, "status": st, **extra} for k, st, extra in keys], **kw}


DB = secret("db", keys=[("password", "different", {"reason": "different value"}),
                        ("log", "different", {"ignored": True})])
QUEUE = secret("queue", "left_only")
STORE = secret("ks", "not_compared", keys=[("store", "not_compared", {"reason": "PKCS#12 keystore with a password"})])
EQ = secret("eq", "equal")


def test_findings_name_keys_or_the_whole_secret():
    fs = drift.findings(report(DB, QUEUE, STORE, EQ, secret("na", "no_access")))
    assert [(f.path, f.key, f.status) for f in fs] == [
        ("db", "password", "different"), ("ks", "store", "not_compared"), ("queue", None, "left_only")]


def test_without_a_baseline_any_drift_fails():
    o = drift.check(report(DB), "any", today=TODAY)
    assert o.failed and [f.key for f in o.new] == ["password"]
    assert not drift.check(report(EQ), "any", today=TODAY).failed


def test_baseline_known_new_and_resolved():
    base = drift.baseline_of(report(DB, QUEUE))
    now = report(DB, STORE)  # queue fixed, keystore new
    o = drift.check(now, "new", base, "drift.json", today=TODAY)
    assert [f.path for f in o.known] == ["db"] and [f.path for f in o.new] == ["ks"]
    assert [f.path for f in o.resolved] == ["queue"]
    assert o.failed
    assert not drift.check(report(DB), "new", base, "drift.json", today=TODAY).failed  # only resolved
    assert drift.check(report(DB), "changed", base, "drift.json", today=TODAY).failed
    assert drift.check(report(DB, QUEUE), "any", base, "drift.json", today=TODAY).failed


def test_a_changed_status_is_new():
    base = drift.baseline_of(report(QUEUE))
    o = drift.check(report(secret("queue", "right_only")), "new", base, "b", today=TODAY)
    assert o.failed and o.new[0].status == "right_only" and not o.known


def test_waivers(tmp_path):
    f = tmp_path / "waivers.yaml"
    f.write_text(yaml.safe_dump({"waivers": [
        {"path": "d*", "key": "password", "owner": "team-db", "reason": "rotated per env", "expires": "2027-01-01"},
        {"path": "gone", "owner": "x", "reason": "y", "expires": "2027-01-01"}]}))
    ws = drift.load_waivers(str(f))
    o = drift.check(report(DB), "any", waivers=ws, today=TODAY)
    assert not o.failed and [x.key for x in o.waived] == ["password"]
    assert [w.path for w in o.unused] == ["gone"]
    o = drift.check(report(DB), "any", waivers=ws, today=dt.date(2027, 1, 2))
    assert o.failed and len(o.expired) == 2 and o.new  # expired: no longer waives, and fails the run
    assert any("expired on 2027-01-01" in line for line in drift.summary_lines(o))


def test_waivers_file_mistakes(tmp_path):
    f = tmp_path / "w.yaml"
    f.write_text(yaml.safe_dump([{"path": "a", "owner": "o", "expires": "soon"}]))
    with pytest.raises(CliError) as e:
        drift.load_waivers(str(f))
    assert "waiver 1" in str(e.value) and "reason" in str(e.value) and "expires" in str(e.value)


def test_baseline_file_round_trip_and_reports(tmp_path):
    base = drift.baseline_of(report(DB, QUEUE))
    text = drift.dump_baseline(base)
    assert "different value" not in text and '"password"' in text  # statuses only
    p = tmp_path / "drift.json"
    p.write_text(text)
    assert drift.load_baseline(str(p)).drift == base.drift
    r = tmp_path / "report.yaml"
    r.write_text(rpt.dump(report(DB, QUEUE), "report.yaml"))
    assert drift.load_baseline(str(r)).drift == base.drift  # a report works as a baseline
    with pytest.raises(CliError, match="lockstep baseline update"):
        drift.load_baseline(str(tmp_path / "missing.json"))


def test_a_baseline_for_other_locations_is_refused():
    base = drift.baseline_of(report(DB, prefix="other"))
    with pytest.raises(CliError, match="baseline"):
        drift.check_matches(base, report(DB), "drift.json")


def _outcome(rep, base=None, waivers=None, fail_on="new"):
    o = drift.check(rep, fail_on if base else "any", base, "drift.json" if base else None, waivers, today=TODAY)
    drift.annotate(rep, o)
    return o


def test_yaml_and_json_reports_carry_drift_states_and_still_load():
    rep = report(DB, QUEUE)
    _outcome(rep, drift.baseline_of(report(QUEUE)))
    y = rpt.dump(rep, "r.yaml")
    assert "drift: new" in y and "drift: known" in y and "fail_on: new" in y
    again = rpt.load(y, "r.yaml")
    assert again.drift_check.new == 1 and again.secrets[0].keys[0].drift == "new"
    j = json.loads(formats.render(rep, drift.check(rep, "any", today=TODAY), "json", "r.json"))
    assert j["drift_check"]["failed"] is True
    assert rpt.load(json.dumps(j), "r.json").secrets[1].drift == "known"  # apply reads JSON reports


def test_sarif():
    rep = report(DB, QUEUE, STORE)
    w = drift.Waiver(path="ks", owner="sec", reason="password kept elsewhere", expires="2027-01-01")
    o = _outcome(rep, drift.baseline_of(report(QUEUE)), [w])
    doc = json.loads(formats.sarif(rep, o))
    assert doc["version"] == "2.1.0"
    res = {r["logicalLocations"][0]["fullyQualifiedName"] if "logicalLocations" in r else None: r
           for r in (x | {"logicalLocations": x["locations"][0]["logicalLocations"]} for x in doc["runs"][0]["results"])}
    assert res["db#password"]["level"] == "error" and res["db#password"]["baselineState"] == "new"
    assert res["db#password"]["ruleId"] == "drift/different"
    assert res["queue"]["level"] == "note" and res["queue"]["baselineState"] == "unchanged"
    assert res["ks#store"]["suppressions"][0]["justification"].startswith("password kept elsewhere")
    assert res["db#password"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "m/pre/db"
    assert len({r["partialFingerprints"]["lockstepFinding/v1"] for r in res.values()}) == 3


def test_junit():
    rep = report(DB, QUEUE, EQ, secret("na", "no_access", note="permission denied"))
    o = _outcome(rep, drift.baseline_of(report(QUEUE)))
    root = ET.fromstring(formats.junit(rep, o))
    suite = root.find("testsuite")
    assert (suite.get("tests"), suite.get("failures"), suite.get("skipped")) == ("4", "1", "2")
    cases = {c.get("name"): c for c in suite.iter("testcase")}
    assert "password" in cases["db"].find("failure").get("message")
    assert cases["queue"].find("skipped").get("message").startswith("accepted in the baseline")
    assert cases["eq"].find("failure") is None and cases["eq"].find("skipped") is None
    assert "permission denied" in cases["na"].find("skipped").get("message")


def test_markdown_escapes_and_orders_new_first():
    rep = report(QUEUE, secret("a|b", keys=[("k<x>", "different", {"reason": "different at `x|y`"})]))
    o = _outcome(rep, drift.baseline_of(report(QUEUE)))
    md = formats.markdown(rep, o)
    assert md.startswith("### Lockstep: drift found")
    assert "**1 new**, 1 known (in the baseline), 0 resolved" in md
    rows = [line for line in md.splitlines() if line.startswith("| **new**") or line.startswith("| known")]
    assert rows[0].startswith("| **new** | `a\\|b` | `k<x>`") and "different at `x\\|y`" in rows[0]
    assert rows[1].startswith("| known | `queue`")


def test_csv_neutralises_formulas():
    rep = report(secret("=cmd", keys=[("@k", "different", {"reason": "-1"})]))
    out = list(csv.reader(io.StringIO(formats.csv_(rep, _outcome(rep)))))
    assert out[0][:4] == ["secret", "key", "status", "drift"]
    assert out[1][:5] == ["'=cmd", "'@k", "different", "new", "'-1"]


def test_format_follows_the_extension():
    assert formats.format_for("r.sarif", None) == "sarif" and formats.format_for("t.xml", None) == "junit"
    assert formats.format_for("x.MD", None) == "markdown" and formats.format_for("-", None) == "yaml"
    assert formats.format_for("r.sarif", "csv") == "csv"


def test_prometheus_gauges():
    rep = report(DB, QUEUE, STORE)
    o = _outcome(rep, drift.baseline_of(report(QUEUE)))
    text = formats.prometheus(rep, o, seconds=1.25, now=1_800_000_000)
    lab = 'left="prod",right="stage",mount="m",prefix="pre"'
    assert f'lockstep_drift_keys{{{lab},status="different"}} 1' in text
    assert f'lockstep_drift_keys{{{lab},status="left_only"}} 1' in text
    assert f'lockstep_drift_keys{{{lab},status="right_only"}} 0' in text
    assert f"lockstep_drift_new_keys{{{lab}}} 2" in text and f"lockstep_drift_check_failed{{{lab}}} 1" in text
    assert f"lockstep_compare_success{{{lab}}} 1" in text and f"lockstep_compare_duration_seconds{{{lab}}} 1.25" in text
    assert f"lockstep_compare_last_success_timestamp_seconds{{{lab}}} 1800000000" in text
    assert text.count("# TYPE lockstep_drift_keys gauge") == 1
    bare = formats.prometheus(rep, o, labels=False)
    assert 'lockstep_drift_keys{status="different"} 1' in bare and "lockstep_compare_success 1" in bare
    assert formats.format_for("drift.prom", None) == "prometheus"


def test_pushgateway_grouping_and_methods():
    import base64

    import httpx

    from lockstep.cli import pushgateway

    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, req.content.decode()))
        return httpx.Response(200)

    labels = {"left": "prod", "right": "stage", "mount": "m", "prefix": "a/b"}
    pushgateway.push("http://pg:9091/", "lockstep", labels, "x 1\n", transport=httpx.MockTransport(handler))
    pushgateway.push("http://pg:9091", "lockstep", {**labels, "prefix": ""}, "x 0\n", replace=False,
                     transport=httpx.MockTransport(handler))
    (m1, path1, body1), (m2, path2, _) = seen
    assert m1 == "PUT" and m2 == "POST" and body1 == "x 1\n"
    b = lambda v: base64.urlsafe_b64encode(v.encode()).decode()  # noqa: E731
    assert path1 == f"/metrics/job@base64/{b('lockstep')}/left@base64/{b('prod')}/right@base64/{b('stage')}" \
                    f"/mount@base64/{b('m')}/prefix@base64/{b('a/b')}"
    assert path2.endswith("/prefix@base64/=")
    bad = httpx.MockTransport(lambda r: httpx.Response(400, text="pushed metrics are invalid"))
    with pytest.raises(CliError, match="answered 400: pushed metrics are invalid"):
        pushgateway.push("http://pg:9091", "j", {}, "", transport=bad)


# --------------------------------------------------------------------------- signed baselines and waivers


def _keys(sign=True, trust=True, name="release"):
    from lockstep import plansign
    private, public = plansign.generate()
    signer = plansign._keys(private, (), name)  # signs; trusts only itself
    checker = plansign._keys("", ((name, public),) if trust else (), "ci")  # the public key only
    return (signer if sign else None), checker


def test_signed_baseline_is_checked_and_an_edit_is_caught(tmp_path):
    signer, checker = _keys()
    b = drift.sign_baseline(drift.baseline_of(report(DB, QUEUE)), signer)
    (tmp_path / "base.json").write_text(drift.dump_baseline(b))
    loaded = drift.load_baseline(str(tmp_path / "base.json"))
    assert loaded.issuer.name == "release" and loaded.signature.startswith("ed25519:")
    note = drift.check_signed("baseline", loaded.body(), loaded.issuer, loaded.signature, checker, "base.json", True)
    assert note == f"base.json: signed by release (key {loaded.issuer.key_id})."

    # Accepting more drift by hand breaks the signature
    raw = json.loads((tmp_path / "base.json").read_text())
    raw["drift"].append({"path": "new-secret", "status": "left_only"})
    edited = drift.Baseline.model_validate(raw)
    with pytest.raises(CliError, match="was changed after release signed it"):
        drift.check_signed("baseline", edited.body(), edited.issuer, edited.signature, checker, "base.json", False)
    # So does a garbled signature, or a key the checker doesn't trust
    with pytest.raises(CliError, match="can't read"):
        drift.check_signed("baseline", loaded.body(), loaded.issuer, "nope", checker, "base.json", False)
    _, stranger = _keys()
    with pytest.raises(CliError, match="isn't a trusted key here"):
        drift.check_signed("baseline", loaded.body(), loaded.issuer, loaded.signature, stranger, "base.json", False)
    # Signed as a baseline, it isn't a signed waivers file
    with pytest.raises(CliError, match="was changed after"):
        drift.check_signed("waivers", loaded.body(), loaded.issuer, loaded.signature, checker, "base.json", False)


def test_unsigned_files_and_no_trusted_keys():
    signer, checker = _keys()
    _, nobody = _keys(trust=False)
    b = drift.baseline_of(report(DB))
    assert drift.check_signed("baseline", b.body(), None, None, checker, "base.json", False) is None  # as before
    with pytest.raises(CliError, match="isn't signed, and signed files are required"):
        drift.check_signed("baseline", b.body(), None, None, checker, "base.json", True)
    drift.sign_baseline(b, signer)
    assert "not checked" in drift.check_signed("baseline", b.body(), b.issuer, b.signature, nobody, "base.json", False)
    with pytest.raises(CliError, match="needs the signer's public key"):
        drift.check_signed("baseline", b.body(), b.issuer, b.signature, nobody, "base.json", True)
    with pytest.raises(CliError, match="LOCKSTEP_PLAN_SIGNING_KEY"):
        drift.sign_baseline(b, checker)  # no private key


def test_signed_waivers_keep_comments_and_catch_edits(tmp_path):
    from lockstep import driftsign
    signer, checker = _keys()
    p = tmp_path / "waivers.yaml"
    p.write_text("# accepted until the migration ends\n"
                 "- {path: billing/*, key: flag, owner: team-a, reason: trying the new checkout, expires: 2099-01-31}\n")

    def sign():
        w = drift.load_waivers_file(str(p))
        issuer, sig = driftsign.sign("waivers", w.body(), signer)
        p.write_text(drift.signed_waivers_text(p.read_text(), issuer, sig))

    def check():
        w = drift.load_waivers_file(str(p))
        return drift.check_signed("waivers", w.body(), w.issuer, w.signature, checker, "waivers.yaml", True)

    sign()
    text = p.read_text()
    assert text.startswith("waivers:\n  # accepted until the migration ends\n  - {path: billing/*")
    assert "signed by release" in check()
    sign()  # signing again replaces the old signature
    assert p.read_text().count("signature:") == 1 and "signed by release" in check()
    p.write_text("# a new comment\n" + p.read_text())  # comments and layout don't matter
    assert "signed by release" in check()
    p.write_text(p.read_text().replace("2099-01-31", "2199-01-31"))  # a waiver does
    with pytest.raises(CliError, match="was changed after release signed it"):
        check()
