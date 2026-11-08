"""Certificate expiry dashboard against the seeded certs mount."""

import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def scan(client):
    def connect(preset, token):
        return client.post("/api/connections", json={"preset_id": preset, "auth": {"method": "token", "token": token}}).json()["id"]
    a, b = connect(0, "root-a"), connect(1, "root-b")

    def run(*sides):
        body = {"sides": [{"side": s, "conn_id": a if s == "left" else b, "mount": "certs"} for s in sides]}
        r = client.post("/api/expiry", json=body)
        assert r.status_code == 200, r.text
        return r.json()
    return run


def rows(out, **match):
    return [r for r in out["certificates"] if all(r[k] == v for k, v in match.items())]


def test_finds_certificates_everywhere_sorted_by_expiry(scan):
    out = scan("left", "right")
    dates = [r["not_after"] for r in out["certificates"]]
    assert dates == sorted(dates)
    assert rows(out, side="left", path="web/expired", key="tls.crt")[0]["status"] == "expired"
    assert rows(out, side="right", path="web/not-yet-valid")[0]["status"] == "not_yet_valid"
    # base64 DER and a base64 PEM chain are found too
    assert rows(out, side="left", path="web/app", key="tls.crt.der.b64")[0]["subject_cn"] == "app.example.com"
    assert len(rows(out, side="left", path="web/app-b64", key="tls.crt.b64")) == 2
    assert {r["side"] for r in out["certificates"]} == {"left", "right"}
    assert [s["side"] for s in out["sides"]] == ["left", "right"] and out["sides"][0]["secrets"] > 0


def test_keystores_opened_with_sibling_password(scan):
    out = scan("left")
    p12 = rows(out, path="keystores/app", key="keystore.p12")
    assert len(p12) == 3 and {r["opened_with"] for r in p12} == {"keystore.password"}
    assert any(r["alias"] == "app" for r in p12)
    jks = rows(out, path="keystores/java-app", key="keystore.jks")
    assert {r["subject_cn"] for r in jks} == {"jks-app.example.com", "Partner CA"}
    assert {r["opened_with"] for r in jks} == {"keystore.password"}
    jceks = rows(out, path="keystores/java-jceks", key="keystore.jceks")
    assert jceks and {r["opened_with"] for r in jceks} == {"storepass"}
    nopass = rows(out, path="keystores/selfsigned-nopass")
    assert nopass and nopass[0]["opened_with"] is None and nopass[0]["self_signed"]


def test_unopenable_keystore_is_listed_not_hidden(scan):
    out = scan("left")
    # truststore.jks has no password key next to it: certs listed, but flagged
    trust = [l for l in out["locked"] if l["path"] == "truststores/partner"]
    assert trust and "integrity" in trust[0]["reason"]
    assert rows(out, path="truststores/partner")[0]["subject_cn"] == "Partner CA"


def test_no_values_returned(scan):
    import json
    blob = json.dumps(scan("left", "right"))
    assert "changeit" not in blob and "BEGIN" not in blob and "PRIVATE" not in blob
