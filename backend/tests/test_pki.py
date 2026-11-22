"""Issuing development certificates from a PKI role (seeded pki-dev on Vault A)."""

import json
import logging
import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def root(client):
    return client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]


def test_mounts_and_overview(client, root):
    assert {"path": "pki-dev", "description": "Development certificates"} in client.get("/api/pki/mounts", params={"conn_id": root}).json()
    out = client.get("/api/pki/overview", params={"conn_id": root, "mount": "pki-dev"}).json()
    assert out["issuers"][0]["subject"] == "Lockstep Dev Root CA" and out["issuers"][0]["name"] == "dev-root"
    role = out["roles"][0]
    assert role["name"] == "dev-services" and role["allowed_domains"] == ["dev.internal"] and role["key_type"] == "ec"


def test_issue_and_store(client, root, vaults, caplog):
    path = f"pki-test-{uuid.uuid4().hex[:6]}/api-tls"
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        r = client.post("/api/pki/issue", json={"conn_id": root, "mount": "pki-dev", "role": "dev-services",
                                               "common_name": "api.dev.internal", "alt_names": ["www.dev.internal"], "ttl": "2h",
                                               "store": {"mount": "app-config", "path": path}})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["info"]["subject"] == "api.dev.internal" and set(out["info"]["sans"]) == {"api.dev.internal", "www.dev.internal"}
    assert out["info"]["issuer"] == "Lockstep Dev Root CA" and out["private_key"].startswith("-----BEGIN")
    assert out["stored"] == {"mount": "app-config", "path": path, "version": 1}
    line = next(json.loads(m) for m in caplog.messages if '"pki.issue"' in m)
    assert "PRIVATE" not in json.dumps(line) and line["serial"]
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    stored = v.get(f"app-config/data/{path}").json()["data"]["data"]
    assert set(stored) == {"certificate", "private_key", "ca_chain"}
    # The same path again: refused rather than overwritten
    again = client.post("/api/pki/issue", json={"conn_id": root, "mount": "pki-dev", "role": "dev-services",
                                               "common_name": "api.dev.internal", "store": {"mount": "app-config", "path": path}})
    assert again.status_code == 409
    v.delete(f"app-config/metadata/{path}")
    bad = client.post("/api/pki/issue", json={"conn_id": root, "mount": "pki-dev", "role": "dev-services", "common_name": "evil.example.com"})
    assert bad.status_code == 400


def test_expiry_scan_includes_pki_certificates(client, root):
    issued = client.post("/api/pki/issue", json={"conn_id": root, "mount": "pki-dev", "role": "dev-services",
                                                 "common_name": f"scan-{uuid.uuid4().hex[:6]}.dev.internal", "ttl": "1h"}).json()
    side = {"side": "left", "conn_id": root, "mount": "app-config", "prefix": "nothing-here"}
    without = client.post("/api/expiry", json={"sides": [side]}).json()
    assert not any(r["container"].startswith("PKI") for r in without["certificates"])
    out = client.post("/api/expiry", json={"sides": [side, side | {"side": "right"}], "include_pki": True}).json()
    pki = [r for r in out["certificates"] if r["container"].startswith("PKI")]
    leaf = [r for r in pki if r["subject_cn"] == issued["info"]["subject"]]
    assert len(leaf) == 1 and leaf[0]["mount"] == "pki-dev" and leaf[0]["path"].startswith("certs/")
    assert leaf[0]["status"] == "expiring" and leaf[0]["days_left"] == 0
    roots = [r for r in pki if r["container"] == "PKI issuer"]
    assert [r["subject_cn"] for r in roots] == ["Lockstep Dev Root CA"] and roots[0]["path"] == "issuer/dev-root"
    assert len({(r["mount"], r["serial"]) for r in pki}) == len(pki)  # same Vault on both sides: scanned once
