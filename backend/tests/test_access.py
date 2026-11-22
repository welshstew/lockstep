"""Writing policies and auth roles from Lockstep (policy builder phase 5)."""

import json
import logging
import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def ctx(client, vaults):
    tag = uuid.uuid4().hex[:6]
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    mount = f"k8s-acc-{tag}"
    try:
        v.post(f"sys/auth/{mount}", json={"type": "kubernetes"}).raise_for_status()
        v.post(f"auth/{mount}/config", json={"kubernetes_host": "https://k.example:443", "disable_local_ca_jwt": True}).raise_for_status()
        conn = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
        yield tag, v, mount, conn
    finally:
        v.delete(f"sys/auth/{mount}")
        for n in (f"acc-{tag}-a", f"acc-{tag}-b"):
            v.delete(f"sys/policies/acl/{n}")


def role(mount, name, **body):
    return {"kind": "kubernetes", "mount": mount, "name": name,
            "body": {"bound_service_account_names": ["app"], "bound_service_account_namespaces": ["ns"],
                     "token_policies": ["lockstep-limited"], **body}}


def test_preview_then_apply_policies_and_roles(client, ctx, caplog):
    tag, v, mount, conn = ctx
    v.put(f"sys/policies/acl/acc-{tag}-a", json={"policy": 'path "x" { capabilities = ["read"] }'}).raise_for_status()
    body = {"conn_id": conn,
            "policies": [{"name": f"acc-{tag}-a", "text": 'path "x" { capabilities = ["read", "list"] }'},
                         {"name": f"acc-{tag}-b", "text": 'path "y" { capabilities = ["read"] }'}],
            "roles": [role(mount, "app", token_ttl="30m")]}
    pre = {i["id"]: i for i in client.post("/api/access/preview", json=body).json()}
    a = pre[f"policy:acc-{tag}-a"]
    assert a["action"] == "change" and '+path "x" { capabilities = ["read", "list"] }' in a["diff"] and a["allowed"]
    assert pre[f"policy:acc-{tag}-b"]["action"] == "new" and pre[f"role:{mount}/app"]["action"] == "new"
    expected = {k: i["hash"] for k, i in pre.items()}
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        out = client.post("/api/access/apply", json=body | {"expected": expected, "confirm": True}).json()
    assert all(i["status"] == "applied" for i in out), out
    assert "list" in v.get(f"sys/policies/acl/acc-{tag}-a").json()["data"]["policy"]
    assert v.get(f"auth/{mount}/role/app").json()["data"]["token_ttl"] == 1800
    events = {json.loads(m)["event"] for m in caplog.messages if '"policy.' in m or '"role.' in m}
    assert events == {"policy.write", "role.write"}

    # Again: nothing changes
    again = {i["id"]: i for i in client.post("/api/access/preview", json=body).json()}
    assert {i["action"] for i in again.values()} == {"same"} and {i["status"] for i in again.values()} == {"noop"}

    # A role write replaces the role: dropping a field sets it back to its default
    client.post("/api/access/apply", json={"conn_id": conn, "roles": [role(mount, "app")], "confirm": True})
    assert v.get(f"auth/{mount}/role/app").json()["data"]["token_ttl"] == 0


def test_conflict_when_changed_since_preview(client, ctx):
    tag, v, mount, conn = ctx
    v.put(f"sys/policies/acl/acc-{tag}-a", json={"policy": 'path "x" { capabilities = ["read"] }'})
    body = {"conn_id": conn, "policies": [{"name": f"acc-{tag}-a", "text": 'path "x" { capabilities = ["deny"] }'}]}
    pre = client.post("/api/access/preview", json=body).json()[0]
    v.put(f"sys/policies/acl/acc-{tag}-a", json={"policy": 'path "x" { capabilities = ["update"] }'})
    out = client.post("/api/access/apply", json=body | {"expected": {pre["id"]: pre["hash"]}, "confirm": True}).json()[0]
    assert out["status"] == "conflict"
    assert "update" in v.get(f"sys/policies/acl/acc-{tag}-a").json()["data"]["policy"]


def test_delete_and_guards(client, ctx, monkeypatch):
    tag, v, mount, conn = ctx
    v.put(f"sys/policies/acl/acc-{tag}-a", json={"policy": 'path "x" { capabilities = ["read"] }'})
    v.post(f"auth/{mount}/role/gone", json={"bound_service_account_names": ["a"], "bound_service_account_namespaces": ["b"]})
    body = {"conn_id": conn, "delete_policies": [f"acc-{tag}-a"], "delete_roles": [{"mount": mount, "name": "gone"}]}
    pre = client.post("/api/access/preview", json=body).json()
    assert {i["action"] for i in pre} == {"delete"}
    out = client.post("/api/access/apply", json=body | {"expected": {i["id"]: i["hash"] for i in pre}, "confirm": True}).json()
    assert {i["status"] for i in out} == {"applied"}
    assert v.get(f"sys/policies/acl/acc-{tag}-a").status_code == 404 and v.get(f"auth/{mount}/role/gone").status_code == 404

    for bad in ({"conn_id": conn, "delete_policies": ["default"]}, {"conn_id": conn, "policies": [{"name": "root", "text": 'path "x" {}'}]},
                {"conn_id": conn}):
        assert client.post("/api/access/preview", json=bad).status_code == 422
    broken = client.post("/api/access/preview", json={"conn_id": conn, "policies": [{"name": f"acc-{tag}-b", "text": 'path "x" {'}]}).json()[0]
    assert broken["status"] == "invalid"
    wrong = client.post("/api/access/preview", json={"conn_id": conn, "roles": [role("jwt", "x")]}).json()[0]
    assert wrong["status"] == "invalid" and "isn't a Kubernetes" in wrong["problems"][0]

    from lockstep.config import get_settings
    monkeypatch.setattr(get_settings(), "policy_apply", "off")
    r = client.post("/api/access/apply", json={"conn_id": conn, "policies": [{"name": f"acc-{tag}-b", "text": 'path "y" { capabilities = ["read"] }'}], "confirm": True})
    assert r.status_code == 403 and "LOCKSTEP_POLICY_APPLY" in r.text
    assert client.get("/api/config").json()["policy_apply"] is False


def test_bob_is_denied_in_the_preview(client, ctx):
    tag, v, mount, conn = ctx
    bob = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "bob", "password": "password"}}).json()["id"]
    pre = client.post("/api/access/preview", json={"conn_id": bob, "policies": [{"name": f"acc-{tag}-b", "text": 'path "y" { capabilities = ["read"] }'}]}).json()[0]
    assert pre["status"] == "denied" and pre["allowed"] is False


def test_access_plan_made_by_bob_applied_by_root(client, ctx, caplog):
    """Bob can't write policies, so he saves a plan; someone with the rights checks and applies it."""
    tag, v, mount, conn = ctx
    bob = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "bob", "password": "password"}}).json()["id"]
    changes = {"policies": [{"name": f"acc-{tag}-a", "text": 'path "x" { capabilities = ["read"] }'}],
               "roles": [role(mount, f"plan-{tag}")]}
    r = client.post("/api/access/plans", json={"conn_id": bob} | changes)
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["format"] == "lockstep.access-plan" and plan["vault"] == "Vault A" and plan["preset"] is True
    assert plan["created_by"] == "userpass-bob" and plan["signature"]
    st = {i["id"].split(":")[0]: i["status"] for i in plan["items"]}
    assert st["policy"] == "denied"  # and the role: bob can't even see the auth mounts, so it's "invalid" for him

    check = client.post("/api/access/plans/check", json={"conn_ids": [conn], "plan": plan}).json()
    assert check["conn_id"] == conn and {i["status"] for i in check["items"]} == {"ready"}

    # Edited plans are refused
    tampered = plan | {"changes": plan["changes"] | {"policies": [{"name": f"acc-{tag}-a", "text": 'path "*" { capabilities = ["sudo"] }'}]}}
    assert client.post("/api/access/plans/check", json={"conn_ids": [conn], "plan": tampered}).status_code == 400

    # The wrong Vault: a Vault B connection
    other = client.post("/api/connections", json={"preset_id": 1, "auth": {"method": "token", "token": "root-b"}}).json()["id"]
    wrong = client.post("/api/access/plans/check", json={"conn_ids": [other], "plan": plan})
    assert wrong.status_code == 409 and "Vault A" in wrong.json()["detail"]["message"]

    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        both = client.post("/api/access/plans/check", json={"conn_ids": [bob, conn], "plan": plan}).json()
    assert both["conn_id"] == conn  # both on Vault A: the one with the rights
    out = client.post("/api/access/plans/apply", json={"conn_ids": [other, conn], "plan": plan, "confirm": True}).json()
    assert {i["status"] for i in out} == {"applied"}
    assert v.get(f"auth/{mount}/role/plan-{tag}").status_code == 200
    assert any(json.loads(m).get("plan_id") == plan["id"] for m in caplog.messages if m.startswith("{"))


def test_access_plan_conflict(client, ctx):
    tag, v, mount, conn = ctx
    plan = client.post("/api/access/plans", json={"conn_id": conn, "policies": [{"name": f"acc-{tag}-b", "text": 'path "y" { capabilities = ["read"] }'}]}).json()
    v.put(f"sys/policies/acl/acc-{tag}-b", json={"policy": 'path "z" { capabilities = ["list"] }'}).raise_for_status()  # someone else got there first
    check = client.post("/api/access/plans/check", json={"conn_ids": [conn], "plan": plan}).json()["items"][0]
    assert check["status"] == "conflict" and "since the plan was made" in check["problems"][0]
    out = client.post("/api/access/plans/apply", json={"conn_ids": [conn], "plan": plan, "confirm": True}).json()[0]
    assert out["status"] == "conflict"
    assert "z" in v.get(f"sys/policies/acl/acc-{tag}-b").json()["data"]["policy"]
    assert client.post("/api/access/plans", json={"conn_id": conn, "policies": [{"name": f"acc-{tag}-b", "text": 'path "z" { capabilities = ["list"] }'}]}).status_code == 400  # nothing to do
