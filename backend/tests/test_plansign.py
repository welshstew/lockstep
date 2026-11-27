"""Plans that travel between installations: Ed25519 signatures, trusted keys, audience, expiry,
and the creator's entity ID; the HMAC scheme still works without a key pair."""

import copy
import json

import pytest
from fastapi import HTTPException

from lockstep import plansign
from lockstep.api.plans import Plan, load_plan, sign
from lockstep.config import Settings, TrustedKey
from test_sync import env  # noqa: F401  (fixture)

DEV_PRIV, DEV_PUB = plansign.generate()
PROD_PRIV, PROD_PUB = plansign.generate()


def settings(**kw) -> Settings:
    base = {"session_key": "s" * 32, "public_url": "https://lockstep.example.com"}
    return Settings(**(base | kw))


def a_plan(s: Settings, **kw) -> dict:
    p = Plan(id="p1", created_at=plansign.now_iso(), **(plansign.validity(s) | kw),
             left={"vault": "Dev", "preset": True, "mount": "kv"}, right={"vault": "Prod", "preset": True, "mount": "kv"},
             changes=[{"path": "db", "right_path": "db", "direction": "left_to_right", "source_path": "db",
                       "target_path": "db", "source_version": 1, "target_version": 2,
                       "keys": [{"key": "pw", "action": "update", "override": True}], "typed": {"pw": "0" * 32}}])
    return sign(p, s).model_dump(mode="json")


DEV = settings(plan_signing_key=DEV_PRIV, plan_issuer="dev-lockstep", session_key="d" * 32)
PROD = settings(plan_signing_key=PROD_PRIV, plan_issuer="prod-lockstep", session_key="p" * 32,
                plan_trusted_keys=[TrustedKey(name="dev-lockstep", key=DEV_PUB)])


def refused(raw, s, text):
    with pytest.raises(HTTPException) as e:
        load_plan(raw, s)
    assert text in e.value.detail["message"], e.value.detail["message"]


def test_a_plan_travels_to_an_installation_that_trusts_its_key():
    raw = a_plan(DEV)
    assert raw["signature"].startswith("ed25519:") and raw["version"] == 2
    assert raw["issuer"] == {"name": "dev-lockstep", "key_id": plansign.key_id(plansign.load_public(DEV_PUB))}
    assert load_plan(raw, DEV)._local is True
    plan = load_plan(raw, PROD)  # a different session key: only the trusted public key matters
    assert plan._local is False
    refused(raw, settings(plan_signing_key=PROD_PRIV), "doesn't trust")
    refused(raw, settings(), "doesn't trust")  # an HMAC-only installation trusts no key pair


def test_tampering_audience_and_expiry():
    raw = a_plan(DEV)
    for edit in (lambda p: p["changes"][0].__setitem__("target_path", "other"),
                 lambda p: p.__setitem__("expires_at", "2099-01-01T00:00:00Z"),
                 lambda p: p["issuer"].__setitem__("name", "prod-lockstep")):
        bad = copy.deepcopy(raw)
        edit(bad)
        refused(bad, PROD, "changed after it was created")
    refused(a_plan(DEV, audience=["staging-lockstep"]), PROD, "is for staging-lockstep, not this Lockstep server (prod-lockstep)")
    assert load_plan(a_plan(DEV, audience=["prod-lockstep"]), PROD)
    refused(a_plan(DEV, expires_at="2020-01-01T00:00:00Z"), PROD, "expired at 2020-01-01")
    refused(a_plan(DEV, not_before="2099-01-01T00:00:00Z"), PROD, "isn't valid until")


def test_hmac_plans_still_work_without_a_key_pair():
    s = settings()
    raw = a_plan(s)
    assert not raw["signature"].startswith("ed25519:") and raw["issuer"] == {"name": "lockstep.example.com", "key_id": ""}
    assert load_plan(raw, s)._local is True
    refused(raw, settings(session_key="x" * 32), "changed after it was created")
    old = {k: v for k, v in raw.items() if k not in ("issuer", "audience", "not_before", "expires_at")} | {"version": 1}
    old = sign(Plan.model_validate(old), s).model_dump(mode="json")
    for k in ("issuer", "not_before", "expires_at"):
        old.pop(k, None)
    old.pop("audience", None)
    from lockstep.api.plans import _canonical, _key
    import hashlib
    import hmac
    old["signature"] = hmac.new(_key(s), _canonical(old), hashlib.sha256).hexdigest()
    assert load_plan(old, s).version == 1  # a plan file from before version 2


def test_typed_values_on_a_plan_from_elsewhere_are_taken_as_typed():
    from lockstep.api.plans import _typed_values
    plan = load_plan(a_plan(DEV), PROD)
    assert _typed_values(plan, {"0": {"pw": "anything"}}, PROD, require=True)[0] == {"pw": "anything"}
    with pytest.raises(HTTPException):  # on the installation that made it, the check code applies
        _typed_values(load_plan(a_plan(DEV), DEV), {"0": {"pw": "anything"}}, DEV, require=True)


def test_plan_key_command(capsys):
    from lockstep.cli import main
    assert main(["plan-key"]) == 0
    out = capsys.readouterr().out.splitlines()
    priv = out[0].split("=", 1)[1]
    trusted = json.loads(out[1].split("=", 1)[1])
    assert plansign.key_id(plansign.load_private(priv).public_key()) == plansign.key_id(plansign.load_public(trusted[0]["key"]))


def test_bad_keys_are_reported():
    with pytest.raises(HTTPException) as e:
        plansign.keys(settings(plan_signing_key="not-a-key"))
    assert "isn't a valid Ed25519 private key" in e.value.detail["message"]


@pytest.mark.usefixtures("vaults")
def test_api_signs_with_the_key_and_records_entity_ids(client, env, monkeypatch):  # noqa: F811
    from lockstep.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "plan_signing_key", DEV_PRIV)
    monkeypatch.setattr(s, "plan_issuer", "dev-lockstep")
    key = client.get("/api/plans/key").json()
    assert key == {"issuer": "dev-lockstep", "key_id": plansign.key_id(plansign.load_public(DEV_PUB)), "public_key": DEV_PUB}
    alice = env.connect(0, method="userpass", username="alice", password="password")
    env.a.put(f"{env.prefix}/db", {"k": "a"})
    env.b.put(f"{env.prefix}/db", {"k": "b"})
    ch = env.change(env.compare(left=alice)["db"])
    r = client.post("/api/plans", json={"left": {"conn_id": alice, "mount": "app-config", "prefix": env.prefix},
                                        "right": {"conn_id": env.cb, "mount": "app-config", "prefix": env.prefix},
                                        "changes": [ch], "audience": ["dev-lockstep"]})
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["signature"].startswith("ed25519:") and plan["audience"] == ["dev-lockstep"] and plan["expires_at"]
    assert plan["left"]["entity_id"] and plan["left"]["accessor"]  # alice has an entity; a root token doesn't
    v = client.post("/api/plans/verify", json={"plan": plan}).json()
    assert v["local"] is True
    md = client.post("/api/plans/report", json={"plan": plan}).text
    assert "by dev-lockstep" in md and "Valid until" in md

    # Another installation that trusts dev's key, but isn't in the audience
    monkeypatch.setattr(s, "plan_signing_key", PROD_PRIV)
    monkeypatch.setattr(s, "plan_issuer", "prod-lockstep")
    monkeypatch.setattr(s, "plan_trusted_keys", [TrustedKey(name="dev-lockstep", key=DEV_PUB)])
    r = client.post("/api/plans/verify", json={"plan": plan})
    assert r.status_code == 400 and "not this Lockstep server (prod-lockstep)" in r.text
    monkeypatch.setattr(s, "plan_issuer", "dev-lockstep")  # (the audience names it)
    out = client.post("/api/plans/apply", json={"plan": plan, "left_conn_id": alice, "right_conn_id": env.cb, "confirm": True})
    assert out.status_code == 200 and out.json()["outcome"] == "applied", out.text
    assert env.b.get(f"{env.prefix}/db")[0] == {"k": "a"}
