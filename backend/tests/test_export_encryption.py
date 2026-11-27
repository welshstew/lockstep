"""Exports encrypted with a passphrase (Argon2id) or to age public keys, beside the one-time key."""

import json
import logging

import pyrage
import pytest
from fastapi.testclient import TestClient
from pyrage import x25519

from lockstep import exports as ex
from lockstep.config import ExportTeam, Settings, get_settings
from lockstep.main import create_app
from test_exports import cli_env, doc, env  # noqa: F401  (fixtures)

PASS = "correct horse battery staple"


def sample() -> ex.ExportDoc:
    return doc(("db", {"password": "very-secret-pw", "port": 5432}), ("app", {"k": "v"}))


def test_one_time_key_files_are_unchanged():
    env, key = ex.encrypt(sample())
    f = env.dump()
    assert f["version"] == 1 and not {"scheme", "kdf", "recipients"} & f.keys()  # what older Lockstep writes and reads
    assert ex.load(f, key) == sample()


def test_passphrase():
    f = ex.encrypt_passphrase(sample(), PASS).dump()
    assert f["version"] == 2 and f["scheme"] == "passphrase" and "recipients" not in f
    assert f["kdf"] | {"salt": ""} == {"name": "argon2id", "salt": "", "memory_kib": 65536, "iterations": 3, "lanes": 4}
    assert "very-secret-pw" not in json.dumps(f)
    assert ex.load(f, PASS) == sample()
    with pytest.raises(ex.ExportError, match="Wrong passphrase"):
        ex.load(f, PASS + "!")
    with pytest.raises(ex.ExportError, match="encrypted with a passphrase: enter it"):
        ex.load(f)
    for edit in (lambda g: g["source"].__setitem__("vault", "Other"), lambda g: g["kdf"].__setitem__("iterations", 4)):
        bad = json.loads(json.dumps(f))
        edit(bad)
        with pytest.raises(ex.ExportError, match="changed or damaged"):  # the header, kdf included, is authenticated
            ex.load(bad, PASS)
    with pytest.raises(ex.ExportError, match="at least 12"):
        ex.encrypt_passphrase(sample(), "short")


def test_a_file_cant_ask_for_a_huge_argon2_cost():
    f = ex.encrypt_passphrase(sample(), PASS).dump()
    f["kdf"]["memory_kib"] = 4 * 1024 * 1024
    with pytest.raises(ex.ExportError, match="isn't valid"):
        ex.load(f, PASS)


def test_age():
    alice, bob, eve = (x25519.Identity.generate() for _ in range(3))
    keys = [str(alice.to_public()), f"# bob\n{bob.to_public()}\n\n"]
    f = ex.encrypt_age(sample(), keys).dump()
    assert f["version"] == 2 and f["scheme"] == "age" and f["cipher"] == "age" and "nonce" not in f and "kdf" not in f
    assert f["recipients"] == [str(alice.to_public()), str(bob.to_public())]
    assert f["ciphertext"].startswith("-----BEGIN AGE ENCRYPTED FILE-----")
    # Without Lockstep: `jq -r .ciphertext | age -d -i key.txt` gives the plain export
    assert json.loads(pyrage.decrypt(f["ciphertext"].encode(), [bob]))["secrets"][0]["data"]["password"] == "very-secret-pw"
    assert ex.load(f, str(alice)) == sample()
    assert ex.load(f, f"# created: today\n# public key: {bob.to_public()}\n{bob}\n") == sample()  # a whole key file
    with pytest.raises(ex.ExportError, match="isn't encrypted to that age key"):
        ex.load(f, str(eve))
    with pytest.raises(ex.ExportError, match="isn't an age identity"):
        ex.load(f, "lsk1.nope")
    with pytest.raises(ex.ExportError, match="paste your age identity"):
        ex.load(f)
    bad = json.loads(json.dumps(f))
    bad["source"]["prefix"] = "elsewhere"  # age can't authenticate the header: it's checked against the contents
    with pytest.raises(ex.ExportError, match="doesn't match its contents"):
        ex.load(bad, str(alice))
    with pytest.raises(ex.ExportError, match="isn't an age public key"):
        ex.parse_recipients(["age1nope"])
    with pytest.raises(ex.ExportError, match="at least one"):
        ex.parse_recipients(["# nobody"])


def test_teams_setting_checks_keys():
    good = str(x25519.Identity.generate().to_public())
    assert ExportTeam(name="Platform", recipients=[f" {good} "]).recipients == [good]
    with pytest.raises(ValueError, match="isn't an age public key"):
        ExportTeam(name="Platform", recipients=["age1nope"])
    s = Settings(session_key="x" * 32, export_recipients=json.dumps([{"name": "Platform", "recipients": [good]}]))
    assert s.export_recipients[0].name == "Platform"


def test_api(vaults, caplog):
    team = x25519.Identity.generate()
    mine = x25519.Identity.generate()
    app = create_app()
    base = get_settings().model_dump()
    app.dependency_overrides[get_settings] = lambda: Settings(**(base | {"export_recipients": [
        {"name": "Platform", "recipients": [str(team.to_public())]}]}))
    with TestClient(app, headers={"X-Requested-With": "lockstep"}) as c:
        assert c.get("/api/config").json()["export_teams"] == [{"name": "Platform", "keys": 1}]
        cid = c.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
        side = {"conn_id": cid, "mount": "app-config", "prefix": "payments"}

        with caplog.at_level(logging.INFO, logger="lockstep.audit"):
            r = c.post("/api/exports", json={"side": side, "teams": ["Platform"], "recipients": [str(mine.to_public())]})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["scheme"] == "age" and out["key"] is None and len(out["file"]["recipients"]) == 2
        entry = json.loads([rec.message for rec in caplog.records if '"event": "export"' in rec.message][-1])
        assert entry["scheme"] == "age" and entry["teams"] == ["Platform"] and len(entry["recipients"]) == 2
        opened = c.post("/api/exports/open", json={"file": out["file"], "key": str(team)})
        assert opened.status_code == 200 and opened.json()["encrypted"] is True
        r = c.post("/api/exports/open", json={"file": out["file"]})
        assert r.status_code == 400 and r.json()["detail"] | {"message": ""} == {"message": "", "needs_key": True, "scheme": "age"}

        r = c.post("/api/exports", json={"side": side, "passphrase": PASS})
        assert r.status_code == 200 and r.json()["scheme"] == "passphrase"
        assert c.post("/api/exports/open", json={"file": r.json()["file"], "key": PASS}).status_code == 200

        for body, msg in (({"passphrase": "short"}, "at least 12"),
                          ({"passphrase": PASS, "teams": ["Platform"]}, "not both"),
                          ({"teams": ["Nobody"]}, "No team called Nobody"),
                          ({"recipients": ["age1nope"]}, "isn't an age public key")):
            r = c.post("/api/exports", json={"side": side} | body)
            assert r.status_code == 400 and msg in r.text, (body, r.text)
        # Plain stays plain: the protection fields only apply when encrypting
        r = c.post("/api/exports", json={"side": side, "encrypt": False, "passphrase": PASS})
        assert r.status_code == 200 and r.json()["scheme"] == "none"


def test_cli_passphrase_and_age(cli_env, monkeypatch, capsys):  # noqa: F811
    from lockstep.cli import main
    e = cli_env
    e.a.put(f"{e.prefix}/x", {"k": "v"})
    monkeypatch.setenv("VAULT_TOKEN", "root-a")
    base = ["export", "--vault-addr", e.addr_a, "--mount", "app-config", "--prefix", e.prefix]

    monkeypatch.setenv("LOCKSTEP_EXPORT_PASSPHRASE", PASS)
    assert main(base + ["--passphrase", "-o", "p.json"]) == 0
    assert "(encrypted with your passphrase)" in capsys.readouterr().out
    assert json.loads((e.dir / "p.json").read_text())["scheme"] == "passphrase"

    ident = x25519.Identity.generate()
    (e.dir / "team.txt").write_text(f"# the team\n{ident.to_public()}\n")
    (e.dir / "key.txt").write_text(f"# created: now\n{ident}\n")
    assert main(base + ["-R", "team.txt", "-o", "a.json"]) == 0
    assert "(encrypted to 1 age key)" in capsys.readouterr().out
    assert main(base + ["--passphrase", "-r", str(ident.to_public()), "-o", "z.json"]) == 2
    assert "Choose one of --passphrase, --recipient" in capsys.readouterr().err

    monkeypatch.setenv("VAULT_TOKEN", "root-b")
    imp = ["import", "--vault-addr", e.addr_b, "--mount", "app-config", "--prefix", e.prefix, "--dry-run"]
    assert main(imp[:1] + ["p.json"] + imp[1:]) == 0  # the passphrase from LOCKSTEP_EXPORT_PASSPHRASE
    assert "1 to write" in capsys.readouterr().out
    assert main(imp[:1] + ["a.json"] + imp[1:] + ["--key-file", "key.txt"]) == 0
    assert "1 to write" in capsys.readouterr().out
    monkeypatch.delenv("LOCKSTEP_EXPORT_PASSPHRASE")
    assert main(imp[:1] + ["a.json"] + imp[1:]) == 2
    assert "paste your age identity. Use --key-file with your age identity file." in capsys.readouterr().err
