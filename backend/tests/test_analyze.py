"""Value tools: detection, certificates/chains, keystores, content download, badges."""

import base64
import os

import pytest

from lockstep.analyze import detect

# --------------------------------------------------------------------------- unit: detection


def kinds(node):
    return [node["kind"]] + [k for c in node["children"] for k in kinds(c)]


def test_plain_strings_stay_text():
    for v in ["password123", "hunter2", "Kf8sLm2Qp9xTzR4w", "https://example.com/x", "true"]:
        assert detect.analyze(v).root.kind == "text", v
        assert detect.badge(v) is None


def test_random_token_that_is_valid_base64_gets_no_badge():
    token = base64.b64encode(os.urandom(24)).decode()  # 32 chars
    assert detect.badge(token) is None


def test_base64_text_and_json():
    r = detect.analyze(base64.b64encode(b"hello there, this is text").decode()).root
    assert r.kind == "base64" and r.children[0].kind == "text"
    r = detect.analyze(base64.b64encode(b'{"a": 1, "b": [1, 2]}').decode()).root
    assert r.children[0].kind == "json"


def test_urlsafe_and_wrapped_base64():
    payload = os.urandom(300)
    wrapped = "\n".join(base64.b64encode(payload).decode()[i:i + 64] for i in range(0, 400, 64))
    assert detect.analyze(wrapped).root.children[0].kind == "binary"
    urlsafe = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    a = detect.analyze(urlsafe)
    assert a.blobs["0.0"] == payload


def test_svg_with_script_is_an_image_not_markup():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    n = detect.analyze(base64.b64encode(svg).decode()).root.children[0]
    assert n.kind == "image" and n.mime == "image/svg+xml"


def test_non_string_values_are_json():
    assert detect.analyze({"a": 1}).root.kind == "json"
    assert detect.analyze(5432).root.kind == "json"


# --------------------------------------------------------------------------- integration



@pytest.fixture
def ana(client, vaults):
    ca = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
    cb = client.post("/api/connections", json={"preset_id": 1, "auth": {"method": "token", "token": "root-b"}}).json()["id"]

    def run(mount, path, key, conn=None, **extra):
        r = client.post("/api/analyze", json={"conn_id": conn or ca, "mount": mount, "path": path, "key": key, **extra})
        assert r.status_code == 200, r.text
        return r.json()

    def content(mount, path, key, node_id, **extra):
        return client.post("/api/analyze/content", json={"conn_id": ca, "mount": mount, "path": path, "key": key,
                                                         "node_id": node_id, **extra})

    run.content, run.ca, run.cb = content, ca, cb
    return run


def find(node, kind):
    if node["kind"] == kind:
        return node
    for c in node["children"]:
        if (hit := find(c, kind)) is not None:
            return hit
    return None


def all_of(node, kind):
    return ([node] if node["kind"] == kind else []) + [n for c in node["children"] for n in all_of(c, kind)]


@pytest.mark.usefixtures("vaults")
def test_cert_chain_uses_siblings_and_needs_a_trusted_root(ana):
    out = ana("certs", "web/app", "tls.crt")
    cert = find(out["root"], "certificate")["details"]
    assert cert["certificate"]["status"] == "valid"
    assert "DNS:www.app.example.com" in cert["certificate"]["sans"]
    chain = cert["chain"]
    # leaf -> intermediate (from sibling chain.pem) -> root (sibling ca.crt), but root isn't trusted
    assert chain["verdict"] == "untrusted_root"
    assert [l["subject"] for l in chain["links"]] == ["app.example.com", "Example Intermediate CA", "Example Root CA"]
    assert all(l["signature_ok"] for l in chain["links"][:2])
    assert {s["key"] for s in out["siblings"]} >= {"chain.pem", "ca.crt"}

    trusted = ana("certs", "web/app", "tls.crt",
                  trust=[{"conn_id": ana.ca, "mount": "certs", "path": "ca/root", "key": "certificate"}])
    assert find(trusted["root"], "certificate")["details"]["chain"]["verdict"] == "trusted"
    assert trusted["trust_anchors"]["selected"] == 1

    # "Trust this root": trust the sibling ca.crt by its fingerprint
    root_fp = chain["links"][-1]["sha256"]
    by_fp = ana("certs", "web/app", "tls.crt", trust_sha256=[root_fp])
    assert find(by_fp["root"], "certificate")["details"]["chain"]["verdict"] == "trusted"


@pytest.mark.usefixtures("vaults")
@pytest.mark.parametrize("conn,path,status,verdict", [
    ("a", "web/expired", "expired", "invalid"),
    ("b", "web/not-yet-valid", "not_yet_valid", "invalid"),
    ("b", "web/selfsigned", "valid", "untrusted_root"),
    ("b", "web/untrusted", "valid", "incomplete"),
    ("b", "web/missing-intermediate", "valid", "incomplete"),
])
def test_certificate_verdicts(ana, conn, path, status, verdict):
    out = ana("certs", path, "tls.crt", conn=ana.ca if conn == "a" else ana.cb)
    d = find(out["root"], "certificate")["details"]
    assert d["certificate"]["status"] == status
    assert d["chain"]["verdict"] == verdict


@pytest.mark.usefixtures("vaults")
def test_base64_der_and_base64_pem_bundle(ana):
    der = ana("certs", "web/app", "tls.crt.der.b64")["root"]
    assert der["kind"] == "base64" and der["children"][0]["kind"] == "certificate"
    bundle = ana("certs", "web/app-b64", "tls.crt.b64")["root"]
    assert len(all_of(bundle, "certificate")) == 2


@pytest.mark.usefixtures("vaults")
def test_pkcs12_password_flow(ana):
    locked = find(ana("certs", "keystores/app", "keystore.p12")["root"], "pkcs12")
    assert locked["needs_password"] and not locked["children"]
    out = ana("certs", "keystores/app", "keystore.p12", password_key="keystore.password")
    assert "keystore.password" in out["password_suggestions"] and out["password_used"]
    p12 = find(out["root"], "pkcs12")
    key = find(p12, "private_key")
    assert key["details"]["matches"] == ["Certificate: app.example.com (alias app)"]
    assert len(all_of(p12, "certificate")) == 3
    wrong = find(ana("certs", "keystores/app", "keystore.p12", password="nope")["root"], "pkcs12")
    assert wrong["needs_password"] and wrong["problems"]
    nopass = find(ana("certs", "keystores/selfsigned-nopass", "keystore.p12")["root"], "pkcs12")
    assert not nopass["needs_password"] and find(nopass, "private_key")


@pytest.mark.usefixtures("vaults")
def test_jks_made_by_keytool(ana):
    no_pw = find(ana("certs", "keystores/java-app", "keystore.jks")["root"], "jks")
    assert no_pw["details"]["integrity"] == "unchecked" and no_pw["needs_password"]
    assert any("SHA-1" in n and "-deststoretype pkcs12" in n for n in no_pw["notes"])  # weak format, said so
    assert len(all_of(no_pw, "certificate")) == 2  # certs readable without the password
    assert find(no_pw, "private_key") is None

    ok = find(ana("certs", "keystores/java-app", "keystore.jks", password_key="keystore.password")["root"], "jks")
    assert ok["details"]["integrity"] == "ok" and not ok["needs_password"]
    key = find(ok, "private_key")
    assert key["details"]["key"] == "EC secp256r1"
    assert key["details"]["matches"] == ["Certificate: jks-app.example.com (alias app)"]

    bad = find(ana("certs", "keystores/java-app", "keystore.jks", password="wrong")["root"], "jks")
    assert bad["details"]["integrity"] == "bad_password" and find(bad, "private_key") is None


@pytest.mark.usefixtures("vaults")
def test_jceks_made_by_keytool(ana):
    ks = find(ana("certs", "keystores/java-jceks", "keystore.jceks", password_key="storepass")["root"], "jceks")
    assert ks["details"]["integrity"] == "ok"
    entry = find(ks, "keystore_entry")
    assert any("JCEKS" in n for n in entry["notes"])
    assert any("MD5 with Triple DES" in n and "old.jceks" in n for n in ks["notes"])
    assert len(all_of(ks, "certificate")) == 2


@pytest.mark.usefixtures("vaults")
def test_images_zip_binary_and_content_download(ana):
    png = ana("app-config", "frontend/assets", "logo.png")["root"]["children"][0]
    assert png["kind"] == "image" and png["mime"] == "image/png"
    r = ana.content("app-config", "frontend/assets", "logo.png", png["id"])
    assert r.status_code == 200 and r.content.startswith(b"\x89PNG")
    assert r.headers["x-mime"] == "image/png" and r.headers["x-filename"] == "logo.png"
    assert r.headers["content-type"] == "application/octet-stream"

    jar = ana("app-config", "frontend/bundle", "plugin.jar")["root"]["children"][0]
    assert jar["label"] == "ZIP archive (JAR)"
    assert [e["name"] for e in jar["details"]["entries"]] == ["META-INF/MANIFEST.MF", "config/app.properties"]

    aes = ana("app-config", "crypto/keys", "aes_key")["root"]["children"][0]
    assert aes["kind"] == "binary" and aes["size"] == 32


@pytest.mark.usefixtures("vaults")
def test_keystore_private_keys_are_not_downloadable(ana):
    out = ana("certs", "keystores/java-app", "keystore.jks", password_key="keystore.password")
    key = find(out["root"], "private_key")
    assert key["downloadable"] is False
    r = ana.content("certs", "keystores/java-app", "keystore.jks", key["id"], password_key="keystore.password")
    assert r.status_code == 404
    whole = find(out["root"], "jks")
    assert ana.content("certs", "keystores/java-app", "keystore.jks", whole["id"]).content[:4] == b"\xfe\xed\xfe\xed"


@pytest.mark.usefixtures("vaults")
def test_badges_in_compare(client, ana):
    r = client.post("/api/compare", json={"left": {"conn_id": ana.ca, "mount": "certs"},
                                          "right": {"conn_id": ana.cb, "mount": "certs"}}).json()
    s = {x["path"]: x for x in r["secrets"]}
    exp = s["web/expired"]["badges"]["tls.crt"]["left"]
    assert exp["kind"] == "pem" and exp["status"] == "bad" and exp["detail"] == "expired"
    p12 = s["keystores/app"]["badges"]["keystore.p12"]["left"]
    assert p12["kind"] == "pkcs12" and p12["detail"] == "password needed"
    assert "keystore.password" not in s["keystores/app"]["badges"]  # plain text: no badge
    jks = s["keystores/java-app"]["badges"]["keystore.jks"]["right"]
    assert jks["kind"] == "jks" and jks["status"] == "ok"
    assert "changeit" not in str(r)  # badges carry no values
