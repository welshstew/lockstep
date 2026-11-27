"""The GitHub Action's runner (lockstep.cli.github_action), with GitHub's endpoints faked locally:
the OIDC token endpoint hands out a real Dex ID token, which Vault's JWT auth accepts."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from lockstep.cli import github_action as gha
from test_cli import MOUNT, env  # noqa: F401  (the two-Vault fixture)
from test_jwt import id_token


class Fake:
    """A tiny HTTP server: GitHub's OIDC endpoint and the issue comments API."""

    def __init__(self, jwt: str | None = None):
        self.jwt, self.comments, self.requests = jwt, [], []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fake.requests.append(("GET", self.path, self.headers.get("Authorization")))
                if self.path.startswith("/token"):
                    return self._send(200, {"value": fake.jwt})
                return self._send(200, [{"id": i, "body": b} for i, b in enumerate(fake.comments)])

            def _body(self):
                return json.loads(self.rfile.read(int(self.headers["Content-Length"])))

            def do_POST(self):
                fake.requests.append(("POST", self.path, None))
                fake.comments.append(self._body()["body"])
                self._send(201, {})

            def do_PATCH(self):
                fake.requests.append(("PATCH", self.path, None))
                fake.comments[int(self.path.rsplit("/", 1)[1])] = self._body()["body"]
                self._send(200, {})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def github(monkeypatch, tmp_path):
    fakes = []

    def make(jwt=None):
        f = Fake(jwt)
        fakes.append(f)
        out, summary, event = tmp_path / "out", tmp_path / "summary.md", tmp_path / "event.json"
        event.write_text(json.dumps({"pull_request": {"number": 7}}))
        for k, v in {"GITHUB_OUTPUT": out, "GITHUB_STEP_SUMMARY": summary, "GITHUB_EVENT_PATH": event,
                     "GITHUB_API_URL": f.url, "GITHUB_REPOSITORY": "acme/infra",
                     "ACTIONS_ID_TOKEN_REQUEST_URL": f"{f.url}/token?api-version=2.0",
                     "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-bearer"}.items():
            monkeypatch.setenv(k, str(v))
        return f

    yield make
    for f in fakes:
        f.close()


def outputs(tmp_path: Path) -> dict:
    return dict(line.split("=", 1) for line in (tmp_path / "out").read_text().splitlines())


def set_inputs(monkeypatch, **kw):
    for k, v in kw.items():
        monkeypatch.setenv("INPUT_" + k.upper(), v)


def test_jwt_login_compare_outputs_and_comment(env, github, monkeypatch, tmp_path, capsys):  # noqa: F811
    for var in ("LOCKSTEP_LEFT_TOKEN", "LOCKSTEP_RIGHT_TOKEN"):
        monkeypatch.delenv(var)
    jwt = id_token("alice")  # alice is admin on both Vaults through her identity entity
    gh = github(jwt)
    left, right = env.args[1], env.args[3]
    set_inputs(monkeypatch, left_addr=left, right_addr=right, mount=MOUNT, prefix=env.prefix, left_name="A",
               right_name="B", report_dir=str(tmp_path / "rep"), github_token="gh-token")
    assert gha.run() == 0
    out = capsys.readouterr().out
    assert f"::add-mask::{jwt}" in out and "::error title=Lockstep::Drift found" in out
    o = outputs(tmp_path)
    assert o["exit-code"] == "1" and o["new"] == "4" and len(o["comment-key"]) == 12
    assert ("GET", "/token?api-version=2.0&audience=vault", "bearer runner-bearer") in gh.requests
    rep = tmp_path / "rep"
    assert {p.name for p in rep.iterdir()} == {"drift.yaml", "drift.json", "drift.sarif", "drift.md"}
    assert "### Lockstep: drift found" in (tmp_path / "summary.md").read_text()
    assert "LOCKSTEP_LEFT_JWT" not in __import__("os").environ  # not left for later steps

    set_inputs(monkeypatch, comment_key=o["comment-key"])
    assert gha.comment() == 0 and gha.comment() == 0  # posts, then updates the same comment
    assert [m for m, *_ in gh.requests if m in ("POST", "PATCH")] == ["POST", "PATCH"]
    assert len(gh.comments) == 1 and gh.comments[0].startswith(f"<!-- lockstep-drift:{o['comment-key']} -->\n###")


def test_token_auth_and_a_baseline(env, github, monkeypatch, tmp_path, capsys):  # noqa: F811
    from lockstep.cli import main
    github()
    assert main(["baseline", "update", str(tmp_path / "drift.json"), *env.args, "-q"]) == 0
    for var in ("LOCKSTEP_LEFT_TOKEN", "LOCKSTEP_RIGHT_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        monkeypatch.delenv(var)
    set_inputs(monkeypatch, auth="token", left_token="root-a", right_token="root-b", left_addr=env.args[1],
               right_addr=env.args[3], mount=MOUNT, prefix=env.prefix, left_name="A", right_name="B",
               baseline=str(tmp_path / "drift.json"), report_dir=str(tmp_path / "rep"))
    assert gha.run() == 0
    o = outputs(tmp_path)
    assert o["exit-code"] == "0" and o["new"] == "0"
    assert "::add-mask::root-a" in capsys.readouterr().out


def test_mistakes_are_reported_not_raised(github, monkeypatch, tmp_path, capsys):
    github()
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    set_inputs(monkeypatch, left_addr="https://vault.example.com", report_dir=str(tmp_path / "rep"))
    assert gha.run() == 0
    assert outputs(tmp_path)["exit-code"] == "2"
    assert "permissions: id-token: write" in capsys.readouterr().out
    set_inputs(monkeypatch, auth="password")
    gha.run()
    assert "auth must be jwt or token" in capsys.readouterr().out


def test_arguments(github, monkeypatch, tmp_path):
    github("jwt-value")
    set_inputs(monkeypatch, left_addr="https://a", mount="kv", role="ci", report_dir=str(tmp_path / "r"))
    args, env_ = gha.build(tmp_path / "r")
    assert args[:5] == ["compare", "--left-addr", "https://a", "--right-addr", "https://a"]
    assert "--right-auth" not in args and env_ == {"LOCKSTEP_LEFT_JWT": "jwt-value"}  # same Vault: one login
    assert args[args.index("--left-role") + 1] == "ci" and args.count("-o") == 4
    set_inputs(monkeypatch, right_addr="https://b", right_role="ci-b")
    args, env_ = gha.build(tmp_path / "r")
    assert args[args.index("--right-role") + 1] == "ci-b" and env_["LOCKSTEP_RIGHT_JWT"] == "jwt-value"


def test_action_metadata_matches_the_runner():
    """Every input action.yml declares reaches the runner as INPUT_*, every ${{ inputs.x }} exists,
    and no input is interpolated into a script (only into env:, where it can't inject)."""
    import re

    import yaml
    path = Path(__file__).resolve().parents[2] / "action.yml"
    if not path.exists():
        pytest.skip("repository checkout not available")
    action = yaml.safe_load(path.read_text())
    declared = set(action["inputs"])
    steps = action["runs"]["steps"]
    used = set(re.findall(r"inputs\.([a-z-]+)", path.read_text()))
    assert used <= declared, used - declared
    passed = {k[len("INPUT_"):].lower().replace("_", "-") for s in steps for k in (s.get("env") or {})
              if k.startswith("INPUT_")}
    via_with = {"python-version", "sarif", "comment", "fail-on-drift"}  # used by action.yml itself
    assert declared - passed - via_with == set(), declared - passed - via_with
    for s in steps:
        assert "${{" not in s.get("run", ""), f"step {s.get('name')} interpolates into its script"
    runner = Path(gha.__file__).read_text()
    for name in passed:
        assert f'"{name}"' in runner, f"the runner never reads {name}"
