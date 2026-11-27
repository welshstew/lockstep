"""The GitHub Action (action.yml at the repository root) runs this module.

  python -m lockstep.cli.github_action run       compare, write the reports and the step outputs
  python -m lockstep.cli.github_action comment   post or update the pull request comment

Inputs arrive as INPUT_* environment variables, set from `with:` by action.yml, never
interpolated into a script. The Vault login uses GitHub's OIDC token (the job needs
`permissions: id-token: write`) or a token input. Neither is written anywhere another step can see.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import main as lockstep_main

COMMENT_MARK = "<!-- lockstep-drift:{key} -->"


def inp(name: str, default: str = "") -> str:
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), "").strip() or default


class ActionError(Exception):
    pass


def oidc_token(audience: str) -> str:
    """The job's GitHub OIDC ID token, for Vault's JWT auth."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise ActionError("No GitHub OIDC token: give the job `permissions: id-token: write`, "
                          "or use auth: token with a Vault token.")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(f"{url}{sep}audience={urllib.parse.quote(audience)}",
                                 headers={"Authorization": f"bearer {bearer}", "Accept": "application/json"})
    try:
        # GitHub's own token endpoint, from the runner's environment
        with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310
            value = json.load(r)["value"]
    except (urllib.error.URLError, KeyError, ValueError) as e:
        raise ActionError(f"Couldn't get the GitHub OIDC token: {e}") from e
    print(f"::add-mask::{value}")
    return value


def check_key(left: str, right: str, mount: str, prefix: str) -> str:
    """Tells one check's PR comment from another's, without putting inputs in the marker."""
    return hashlib.sha256("\0".join((left, right, mount, prefix)).encode()).hexdigest()[:12]


def build(report_dir: Path) -> tuple[list[str], dict[str, str]]:
    """The `lockstep compare` arguments, and the environment for the login."""
    left_addr = inp("left-addr") or inp("vault-addr")
    if not left_addr:
        raise ActionError("Set left-addr (the Vault to compare).")
    right_addr = inp("right-addr", left_addr)
    args = ["compare", "--left-addr", left_addr, "--right-addr", right_addr]
    for opt in ("left-namespace", "right-namespace", "mount", "left-mount", "right-mount", "prefix", "left-prefix",
                "right-prefix", "left-name", "right-name", "profile", "profile-name", "baseline", "waivers",
                "fail-on"):
        if v := inp(opt):
            args += [f"--{opt}", v]
    if inp("include-custom-metadata") == "true":
        args.append("--custom-metadata")
    if inp("ca-cert"):
        args += ["--ca-cert", inp("ca-cert")]
    env: dict[str, str] = {}
    auth = inp("auth", "jwt")
    same_vault = right_addr.rstrip("/") == left_addr.rstrip("/") and inp("right-namespace") in ("", inp("left-namespace"))
    if auth == "jwt":
        role, mount = inp("role"), inp("jwt-mount", "jwt")
        right_role = inp("right-role", role)
        jwt = oidc_token(inp("audience", "vault"))
        args += ["--left-auth", "jwt", "--left-auth-mount", mount]
        if inp("left-role", role):
            args += ["--left-role", inp("left-role", role)]
        env["LOCKSTEP_LEFT_JWT"] = jwt
        if not same_vault or inp("right-role"):  # the same Vault reuses the left side's login
            args += ["--right-auth", "jwt", "--right-auth-mount", inp("right-jwt-mount", mount)]
            if right_role:
                args += ["--right-role", right_role]
            env["LOCKSTEP_RIGHT_JWT"] = jwt
    elif auth == "token":
        left_token = inp("left-token") or inp("token")
        if not left_token:
            raise ActionError("auth: token needs left-token (a Vault token, from a secret).")
        print(f"::add-mask::{left_token}")
        env["LOCKSTEP_LEFT_TOKEN"] = left_token
        right_token = inp("right-token") or (left_token if not same_vault else "")
        if right_token:
            print(f"::add-mask::{right_token}")
            env["LOCKSTEP_RIGHT_TOKEN"] = right_token
    else:
        raise ActionError(f"auth must be jwt or token, not {auth!r}.")
    report_dir.mkdir(parents=True, exist_ok=True)
    for name in ("drift.yaml", "drift.json", "drift.sarif", "drift.md"):
        args += ["-o", str(report_dir / name)]
    return args, env


def _output(name: str, value: str) -> None:
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def run() -> int:
    report_dir = Path(inp("report-dir", "lockstep-report"))
    try:
        args, env = build(report_dir)
    except ActionError as e:
        print(f"::error title=Lockstep::{e}")
        _output("exit-code", "2")
        return 0
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        code = lockstep_main(args)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    _output("exit-code", str(code))
    _output("report-dir", str(report_dir))
    md = report_dir / "drift.md"
    if code in (0, 1) and md.is_file():
        data = json.loads((report_dir / "drift.json").read_text())
        check = data.get("drift_check") or {}
        new = check.get("new", sum(1 for _ in _findings(data)))
        _output("new", str(new))
        _output("comment-key", check_key(data["left"]["addr"], data["right"]["addr"], data["left"]["mount"],
                                         data["left"].get("prefix", "")))
        if path := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(path, "a", encoding="utf-8") as f:
                f.write(md.read_text() + "\n")
        if code == 1:
            print(f"::error title=Lockstep::{'Drift found' if not check else f'{new} new differences'}: "
                  f"see the job summary.")
    return 0


def _findings(data: dict):
    for s in data.get("secrets", []):
        if s["status"] in ("different", "left_only", "right_only", "not_compared"):
            keys = [k for k in s.get("keys", []) if not k.get("ignored")]
            yield from (keys if keys and s["status"] not in ("left_only", "right_only") else [s])


def _api(method: str, url: str, token: str, body: dict | None = None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
    # the GitHub API of this run, from the runner's environment
    with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310
        return json.load(r), r.headers.get("Link", "")


def comment() -> int:
    """Post the Markdown summary on the pull request, or update this check's earlier comment."""
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    number = (event.get("pull_request") or {}).get("number")
    md = Path(inp("report-dir", "lockstep-report")) / "drift.md"
    if not number or not md.is_file():
        return 0
    token = inp("github-token")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    repo = os.environ["GITHUB_REPOSITORY"]
    mark = COMMENT_MARK.format(key=inp("comment-key", "default"))
    body = f"{mark}\n{md.read_text()}"
    try:
        url, existing = f"{api}/repos/{repo}/issues/{number}/comments?per_page=100", None
        while url and existing is None:
            page, link = _api("GET", url, token)
            existing = next((c["id"] for c in page if c.get("body", "").startswith(mark)), None)
            url = next((p.split(";")[0].strip(" <>") for p in link.split(",") if 'rel="next"' in p), None)
        if existing is not None:
            _api("PATCH", f"{api}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
        else:
            _api("POST", f"{api}/repos/{repo}/issues/{number}/comments", token, {"body": body})
    except urllib.error.HTTPError as e:
        # A pull request from a fork gets a read-only token: say so, don't fail the check over it
        print(f"::warning title=Lockstep::Couldn't comment on the pull request ({e.code}); "
              f"the job summary has the report. Comments need `permissions: pull-requests: write`.")
    return 0


if __name__ == "__main__":
    sys.exit({"run": run, "comment": comment}[sys.argv[1]]())
