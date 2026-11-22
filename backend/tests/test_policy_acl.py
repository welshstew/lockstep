"""Policy parsing, and Lockstep's path matching checked against Vault's own (sys/capabilities)."""

import itertools
import os
import random
import uuid

import httpx
import pytest

from lockstep.policy.acl import ACL
from lockstep.policy.hcl import PolicyParseError, parse_policy, to_hcl


# --------------------------------------------------------------------------- parsing

def test_parse_hcl_with_comments_legacy_and_extra_fields():
    p = parse_policy('''
# a comment
// another
/* and a
   block comment */
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "/secret/metadata/*" { capabilities = ["LIST"], }
path "legacy/*" { policy = "write" }
path "params/*" {
  capabilities = ["create"]
  allowed_parameters = { "ttl" = [] "role" = ["a", "b"] }
  min_wrapping_ttl = "1s"
}
path "empty" {}
''', "p")
    rules = {r.path: r for r in p.rules}
    assert rules["secret/data/*"].capabilities == ["read", "list"]
    assert rules["secret/metadata/*"].capabilities == ["list"]  # leading / dropped, lower-cased
    assert rules["legacy/*"].capabilities == ["create", "read", "update", "delete", "list"]
    assert rules["params/*"].extra == {"allowed_parameters": {"ttl": [], "role": ["a", "b"]}, "min_wrapping_ttl": "1s"}
    assert rules["empty"].capabilities == []
    assert rules["secret/data/*"].line == 6
    assert parse_policy(to_hcl(p)).rules[0].capabilities == ["read", "list"]


def test_parse_json_policy():
    p = parse_policy('{"path": {"a/*": {"capabilities": ["read"]}, "b": [{"capabilities": ["deny"]}]}}')
    assert [(r.path, r.capabilities) for r in p.rules] == [("a/*", ["read"]), ("b", ["deny"])]


@pytest.mark.parametrize("bad", [
    'path "a" { capabilities = ["read"] ',
    'path "a" capabilities',
    'path { capabilities = ["read"] }',
    'path "a" { capabilities = "read }',
    'path "a" { policy = "admin" }',
    '{"path": [1]}',
])
def test_parse_errors(bad):
    with pytest.raises(PolicyParseError):
        parse_policy(bad)


def test_unknown_capabilities_are_kept_and_reported():
    r = parse_policy('path "a" { capabilities = ["read", "reed"] }').rules[0]
    assert r.unknown == ["reed"]


def test_merge_and_priority_examples():
    acl = ACL([parse_policy('''
path "secret/data/payments/*" { capabilities = ["read"] }
path "secret/data/+/dev/*"    { capabilities = ["update"] }
path "secret/data/payments/prod/*" { capabilities = ["deny"] }
''', "a"), parse_policy('path "secret/data/payments/*" { capabilities = ["list"] }', "b")])
    d = acl.decide("secret/data/payments/db")
    assert d.capabilities == ["read", "list"] and {s.policy for s in d.entry.sources} == {"a", "b"}
    # The prefix rule's wildcard comes later in the path than the +: it wins
    assert acl.decide("secret/data/payments/dev/db").capabilities == ["read", "list"]
    assert acl.decide("secret/data/orders/dev/db").capabilities == ["update"]
    assert acl.decide("secret/data/payments/prod/db").capabilities == ["deny"]
    assert acl.decide("other").capabilities == ["deny"] and acl.decide("other").entry is None


# --------------------------------------------------------------------------- against Vault


SEGMENTS = ["a", "b", "ab", "c"]
MIXED = ["a", "A", "b", "ab", "aB", "c"]  # to check case-insensitive deny (Vault 2.2.2+)
CAPS = ["read", "list", "update", "create", "delete", "sudo", "patch"]


def _random_path(rnd: random.Random, vocab=SEGMENTS) -> str:
    parts = [("+" if rnd.random() < 0.3 else rnd.choice(vocab)) for _ in range(rnd.randint(1, 4))]
    path = "/".join(parts)
    ending = rnd.random()
    if ending < 0.25:
        path += "/*"
    elif ending < 0.4 and not path.endswith("+"):  # Vault refuses "+*"
        path += "*"
    elif ending < 0.5:
        path += "/"
    return path


def _random_policy(rnd: random.Random, vocab=SEGMENTS) -> str:
    rules = []
    for _ in range(rnd.randint(1, 6)):
        caps = ["deny"] if rnd.random() < 0.15 else rnd.sample(CAPS, rnd.randint(1, 3))
        rules.append(f'path "{_random_path(rnd, vocab)}" {{ capabilities = {caps!r} }}'.replace("'", '"'))
    return "\n".join(rules)


def _probe_paths(vocab=SEGMENTS, depth=4) -> list[str]:
    out = set()
    for n in range(1, depth + 1):
        for combo in itertools.product(vocab, repeat=n):
            p = "/".join(combo)
            out.add(p)
            out.add(p + "/")
    out |= {"a/abc", "ab/c/d/e/f", "c/a/b/ab/x", "abc", "a/b/abx/y"}
    return sorted(out)


def test_behaviour_for_versions():
    from lockstep.policy.acl import CURRENT, LEGACY, behaviour_for
    assert behaviour_for("1.21.4") is LEGACY and behaviour_for("2.2.1+ent") is LEGACY
    assert behaviour_for("2.2.2") is CURRENT and behaviour_for("v2.3.0") is CURRENT and behaviour_for(None) is CURRENT


def _check_against(addr: str, token: str, trials: int, vocab, depth: int, seed: int) -> None:
    from lockstep.policy.acl import behaviour_for
    v = httpx.Client(base_url=f"{addr}/v1/", headers={"X-Vault-Token": token}, timeout=20)
    version = v.get("sys/seal-status").json().get("version")
    behaviour = behaviour_for(version)
    rnd = random.Random(seed)
    paths = _probe_paths(vocab, depth)
    names = []
    try:
        for trial in range(trials):
            texts = [_random_policy(rnd, vocab) for _ in range(rnd.randint(1, 3))]
            pnames = [f"lockstep-acltest-{uuid.uuid4().hex[:8]}" for _ in texts]
            names += pnames
            for n, t in zip(pnames, texts):
                w = v.put(f"sys/policies/acl/{n}", json={"policy": t})
                assert w.status_code < 300, f"Vault refused {t!r}: {w.text}"
            tok = v.post("auth/token/create", json={"policies": pnames, "no_default_policy": True, "ttl": "5m"})
            tok.raise_for_status()
            token_ = tok.json()["auth"]["client_token"]
            r = v.post("sys/capabilities", json={"token": token_, "paths": paths})
            r.raise_for_status()
            vault = r.json()
            acl = ACL([parse_policy(t, n) for n, t in zip(pnames, texts)], behaviour)
            wrong = {p: (sorted(vault[p]), sorted(acl.decide(p).capabilities)) for p in paths
                     if sorted(vault[p]) != sorted(acl.decide(p).capabilities)}
            assert not wrong, (f"Vault {version} ({behaviour.label}), trial {trial}: policies {texts}\n"
                               f"vault vs lockstep: {dict(list(wrong.items())[:5])}")
            v.post("auth/token/revoke", json={"token": token_})
    finally:
        for n in names:
            v.delete(f"sys/policies/acl/{n}")


LATEST = os.environ.get("VAULT_LATEST_ADDR")
# The scheduled vault-release workflow explores more: other seeds each run, and more trials
FUZZ_SEED = int(os.environ.get("FUZZ_SEED", "0"))
FUZZ_SCALE = max(1, int(os.environ.get("FUZZ_SCALE", "1")))


def _latest_up() -> bool:
    if not LATEST:
        return False
    try:
        return httpx.get(f"{LATEST}/v1/sys/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(not _latest_up(), reason="no latest Vault (VAULT_LATEST_ADDR; the compose test profile starts one)")
@pytest.mark.parametrize("vocab,depth,trials,seed", [(SEGMENTS, 4, 150, 20261121), (MIXED, 3, 60, 20261122)])
def test_matching_agrees_with_the_latest_vault(vocab, depth, trials, seed):
    """The same checks against the newest Vault release, whose evaluation rules changed in 2.2.2."""
    _check_against(LATEST, "root-latest", trials * FUZZ_SCALE, vocab, depth, seed + FUZZ_SEED)


@pytest.mark.usefixtures("vaults")
def test_mixed_case_matching_agrees_with_vault(vaults):
    """Upper and lower case in rules and paths: deny rules ignore case from Vault 2.2.2."""
    _check_against(vaults[0], "root-a", 60, MIXED, 3, 20261122)


@pytest.mark.usefixtures("vaults")
def test_matching_agrees_with_vault(vaults):
    """Random policies: Lockstep's answer must equal Vault's for every probe path."""
    _check_against(vaults[0], "root-a", 150, SEGMENTS, 4, 20261121)
