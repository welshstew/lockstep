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
    from lockstep.policy.acl import CURRENT, LEGACY, OPENBAO, UNKNOWN, behaviour_for
    assert behaviour_for("1.21.4") is LEGACY and behaviour_for("2.2.1+ent") is LEGACY
    assert behaviour_for("2.2.2") is CURRENT and behaviour_for("v2.3.0") is CURRENT
    # OpenBao's version numbers say nothing about Vault's rules: it has its own
    assert behaviour_for("2.7.3", "OpenBao") is OPENBAO and behaviour_for("2.0.0", "OpenBao") is OPENBAO
    assert behaviour_for(None) is UNKNOWN and behaviour_for("dev") is UNKNOWN
    assert not UNKNOWN.known and UNKNOWN.lookup == "current" and CURRENT.known


def test_openbao_tries_the_path_as_written_before_trimming_the_slash():
    """OpenBao 2.7.3 (internal/vault/policy/acl.go): exact rule, then (lists) the exact rule without
    the trailing slash, then the best wildcard rule for the path as written, then for the path without
    the slash. Vault 2.2.2 pools both forms; Vault 2.2.1 trims first."""
    from lockstep.policy.acl import CURRENT, LEGACY, OPENBAO
    pols = [parse_policy('path "b*" { capabilities = ["read", "update", "patch"] }\n'
                         'path "b/+" { capabilities = ["read", "patch"] }', "p")]
    bao = ACL(pols, OPENBAO)
    assert bao.decide("b/").capabilities == ["read", "patch"]  # b/+ matches "b/" (an empty segment)
    assert bao.decide("b/a/").capabilities == ["read", "update", "patch"]  # b/+ can't match 3 segments
    assert ACL(pols, CURRENT).decide("b/a/").capabilities == ["read", "patch"]  # pooled with "b/a"
    assert ACL(pols, LEGACY).decide("b/").capabilities == ["read", "update", "patch"]  # "b" first
    # Only as a fallback: the trimmed form when nothing matches the path as written
    trim = ACL([parse_policy('path "c/+" { capabilities = ["list"] }', "p")], OPENBAO)
    assert trim.decide("c/x/").capabilities == ["list"] and trim.decide("c/x/", list_op=False).capabilities == ["deny"]
    # No case-insensitive deny on OpenBao
    mixed = ACL([parse_policy('path "a/*" { capabilities = ["read"] }\npath "A/*" { capabilities = ["deny"] }', "p")], OPENBAO)
    assert mixed.decide("a/x").capabilities == ["read"]


def test_openbao_scan_capability():
    from lockstep.policy.acl import OPENBAO
    r = parse_policy('path "kv/metadata/*" { capabilities = ["scan", "list"] }').rules[0]
    assert r.unknown == []
    assert ACL([parse_policy('path "kv/metadata/*" { capabilities = ["scan", "list"] }', "p")],
               OPENBAO).decide("kv/metadata/a/").capabilities == ["list", "scan"]


def _check_against(addr: str, token: str, trials: int, vocab, depth: int, seed: int) -> None:
    from lockstep.policy.acl import behaviour_for
    from lockstep.vault import product_of
    v = httpx.Client(base_url=f"{addr}/v1/", headers={"X-Vault-Token": token}, timeout=20)
    seal = v.get("sys/seal-status").json()
    version = seal.get("version")
    behaviour = behaviour_for(version, product_of(seal, v.get("sys/internal/ui/mounts").json()))
    assert behaviour.known, f"{addr}: couldn't tell which evaluation rules {version} uses"
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
            assert not wrong, (f"{addr} {version} ({behaviour.label}), trial {trial}: policies {texts}\n"
                               f"vault vs lockstep: {dict(list(wrong.items())[:5])}")
            v.post("auth/token/revoke", json={"token": token_})
    finally:
        for n in names:
            v.delete(f"sys/policies/acl/{n}")


LEGACY_ADDR = os.environ.get("VAULT_LEGACY_ADDR")
# The scheduled vault-release workflow explores more: other seeds each run, and more trials
FUZZ_SEED = int(os.environ.get("FUZZ_SEED", "0"))
FUZZ_SCALE = max(1, int(os.environ.get("FUZZ_SCALE", "1")))


def _legacy_up() -> bool:
    if not LEGACY_ADDR:
        return False
    try:
        return httpx.get(f"{LEGACY_ADDR}/v1/sys/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(not _legacy_up(), reason="no Vault 1.x (VAULT_LEGACY_ADDR; the compose test profile starts one)")
@pytest.mark.parametrize("vocab,depth,trials,seed", [(SEGMENTS, 4, 150, 20261121), (MIXED, 3, 60, 20261122)])
def test_matching_agrees_with_a_vault_1x(vocab, depth, trials, seed):
    """The same checks against Vault 1.21, whose evaluation rules (before 2.2.2) Lockstep still follows
    for Vaults that report a 1.x version."""
    _check_against(LEGACY_ADDR, "root-legacy", trials * FUZZ_SCALE, vocab, depth, seed + FUZZ_SEED)


# Vault A and Vault B: under `make test-openbao` (and the weekly openbao workflow) Vault B is OpenBao
SIDES = [pytest.param(0, "root-a", id="vault-a"), pytest.param(1, "root-b", id="vault-b")]


@pytest.mark.usefixtures("vaults")
@pytest.mark.parametrize("side,token", SIDES)
def test_mixed_case_matching_agrees_with_vault(vaults, side, token):
    """Upper and lower case in rules and paths: deny rules ignore case from Vault 2.2.2."""
    _check_against(vaults[side], token, 60, MIXED, 3, 20261122)


@pytest.mark.usefixtures("vaults")
@pytest.mark.parametrize("side,token", SIDES)
def test_matching_agrees_with_vault(vaults, side, token):
    """Random policies: Lockstep's answer must equal Vault's for every probe path."""
    _check_against(vaults[side], token, 150, SEGMENTS, 4, 20261121)
