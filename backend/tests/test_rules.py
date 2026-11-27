"""Profile rules: globs, mappings, ignores, pairing. Pure unit tests."""

import pytest
from pydantic import ValidationError

from lockstep.rules import Mapping, Rules, compile_glob, pair_paths

ENV = Rules(mappings=[{"left": "services/*/prod/**", "right": "services/*/staging/**"}])


@pytest.mark.parametrize("pattern,path,ok", [
    ("a/*", "a/b", True), ("a/*", "a/b/c", False), ("a/**", "a/b/c", True), ("a/**", "a", True),
    ("**/x", "a/b/x", True), ("*_url", "cdn_url", True), ("a/*/c", "a/b/c", True), ("a.b", "aXb", False),
])
def test_globs(pattern, path, ok):
    assert bool(compile_glob(pattern).match(path)) is ok


def test_mapping_both_ways_with_captures():
    assert ENV.to_right("services/billing/prod/db/main") == "services/billing/staging/db/main"
    assert ENV.to_left("services/billing/staging/db/main") == "services/billing/prod/db/main"
    assert ENV.to_right("services/billing/prod") == "services/billing/staging"
    assert ENV.to_right("other/path") == "other/path"  # unmapped: as is


def test_first_matching_mapping_wins():
    r = Rules(mappings=[{"left": "a/special", "right": "b/special-v2"}, {"left": "a/*", "right": "b/*"}])
    assert r.to_right("a/special") == "b/special-v2" and r.to_right("a/x") == "b/x"


def test_mapping_wildcards_must_match():
    with pytest.raises(ValidationError, match="same wildcards"):
        Mapping(left="a/*/b", right="c/**")


def test_ignored_keys_scoped_by_path():
    r = Rules(ignore_keys=[{"key": "host"}, {"key": "*_url", "path": "frontend/**"}])
    assert r.key_ignored("host", "anything")
    assert r.key_ignored("cdn_url", "frontend/settings") and not r.key_ignored("cdn_url", "backend/x")
    assert not r.key_ignored("hostname", "x")


def test_pairing_with_mapping_ignores_and_collisions():
    left = {"services/a/prod/db", "services/b/prod/db", "legacy/x", "services/a/staging/db"}
    right = {"services/a/staging/db", "services/c/staging/q"}
    rules = Rules(mappings=ENV.mappings, ignore_paths=["legacy/**"])
    pairs, collisions, ignored = pair_paths(left, right, rules)
    assert ignored == 1 and "legacy/x" not in pairs
    # services/a/prod/db maps onto services/a/staging/db, which also exists on the left as is
    assert collisions == {"services/a/staging/db": ["services/a/prod/db", "services/a/staging/db"]}
    assert pairs["services/b/staging/db"] == ("services/b/prod/db", "services/b/staging/db")  # left only
    assert pairs["services/c/staging/q"] == ("services/c/prod/q", "services/c/staging/q")  # right only


def test_no_rules_is_identity():
    pairs, collisions, ignored = pair_paths({"a", "b"}, {"b", "c"}, None)
    assert pairs == {"a": ("a", "a"), "b": ("b", "b"), "c": ("c", "c")} and not collisions and ignored == 0


# ---- value rewrites

ENVS = Rules(rewrites=[{"left": "enterprise-logging-app", "right": "elp"}, {"left": "test", "right": "dev"}])


@pytest.mark.parametrize("left,right", [
    ("https://ingest.test.logging.example.internal", "https://ingest.dev.logging.example.internal"),
    ("enterprise-logging-app-test", "elp-dev"),  # both words, in one pass
    ("svc-enterprise-logging-app@test.example.internal", "svc-elp@dev.example.internal"),
    ("latest-contest", "latest-contest"),  # whole words only
    ("Test", "Test"),  # case matters
])
def test_rewrites_whole_words(left, right):
    assert ENVS.rewrite(left) == right
    assert ENVS.rewrite(right, to="left") == left or left == right


def test_rewrites_keep_types_and_skip_opaque_values():
    assert ENVS.rewrite({"a": ["test", 5432, True], "b": None}) == {"a": ["dev", 5432, True], "b": None}
    pem = "-----BEGIN CERTIFICATE-----\nMIIB test\n-----END CERTIFICATE-----\n"
    assert ENVS.rewrite(pem) == pem
    b64 = "dGVzdA" * 20
    assert ENVS.rewrite(b64) == b64


def test_rewrites_validated():
    with pytest.raises(ValidationError, match="the same"):
        Rules(rewrites=[{"left": "dev", "right": "dev"}])
    with pytest.raises(ValidationError, match="more than one rewrite"):
        Rules(rewrites=[{"left": "test", "right": "dev"}, {"left": "qa", "right": "dev"}])
    assert not Rules(rewrites=[{"left": "test", "right": "dev"}]).empty


def test_diff_counts_keys_equal_after_rewrites():
    from lockstep.diff import SideInfo, diff_secret
    here = SideInfo(state="present", version=1)
    d = diff_secret("x", here, {"url": "logs.test.internal", "port": "1"}, here, {"url": "logs.dev.internal", "port": "2"},
                    rules=ENVS)
    keys = {k.key: k for k in d.keys}
    assert keys["url"].status == "equal" and keys["url"].rewritten
    assert keys["port"].status == "different" and d.status == "different" and d.rewritten_keys == 1


# ---- suggesting rules from the two sides

def test_suggest_mapping_for_a_renamed_folder():
    from lockstep.profile_suggest import suggest_mappings
    left = {"enterprise-logging-app/values", "enterprise-logging-app/certs", "enterprise-logging-app/legacy-syslog", "shared/x"}
    right = {"ELP/values", "ELP/certs", "ELP/alerts", "shared/x"}
    (m,) = suggest_mappings(left, right, Rules())
    assert (m.left, m.right) == ("enterprise-logging-app/**", "ELP/**")
    assert m.pairs == [("enterprise-logging-app/certs", "ELP/certs"), ("enterprise-logging-app/values", "ELP/values")]
    assert "rename" in m.reason and "(certs, values)" in m.reason
    assert "1 secret only on the left and 1 secret only on the right remain" in m.reason
    assert suggest_mappings(left, right, Rules(mappings=[{"left": m.left, "right": m.right}])) == []


def test_suggest_mapping_generalises_an_environment_segment():
    from lockstep.profile_suggest import suggest_mappings
    left = {"services/billing/prod/db", "services/billing/prod/api", "services/search/prod/config"}
    right = {"services/billing/staging/db", "services/billing/staging/api", "services/search/staging/config"}
    out = suggest_mappings(left, right, Rules())
    assert [(m.left, m.right) for m in out] == [("services/*/prod/**", "services/*/staging/**")]
    assert len(out[0].pairs) == 3 and "wildcard" in out[0].reason
    # one service only: the wildcard still wins (it pairs as many, and covers services added later)
    out = suggest_mappings({"services/billing/prod/db", "services/search/prod/x"},
                           {"services/billing/staging/db", "services/orders/staging/y"}, Rules())
    assert [(m.left, m.right) for m in out] == [("services/*/prod/**", "services/*/staging/**")]


def test_suggest_rewrites_from_visible_words_only():
    from lockstep.diff import KeyDiff, SecretDiff, SideInfo
    from lockstep.profile_suggest import ValuePairs, suggest_rewrites
    here = SideInfo(state="present")
    left = {"ingest": "https://ingest.test.example", "prefix": "enterprise-logging-app-test",
            "account": "svc-enterprise-logging-app", "token": "tok-test-aaaa", "pw": "hunter2-left"}
    right = {"ingest": "https://ingest.dev.example", "prefix": "elp-dev",
             "account": "svc-elp", "token": "tok-dev-bbbb", "pw": "hunter2-right"}
    d = SecretDiff(path="ELP/values", status="different", left=here, right=here,
                   keys=[KeyDiff(key=k, status="different") for k in left])
    values = ValuePairs()
    values.observe(d, left, right)
    out = suggest_rewrites(values, Rules(), {"enterprise-logging-app/values", "ELP/values"})
    assert {(r.left, r.right) for r in out} == {("test", "dev"), ("enterprise-logging-app", "elp")}
    by = {r.left: r for r in out}
    assert by["test"].keys == 2 and by["enterprise-logging-app"].keys == 2  # prefix needs both
    assert all("left" not in r.left and "right" not in r.right for r in out)  # never a fragment of a value
