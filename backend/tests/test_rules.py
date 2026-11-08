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
