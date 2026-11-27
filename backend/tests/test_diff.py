from lockstep.diff import SideInfo, diff_keys, diff_secret, summarize

P = SideInfo(state="present")


def st(keys):
    return {k.key: k.status for k in keys}


def test_key_statuses():
    assert st(diff_keys({"a": "1", "b": "x", "c": "z"}, {"a": "1", "b": "y", "d": "w"})) == {
        "a": "equal", "b": "different", "c": "left_only", "d": "right_only"}


def test_canonical_json_ignores_object_key_order():
    assert st(diff_keys({"t": {"a": 1, "b": 2}}, {"t": {"b": 2, "a": 1}})) == {"t": "equal"}


def test_type_difference_flagged():
    (k,) = diff_keys({"port": 5432}, {"port": "5432"})
    assert k.status == "different" and k.type_differs


def test_equal_secret():
    d = diff_secret("x", P, {"a": "1"}, P, {"a": "1"})
    assert d.status == "equal"


def test_different_secret():
    assert diff_secret("x", P, {"a": "1"}, P, {"a": "2"}).status == "different"
    assert diff_secret("x", P, {"a": "1"}, P, {"a": "1", "b": "2"}).status == "different"


def test_one_sided():
    d = diff_secret("x", P, {"a": "1"}, SideInfo(state="absent"), None)
    assert d.status == "left_only" and st(d.keys) == {"a": "left_only"}
    d = diff_secret("x", SideInfo(state="deleted", version=3), None, P, {"a": "1"})
    assert d.status == "right_only"


def test_no_access_hides_key_statuses():
    d = diff_secret("x", P, {"a": "1"}, SideInfo(state="no_access"), None)
    assert d.status == "no_access" and st(d.keys) == {"a": "unknown"}


def test_error_wins():
    d = diff_secret("x", SideInfo(state="error", error="boom"), None, SideInfo(state="no_access"), None)
    assert d.status == "error"


def test_no_values_in_output():
    d = diff_secret("x", P, {"pw": "hunter2"}, P, {"pw": "s3cret"})
    assert "hunter2" not in d.model_dump_json() and "s3cret" not in d.model_dump_json()


def test_summary():
    ds = [diff_secret("a", P, {"k": 1}, P, {"k": 1}), diff_secret("b", P, {"k": 1}, P, {"k": 2})]
    s = summarize(ds)
    assert s["equal"] == 1 and s["different"] == 1 and s["total"] == 2


# ---- structured values: where they differ, and why each key has its status

from lockstep.diff import changed_paths, structured  # noqa: E402
from lockstep.rules import Rules  # noqa: E402


def k1(left, right, **kw):
    (k,) = diff_keys({"v": left}, {"v": right}, **kw)
    return k


def test_changed_paths_in_objects_and_lists():
    a = {"db": {"host": "a", "port": 5432}, "hosts": ["x", "y", "z"], "tls": True, "odd key": 1}
    b = {"db": {"host": "b", "port": 5432}, "hosts": ["x", "y"], "extra": 1, "odd key": 2}
    paths, complete = changed_paths(a, b)
    assert paths == ["db.host", "extra", "hosts[2]", '["odd key"]', "tls"] and complete


def test_structured_strings_json_and_yaml():
    assert structured('{"a": 1}') == {"a": 1} and structured(" [1, 2] ") == [1, 2]
    assert structured("db:\n  host: a\n") == {"db": {"host": "a"}}
    assert structured("plain text") is None and structured("a: b") is None  # one line: not YAML
    assert structured("-----BEGIN CERTIFICATE-----\nMIIB:x\n-----END CERTIFICATE-----") is None
    assert structured("{not json") is None


def test_reason_names_the_fields_that_differ():
    k = k1({"config": {"db": {"host": "a", "user": "u"}}}, {"config": {"db": {"host": "b", "user": "u"}}})
    assert k.status == "different" and k.paths == ["config.db.host"] and k.reason == "different at `config.db.host`"
    k = k1('{"db": {"host": "a"}}', '{"db": {"host": "b"}}')  # JSON in a string
    assert k.paths == ["db.host"]
    k = k1("db:\n  host: a\n  port: 1\n", "db:\n  host: a\n  port: 2\n")  # YAML in a string
    assert k.paths == ["db.port"]
    many = k1({f"k{i}": i for i in range(5)}, {f"k{i}": i + 1 for i in range(5)})
    assert many.reason == "different at `k0`, `k1`, `k2` and 2 more" and len(many.paths) == 5


def test_reasons_for_text_and_types():
    assert k1("a\r\nb", "a\nb").reason == "differs only in line endings (CRLF and LF)"
    assert k1("secret ", "secret").reason == "differs only in spaces or newlines at the start or end"
    assert k1("Prod", "prod").reason == "differs only in upper and lower case"
    assert k1("x", "y").reason == "different value"
    assert k1(5432, "5432").reason == "different type: number on the left, text on the right"
    assert k1('{"a":1,"b":2}', '{"b": 2, "a": 1}').reason == "same content, written differently (spacing, key order or quoting)"
    k = k1('{"a": 1}', {"a": 1})
    assert k.status == "different" and k.reason == "same content, stored as text on the left and object on the right"
    (l, r) = diff_keys({"a": 1}, {"b": 1})
    assert (l.reason, r.reason) == ("only on the left", "only on the right")
    assert k1("same", "same").reason == "same value"


def test_reasons_with_profile_rules():
    rules = Rules.model_validate({"rewrites": [{"left": "test", "right": "dev"}],
                                  "ignore_keys": [{"key": "log_level"}, {"key": "config", "field": "db.password"},
                                                  {"key": "certs", "field": "tls.*", "path": "**/certs"}]})
    kw = dict(rules=rules, paths=("x",))
    k = k1("logs.test.internal", "logs.dev.internal", **kw)
    assert k.status == "equal" and k.rewritten and k.reason == "equal after rewrite `test → dev`"
    (k,) = diff_keys({"log_level": "debug"}, {"log_level": "info"}, rules=rules, paths=("x",))
    assert k.ignored and k.reason == "different value; ignored by profile rule `log_level`"
    cfg = dict(rules=rules, paths=("x",))
    (k,) = diff_keys({"config": {"db": {"password": "a", "host": "h"}}}, {"config": {"db": {"password": "b", "host": "h"}}},
                     **cfg)
    assert k.status == "different" and k.ignored and k.paths == []
    assert k.reason == "differs only in ignored fields (`db.password`; rule `config` field `db.password`)"
    (k,) = diff_keys({"config": {"db": {"password": "a", "host": "h"}}}, {"config": {"db": {"password": "b", "host": "i"}}},
                     **cfg)
    assert not k.ignored and k.paths == ["db.host"] and k.reason == "different at `db.host`; 1 ignored field"
    # a field rule covers what's under it, and globs; and only where its path matches
    (k,) = diff_keys({"certs": {"tls": {"a": 1, "b": {"c": 1}}}}, {"certs": {"tls": {"a": 2, "b": {"c": 2}}}}, rules=rules, paths=("app/certs",))
    assert k.ignored
    (k,) = diff_keys({"certs": {"tls": {"a": 1}}}, {"certs": {"tls": {"a": 2}}}, rules=rules, paths=("app/x",))
    assert not k.ignored


def test_secret_counts_field_ignores_as_ignored():
    rules = Rules.model_validate({"ignore_keys": [{"key": "config", "field": "token"}]})
    d = diff_secret("x", P, {"config": {"token": "a", "url": "u"}}, P, {"config": {"token": "b", "url": "u"}},
                    rules=rules)
    assert d.status == "equal" and d.ignored_keys == 1


def test_limits_are_said(monkeypatch):
    import lockstep.diff as diff
    deep_a, deep_b = {"v": 1}, {"v": 2}
    for _ in range(12):
        deep_a, deep_b = {"n": deep_a}, {"n": deep_b}
    paths, complete = changed_paths(deep_a, deep_b)
    assert not complete and len(paths) == 1 and paths[0].count(".") == diff.MAX_DEPTH - 1
    wide_a, wide_b = {f"k{i}": 0 for i in range(3000)}, {f"k{i}": 1 for i in range(3000)}
    paths, complete = changed_paths(wide_a, wide_b)
    assert not complete and len(paths) == diff.MAX_LEAVES
    k = k1(deep_a, deep_b)
    assert "(too big to list every field)" in k.reason


def test_reasons_and_paths_never_hold_values():
    k = k1({"password": "hunter2", "db": {"pw": "s3cret!"}}, {"password": "other", "db": {"pw": "x"}})
    assert "hunter2" not in k.model_dump_json() and "s3cret!" not in k.model_dump_json()
    assert "hunter2" not in k1("hunter2", "Hunter2").model_dump_json()


# ---- phase 3 profile rules: unordered lists, volatile patterns, scoped rewrites

def test_unordered_lists():
    rules = Rules.model_validate({"unordered_keys": [
        {"key": "hosts"}, {"key": "domains", "separator": ","}, {"key": "config", "field": "tls.sans"}]})
    kw = dict(rules=rules, paths=("x",))
    (k,) = diff_keys({"hosts": ["a", "b", "c"]}, {"hosts": ["c", "a", "b"]}, **kw)
    assert k.status == "equal" and k.reason == "same items in a different order (rule `hosts`)"
    (k,) = diff_keys({"hosts": '["a", "b"]'}, {"hosts": '["b", "a"]'}, **kw)
    assert k.status == "equal"
    (k,) = diff_keys({"hosts": ["a", "a", "b"]}, {"hosts": ["a", "b", "b"]}, **kw)  # duplicates count
    assert k.status == "different" and k.reason == "different items (order ignored by rule `hosts`)" and k.paths == []
    (k,) = diff_keys({"domains": "a.com, b.com"}, {"domains": "b.com,a.com"}, **kw)
    assert k.status == "equal"
    (k,) = diff_keys({"domains": "a.com, b.com"}, {"domains": "b.com,c.com"}, **kw)
    assert k.status == "different"
    left = {"config": {"tls": {"sans": ["x", "y"]}, "port": 1}}
    (k,) = diff_keys(left, {"config": {"tls": {"sans": ["y", "x"]}, "port": 1}}, **kw)
    assert k.status == "equal" and k.reason == "same items in a different order (rule `config` field `tls.sans`)"
    (k,) = diff_keys(left, {"config": {"tls": {"sans": ["y", "z"]}, "port": 2}}, **kw)
    assert k.status == "different" and k.paths == ["port", "tls.sans"]  # the list, not an index inside it
    (k,) = diff_keys({"other": ["a", "b"]}, {"other": ["b", "a"]}, **kw)  # no rule: order counts
    assert k.status == "different" and k.paths == ["[0]", "[1]"]


def test_volatile_patterns():
    rules = Rules.model_validate({"volatile": [
        {"key": "*", "path": "apps/**", "pattern": r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z"}]})
    kw = dict(rules=rules, paths=("apps/web",))
    (k,) = diff_keys({"build": "v1 built 2026-01-01T10:00:00Z"}, {"build": "v1 built 2026-02-03T11:12:13Z"}, **kw)
    assert k.status == "different" and k.ignored
    assert k.reason == r"differs only in values matching volatile pattern `\d{4}-\d{2}-\d{2}T[0-9:.]+Z` (rule `*` under apps/**)"
    (k,) = diff_keys({"build": "v1 built 2026-01-01T10:00:00Z"}, {"build": "v2 built 2026-02-03T11:12:13Z"}, **kw)
    assert not k.ignored
    (k,) = diff_keys({"build": "2026-01-01T10:00:00Z"}, {"build": "2026-02-03T11:12:13Z"}, rules=rules, paths=("db/x",))
    assert not k.ignored  # out of the rule's path
    d = diff_secret("apps/web", P, {"cfg": {"at": "2026-01-01T10:00:00Z", "n": 1}}, P,
                    {"cfg": {"at": "2026-05-01T10:00:00Z", "n": 1}}, rules=rules)
    assert d.status == "equal" and d.ignored_keys == 1


def test_volatile_patterns_validated():
    import pytest
    from pydantic import ValidationError
    for bad, msg in (("(", "valid regex"), (r"\d*", "matches empty"), (r"(a+)+b", "repeats a group")):
        with pytest.raises(ValidationError, match=msg):
            Rules.model_validate({"volatile": [{"key": "*", "pattern": bad}]})


def test_scoped_rewrites():
    rules = Rules.model_validate({"rewrites": [{"left": "test", "right": "dev", "key": "*host*"}]})
    kw = dict(rules=rules, paths=("x",))
    a, p = diff_keys({"db_host": "db.test.internal", "password": "test-1"}, {"db_host": "db.dev.internal", "password": "dev-1"}, **kw)
    assert a.status == "equal" and a.rewritten and a.reason == "equal after rewrite `test → dev`"
    assert p.status == "different" and not p.rewritten
    assert rules.rewrite("test", key="password", paths=("x",)) == "test"
    assert rules.rewrite("test", key="api_host", paths=("x",)) == "dev"
    assert rules.rewrite("dev", to="left", key="api_host", paths=("x",)) == "test"
    assert rules.rewrite("test") == "dev"  # no key: every rewrite
    under = Rules.model_validate({"rewrites": [{"left": "test", "right": "dev", "path": "apps/**"}]})
    assert under.rewrite("test", key="k", paths=("apps/a",)) == "dev"
    assert under.rewrite("test", key="k", paths=("db/a",)) == "test"
    assert Rules.model_validate({"rewrites": [{"left": "a", "right": "b", "key": " ", "path": "/"}]}).rewrites[0].scoped is False
