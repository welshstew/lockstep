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
