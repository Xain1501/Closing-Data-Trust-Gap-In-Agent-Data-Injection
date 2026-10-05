from models import Direction, ParseStatus, ToolTraffic
from parser import parse


def T(payload, tool="read_email"):
    return ToolTraffic(direction=Direction.POST_HOP, tool_name=tool, payload=payload)


def kinds(r):
    return [f.kind for f in r.findings]


def test_clean_json_has_paths():
    r = parse(T('{"emails": [{"from": "a@b.com", "body": "Meeting at 3pm"}]}'))
    assert r.status is ParseStatus.OK
    assert {"$", "$.emails", "$.emails[0]", "$.emails[0].body"} <= {f.path for f in r.fields}


def test_parse_has_no_score():          # the split: parsing carries no scoring
    r = parse(T('{"a": 1}'))
    assert not hasattr(r, "structural_score")


def test_parent_links_form_a_tree():
    by = {f.path: f for f in parse(T('{"a": {"b": 1}}')).fields}
    assert by["$.a.b"].parent_path == "$.a" and by["$"].parent_path is None


def test_duplicate_keys_not_collapsed():
    r = parse(T('{"to": "alice", "to": "attacker"}'))
    assert r.status is ParseStatus.OK and "duplicate_key" in kinds(r)
    assert {"$.to", "$.to#2"} <= {f.path for f in r.fields}


def test_non_json_is_untrusted_blob_with_status():
    r = parse(T("emails:\n- from: a@b.com"))
    assert r.status is ParseStatus.INVALID_JSON and len(r.fields) == 1


def test_nan_rejected():
    assert parse(T('{"x": NaN}')).status is ParseStatus.INVALID_JSON


def test_depth_limit_sets_status():
    assert parse(T("[" * 50 + "]" * 50)).status is ParseStatus.TOO_DEEP
