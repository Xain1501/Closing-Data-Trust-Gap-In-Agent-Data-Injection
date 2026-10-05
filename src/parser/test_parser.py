import json

import pytest

try:
    from .models import Direction, ParseStatus, ToolTraffic
    from .parser import MAX_BYTES, parse
except ImportError:  # flat-folder layout
    from models import Direction, ParseStatus, ToolTraffic
    from parser import MAX_BYTES, parse


def T(payload, tool="read_email"):
    return ToolTraffic(direction=Direction.POST_HOP, tool_name=tool, payload=payload)


def kinds(r):
    return [f.kind for f in r.findings]


# ---- normal behaviour -------------------------------------------------------
def test_clean_json_has_paths():
    r = parse(T('{"emails": [{"from": "a@b.com", "body": "Meeting at 3pm"}]}'))
    assert r.status is ParseStatus.OK
    assert {"$", "$.emails", "$.emails[0]", "$.emails[0].body"} <= {f.path for f in r.fields}


def test_parse_has_no_score():          # parsing carries no scoring
    assert not hasattr(parse(T('{"a": 1}')), "structural_score")


def test_parent_links_form_a_tree():
    by = {f.path: f for f in parse(T('{"a": {"b": 1}}')).fields}
    assert by["$.a.b"].parent_path == "$.a" and by["$"].parent_path is None


def test_duplicate_keys_not_collapsed():
    r = parse(T('{"to": "alice", "to": "attacker"}'))
    assert r.status is ParseStatus.OK and "duplicate_key" in kinds(r)
    assert {"$.to", "$.to#2"} <= {f.path for f in r.fields}


def test_nested_duplicate_keys():
    r = parse(T('{"a": {"x": 1, "x": 2}}'))
    assert "duplicate_key" in kinds(r) and "$.a.x#2" in {f.path for f in r.fields}


# ---- failure statuses (malformed != malicious) -------------------------------
def test_non_json_is_untrusted_blob_with_status():
    r = parse(T("emails:\n- from: a@b.com"))
    assert r.status is ParseStatus.INVALID_JSON and len(r.fields) == 1


def test_nan_rejected():
    assert parse(T('{"x": NaN}')).status is ParseStatus.INVALID_JSON


def test_depth_limit_sets_status():
    assert parse(T("[" * 50 + "]" * 50)).status is ParseStatus.TOO_DEEP


def test_too_large_sets_status():
    assert parse(T('"' + "a" * (MAX_BYTES + 10) + '"')).status is ParseStatus.TOO_LARGE


@pytest.mark.parametrize("text", ["", "   ", '{"a":1,}', '{"a":1} // c', "{'a': 1}", "a: 1", '{"a":1}{"b":2}', "[1,2"])
def test_strict_json_only_everything_else_is_invalid(text):
    assert parse(T(text)).status is ParseStatus.INVALID_JSON


# ---- valid-but-unusual JSON --------------------------------------------------
@pytest.mark.parametrize("text,n_fields", [('"hi"', 1), ("5", 1), ("null", 1), ("true", 1), ("[]", 1), ("{}", 1)])
def test_top_level_scalars_and_empty_containers_are_ok(text, n_fields):
    r = parse(T(text))
    assert r.status is ParseStatus.OK and len(r.fields) == n_fields


def test_leading_bom_is_tolerated():
    assert parse(T('\ufeff{"a": 1}')).status is ParseStatus.OK


def test_unusual_key_paths_stay_unique_and_readable():
    r = parse(T('{"a.b": 1, "a b": 2, "k": {"a.b": 3}}'))
    paths = [f.path for f in r.fields]
    assert len(paths) == len(set(paths)) and '$["a.b"]' in paths


def test_unicode_keys_and_values():
    r = parse(T('{"名前": "テスト", "emoji": "\U0001F600"}'))
    assert r.status is ParseStatus.OK and len(r.fields) == 3


def test_dict_payload_with_non_json_types_is_converted():
    import datetime
    r = parse(T({"when": datetime.datetime(2026, 1, 1)}))
    assert r.status is ParseStatus.OK


def test_large_flat_list_is_ok():
    assert parse(T(json.dumps(list(range(5000))))).status is ParseStatus.OK