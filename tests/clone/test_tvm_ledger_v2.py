"""TVM schema v2, ledger skeleton storage, and the clone fixes that go with them.

T1 lookup by name    T3 loader validation    T5 hashable entries    profile() for tagging
L7 get_record copy   skeletons.jsonl + skeleton_sha256              C2 / C3 core lookups
D1 JSON formatter by default                 A6 settings live on the core only
"""
from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite import load_suites
from agentdojo.types import ChatAssistantMessage

from clone.core import InterceptionCore
from clone.interceptor import TrustVerificationToolsExecutor
from clone.ledger import InterceptionLedger
from clone.tvm import ToolMatrixEntry, TrustMatrix, load_tool_matrix
from pipeline.clone_parser_detector import parser_detector


def entry(name="demo", keys=("value",), tid=None, **kw):
    return ToolMatrixEntry(tool_name=name, internal_tool_id=tid or f"test.{name}", impact_tier=1,
                           impact_tier_source="policy default", expected_keys=keys, **kw)


# ---- the shipped matrix -----------------------------------------------------------
def test_every_agentdojo_suite_tool_resolves_to_a_real_entry():
    """Replaces the hardcoded '== 70': each live tool definition must find its entry."""
    matrix = load_tool_matrix()
    checked = 0
    for suite in load_suites._SUITES["v1"].values():
        runtime = FunctionsRuntime(suite.tools)
        for name, definition in runtime.functions.items():
            found = matrix.lookup(name, set(definition.parameters.model_fields))
            assert not found.is_fallback and found.keys_match, name
            checked += 1
    assert checked >= 60


def test_shipped_entries_convert_to_tagging_profiles():
    from trust_graph.tagging import ProfileEntry
    for e in load_tool_matrix().entries:
        profile = e.profile()
        assert isinstance(profile, ProfileEntry) and profile.tool_name == e.tool_name
        assert not profile.usable                     # draft until reviewed


# ---- T1: lookup -------------------------------------------------------------------
def test_t1_single_entry_matches_by_name_even_when_arguments_drift():
    matrix = TrustMatrix((entry("demo", ("value",)),))
    exact = matrix.lookup("demo", {"value"})
    drifted = matrix.lookup("demo", {"value", "new_arg"})
    assert exact.keys_match and not exact.is_fallback
    assert not drifted.is_fallback and drifted.keys_match is False
    assert drifted.internal_tool_id == "test.demo" and drifted.impact_tier == 1
    assert matrix.lookup("demo").keys_match is True            # name only (C2 path)


def test_t1_same_name_variants_are_picked_by_arguments():
    a = entry("send_email", ("to", "body"), tid="ws.send_email")
    b = entry("send_email", ("recipient", "body"), tid="slack.send_email")
    matrix = TrustMatrix((a, b))
    assert matrix.lookup("send_email", {"to", "body"}) is a
    assert matrix.lookup("send_email", {"recipient", "body"}) is b
    assert matrix.lookup("send_email", {"other"}).is_fallback   # ambiguous: no guessing
    assert matrix.lookup("send_email").is_fallback


def test_t1_unknown_tool_is_unclassified():
    found = TrustMatrix((entry(),)).lookup("made_up", {"x"})
    assert found.is_fallback and found.internal_tool_id == "unclassified:made_up"


def test_real_matrix_send_email_variants_still_resolve():
    matrix = load_tool_matrix()
    variants = [e for e in matrix.entries if e.tool_name == "send_email"]
    for v in variants:
        assert matrix.lookup("send_email", set(v.expected_keys)) is v


# ---- entries: hashable, immutable, profile ----------------------------------------
def test_t5_entries_are_hashable_and_immutable():
    e = entry(args={"value": "AUTHORITY_ARG"}, result_fields={"$.id": "SYSTEM"})
    assert {e: 1}[entry(args={"value": "AUTHORITY_ARG"}, result_fields={"$.id": "SYSTEM"})] == 1
    with pytest.raises(FrozenInstanceError):
        e.impact_tier = 10
    assert e.arg_roles == {"value": "AUTHORITY_ARG"} and e.authority_arguments == ("value",)


def test_profile_carries_roles_and_overrides():
    from trust_graph.tagging import Provenance, Role
    e = entry(keys=("recipient", "amount"), args={"recipient": "AUTHORITY_ARG", "amount": "CONTENT"},
              result_fields={"$.id": "SYSTEM"}, review_status="approved")
    p = e.profile()
    assert p.usable and p.args["recipient"] is Role.AUTHORITY_ARG
    assert p.result_fields["$.id"] is Provenance.SYSTEM and p.result_default is Provenance.EXTERNAL


# ---- T3: loader validation --------------------------------------------------------
def _write(tmp_path, tools, version=2):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"schema_version": version, "tools": tools}), encoding="utf-8")
    return path


GOOD = {"tool_name": "t", "internal_tool_id": "x.t", "impact_tier": 5, "impact_tier_source": "policy default",
        "expected_keys": ["a", "b"]}


def test_t3_minimal_entry_loads_with_defaults(tmp_path):
    (e,) = load_tool_matrix(_write(tmp_path, [GOOD])).entries
    assert (e.args, e.result_format, e.result_default, e.review_status) == ((), "json", "EXTERNAL", "draft")


@pytest.mark.parametrize("change,message", [
    ({"impact_tier": None, "tool_name": None}, None),
    ({"args": {"zzz": "AUTHORITY_ARG"}}, "not in expected_keys"),
    ({"args": {"a": "BOSS"}}, "unknown role"),
    ({"result_fields": {"$.x": "USER"}}, "SYSTEM or EXTERNAL"),
    ({"result_fields": {"x": "SYSTEM"}}, "start with '\\$'"),
    ({"result_format": "yaml"}, "result_format"),
    ({"review_status": "maybe"}, "review_status"),
    ({"expected_keys": ["a", "a"]}, "duplicates"),
    ({"impact_tier": 7}, "invalid impact tier"),
    ({"field_trust_classes": {"a": "unclassified"}}, "schema v1"),
])
def test_t3_bad_entries_give_clear_errors(tmp_path, change, message):
    raw = {**GOOD, **change}
    if message is None:                                  # missing required field
        del raw["impact_tier"]
        message = "missing required field"
    with pytest.raises(ValueError, match=message):
        load_tool_matrix(_write(tmp_path, [raw]))


def test_t3_rejects_old_schema_and_duplicates(tmp_path):
    with pytest.raises(ValueError, match="schema_version 2"):
        load_tool_matrix(_write(tmp_path, [GOOD], version=1))
    with pytest.raises(ValueError, match="Duplicate matrix entry"):
        load_tool_matrix(_write(tmp_path, [GOOD, {**GOOD, "internal_tool_id": "y"}]))
    with pytest.raises(ValueError, match="Duplicate internal_tool_id"):
        load_tool_matrix(_write(tmp_path, [GOOD, {**GOOD, "expected_keys": ["a"]}]))


# ---- L7 -----------------------------------------------------------------------------
def test_l7_get_record_returns_a_copy():
    ledger = InterceptionLedger()
    record = ledger.capture("run", "post", "c", "text")
    copy = ledger.get_record(record.interception_id)
    copy.state = "tampered"
    copy.label = "tampered"
    assert record.state == "captured" and ledger.get_record(record.interception_id).label is None


# ---- skeleton storage -----------------------------------------------------------------
def _core(ledger, matrix=None, detector=parser_detector):
    return InterceptionCore(ledger, detector, matrix or TrustMatrix((entry(),)), mode="enforce")


def test_skeleton_is_stored_hashed_and_chained(tmp_path):
    ledger = InterceptionLedger(storage_dir=tmp_path)
    core = _core(ledger)
    call = core.check_call("run", "c1", "demo", {"value": "x"}, {"value"})
    raw = {"id": 1, "body": "hello"}
    result = core.check_result("run", "c1", call.record.interception_id, "demo", json.dumps(raw), raw_result=raw)
    record = result.record
    assert record.skeleton_sha256 and ledger.ledger[-1].skeleton_sha256 == record.skeleton_sha256
    stored = ledger.get_skeleton(record.interception_id)
    assert stored["status"] == "ok" and [f["path"] for f in stored["fields"]] == ["$", "$.id", "$.body"]
    assert stored["interception_id"] == record.interception_id
    rows = [json.loads(line) for line in (tmp_path / "skeletons.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["interception_id"] == record.interception_id
    assert ledger.verify_chain()


def test_no_skeleton_for_pre_hop_text_results_or_no_raw_object():
    ledger = InterceptionLedger()
    core = _core(ledger)
    call = core.check_call("run", "c1", "demo", {"value": "x"}, {"value"})
    assert call.record.skeleton_sha256 is None
    no_raw = core.check_result("run", "c1", call.record.interception_id, "demo", '{"a": 1}')
    assert no_raw.record.skeleton_sha256 is None and ledger.skeletons == []
    text = core.check_result("run", "c1", call.record.interception_id, "demo", "ok", raw_result="ok")
    assert ledger.get_skeleton(text.record.interception_id)["status"] == "unstructured"


def test_skeleton_cannot_be_attached_twice_or_to_pre_hop():
    ledger = InterceptionLedger()
    post = ledger.capture("run", "post", "c", "text")
    ledger.attach_skeleton(post, {"status": "ok", "fields": []})
    with pytest.raises(ValueError, match="already attached"):
        ledger.attach_skeleton(post, {"status": "ok", "fields": []})
    with pytest.raises(ValueError, match="post-hop"):
        ledger.attach_skeleton(ledger.capture("run", "pre", "c", {"a": 1}), {})


def test_clear_empties_skeletons(tmp_path):
    ledger = InterceptionLedger(storage_dir=tmp_path)
    ledger.attach_skeleton(ledger.capture("run", "post", "c", "t"), {"status": "ok", "fields": []})
    ledger.clear()
    assert ledger.skeletons == [] and (tmp_path / "skeletons.jsonl").read_text(encoding="utf-8") == ""


# ---- C2 / C3 -----------------------------------------------------------------------
def test_c2_result_without_pre_record_finds_the_tool_by_name():
    ledger = InterceptionLedger()
    core = _core(ledger, detector=lambda _: True)
    result = core.check_result("run", "c1", "missing-pre-id", "demo", "text")
    assert result.record.internal_tool_id == "test.demo" and result.record.matrix_classified


def test_c3_post_hop_reuses_the_pre_hop_entry_by_id():
    ledger = InterceptionLedger()
    matrix = TrustMatrix((entry("demo", ("value",)),))
    core = _core(ledger, matrix=matrix, detector=lambda _: True)
    call = core.check_call("run", "c1", "demo", {"value": "x", "extra": 1}, {"value", "extra"})
    assert call.record.matrix_keys_match is False and call.record.internal_tool_id == "test.demo"
    result = core.check_result("run", "c1", call.record.interception_id, "demo", "t")
    assert result.record.internal_tool_id == "test.demo" and result.record.impact_tier == 1


def test_unclassified_pre_hop_gives_unclassified_post_hop():
    ledger = InterceptionLedger()
    core = InterceptionCore(ledger, lambda _: True, TrustMatrix((entry(),)), mode="passthrough")
    call = core.check_call("run", "c1", "made_up", {"x": 1}, {"x"})
    result = core.check_result("run", "c1", call.record.interception_id, "made_up", "t")
    assert result.record.internal_tool_id == "unclassified:made_up" and not result.record.matrix_classified
    assert call.record.matrix_keys_match is None


# ---- adapter: D1 / A6 ----------------------------------------------------------------
def _runtime():
    runtime = FunctionsRuntime()

    def lookup(value: str) -> dict:
        """Return a dict.

        :param value: Key.
        """
        return {"key": value, "quote": 'say "hi"'}

    runtime.register_function(lookup)
    return runtime


def test_d1_default_formatter_is_json():
    ledger = InterceptionLedger()
    executor = TrustVerificationToolsExecutor(lambda _: True, mode="passthrough", ledger=ledger,
                                              tool_matrix=TrustMatrix((entry("lookup"),)))
    message = ChatAssistantMessage(role="assistant", content=None,
                                   tool_calls=[FunctionCall(function="lookup", args={"value": "k"}, id="c1")])
    observation = executor.query("", _runtime(), messages=[message])[3][-1]["content"][0]["content"]
    assert json.loads(observation) == {"key": "k", "quote": 'say "hi"'}


def test_a6_settings_live_on_the_core():
    executor = TrustVerificationToolsExecutor(lambda _: True, mode="enforce", ledger=InterceptionLedger(),
                                              tool_matrix=TrustMatrix((entry(),)))
    assert executor.mode == executor.core.mode == "enforce"
    executor.mode = "passthrough"
    assert executor.core.mode == "passthrough"
    with pytest.raises(ValueError, match="Unsupported interception mode"):
        executor.mode = "loud"
    assert executor.detector is executor.core.detector
    assert executor.detector_timeout_s == executor.core.detector_timeout_s
    with pytest.raises(AttributeError):
        executor.detector = None


def test_a6_switching_on_from_off_rechecks_the_detector_signature():
    seen = []
    executor = TrustVerificationToolsExecutor(lambda p, c=None: seen.append(c) or True, mode="off",
                                              ledger=InterceptionLedger(), tool_matrix=TrustMatrix((entry("lookup"),)))
    executor.mode = "enforce"
    message = ChatAssistantMessage(role="assistant", content=None,
                                   tool_calls=[FunctionCall(function="lookup", args={"value": "k"}, id="c1")])
    executor.query("", _runtime(), messages=[message])
    assert seen and seen[0] is not None                  # context was passed
