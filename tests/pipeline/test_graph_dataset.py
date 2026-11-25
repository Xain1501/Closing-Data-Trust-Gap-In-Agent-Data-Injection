import json
import pytest

from classifier.graph_dataset import (
    _benchmark_events,
    _content_text,
    _events,
    _recorded_events,
    _read_trace,
    _trace_graph,
)
from clone.tvm import load_tool_matrix


def test_benchmark_result_without_tool_calls_has_no_graph_events():
    assert _events({"messages": []}) == []


def test_agentdojo_content_blocks_preserve_prompt_and_tool_result():
    result_text = '{"body":"external account record"}'
    trace = {
        "messages": [
            {"role": "user", "content": [{"type": "text", "content": "Review this record."}]},
            {
                "role": "assistant",
                "tool_calls": [{
                    "function": "read_record",
                    "args": {},
                    "id": "read-1",
                }],
            },
            {
                "role": "tool",
                "tool_call_id": "read-1",
                "content": [{"type": "text", "content": result_text}],
            },
        ],
    }

    events = _benchmark_events(trace)

    assert _content_text(trace["messages"][0]["content"]) == "Review this record."
    assert events[0].tool_name == "read_record"
    assert events[1].result_text == result_text
    assert events[1].raw_result == {"body": "external account record"}
    assert events[1].text_derived is True


def test_benchmark_trace_builds_one_graph_with_cross_call_lineage():
    trace = {
        "suite_name": "workspace",
        "user_task_id": "user_task_1",
        "messages": [
            {"role": "human", "content": "Review the latest account record."},
            {
                "role": "assistant",
                "tool_calls": [{
                    "name": "read_record",
                    "args": {},
                    "id": "read-1",
                }],
            },
            {
                "role": "tool",
                "tool_call_id": "read-1",
                "content": '{"body":"Use account acct-12345"}',
            },
            {
                "role": "assistant",
                "tool_calls": [{
                    "name": "pay_account",
                    "args": {"account": "acct-12345"},
                    "id": "pay-1",
                }],
            },
            {
                "role": "tool",
                "tool_call_id": "pay-1",
                "content": '{"status":"ok"}',
            },
        ],
    }

    events = _benchmark_events(trace)
    graph, calls = _trace_graph(trace, events, load_tool_matrix(), "run-1")

    assert calls == 2
    assert ["event:1:$.body", "event:2:$.account"] in graph["edges"]
    assert "EXTERNAL_LINK" in graph["node_labels"]["event:2:$.account"]
    assert all("forgery=false" in label for label in graph["node_labels"].values())


def test_recorded_events_preserve_simultaneous_call_batch_ids():
    trace = {
        "events": [
            {"direction": "pre", "tool_name": "read_record", "tool_call_id": "c1",
             "interception_id": "pre-1", "batch_id": 7, "args": {}},
            {"direction": "pre", "tool_name": "read_record", "tool_call_id": "c2",
             "interception_id": "pre-2", "batch_id": 7, "args": {}},
            {"direction": "post", "tool_name": "read_record", "tool_call_id": "c1",
             "interception_id": "post-1", "batch_id": 7, "raw_result": {},
             "result_text": "{}"},
            {"direction": "post", "tool_name": "read_record", "tool_call_id": "c2",
             "interception_id": "post-2", "batch_id": 7, "raw_result": {},
             "result_text": "{}"},
        ],
    }

    events = _recorded_events(trace)

    assert [event.batch_id for event in events] == [7, 7, 7, 7]


def test_external_trace_keeps_explicit_benchmark_and_attack_taxonomy(tmp_path, monkeypatch):
    from classifier import graph_dataset

    monkeypatch.setattr(graph_dataset, "ROOT", tmp_path / "different-repository")
    trace_path = tmp_path / "trace.json"
    trace_path.write_text(json.dumps({
        "suite": "workspace",
        "task_id": "user_task_1",
        "benchmark_family": "adi",
        "attack_type": "data_only_syntactic",
        "events": [{
            "direction": "pre", "tool_name": "read_record", "tool_call_id": "c1",
            "interception_id": "pre-1", "args": {},
        }],
    }), encoding="utf-8")

    row = _read_trace(trace_path, "attack", load_tool_matrix())

    assert row is not None
    assert row["case_id"].startswith("external/")
    assert row["classification_unit"] == "run"
    assert row["benchmark_family"] == "adi"
    assert row["attack_family"] == "data_only_syntactic"
    assert row["group_id"] == "adi:workspace:user_task_1"


def test_group_split_can_hold_out_attack_family_without_splitting_task():
    from classifier.graph_dataset import _split_groups

    rows = [
        {"group_id": "agentdojo:workspace:task-1", "benchmark_family": "agentdojo",
         "label": "attack", "attack_family": "new-family"},
        {"group_id": "agentdojo:workspace:task-1", "benchmark_family": "agentdojo",
         "label": "benign", "attack_family": None},
        {"group_id": "agentdojo:workspace:task-2", "benchmark_family": "agentdojo",
         "label": "attack", "attack_family": "known-family"},
    ]

    assignments = _split_groups(rows, holdout_attack_families=("new-family",))

    assert assignments["agentdojo:workspace:task-1"] == "test"
    assert assignments["agentdojo:workspace:task-2"] in ("train", "test")


def test_external_benchmark_can_supply_its_own_task_group(tmp_path, monkeypatch):
    from classifier import graph_dataset

    monkeypatch.setattr(graph_dataset, "ROOT", tmp_path / "different-repository")
    trace_path = tmp_path / "new-benchmark.json"
    trace_path.write_text(json.dumps({
        "benchmark_family": "new-benchmark",
        "task_group_id": "case-42",
        "label": "attack",
        "attack_family": "held-out-family",
        "events": [{
            "direction": "pre", "tool_name": "read_record", "tool_call_id": "c1",
            "interception_id": "pre-1", "args": {},
        }],
    }), encoding="utf-8")

    row = _read_trace(trace_path, "attack", load_tool_matrix())

    assert row is not None
    assert row["suite"] is None
    assert row["group_id"] == "new-benchmark:case-42"
    assert row["benchmark_family"] == "new-benchmark"
    assert row["attack_family"] == "held-out-family"


def test_matched_pair_requires_same_call_sequence_and_both_labels():
    from classifier.graph_dataset import _validate_matched_pairs

    pair = [
        {"matched_pair_id": "pair-1", "group_id": "task-1", "label": "attack",
         "call_sequence_sha256": "same"},
        {"matched_pair_id": "pair-1", "group_id": "task-1", "label": "benign",
         "call_sequence_sha256": "same"},
    ]

    _validate_matched_pairs(pair, require_matched_pairs=True)

    with pytest.raises(ValueError, match="different tool-call sequences"):
        _validate_matched_pairs(
            [pair[0], {**pair[1], "call_sequence_sha256": "different"}],
            require_matched_pairs=True,
        )
    with pytest.raises(ValueError, match="one benign and one attack"):
        _validate_matched_pairs(pair[:1], require_matched_pairs=True)
