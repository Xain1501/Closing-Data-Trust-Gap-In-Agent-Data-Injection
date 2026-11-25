from scripts.record_attack_traces import _ScriptedLLM, _call_sequence_sha256, _calls
from agentdojo.functions_runtime import FunctionCall


def test_recorded_assistant_batches_are_replayed_without_flattening():
    batches = _calls({
        "messages": [
            {"role": "assistant", "tool_calls": [
                {"name": "read_a", "args": {}, "id": "source-a"},
                {"name": "read_b", "args": {}, "id": "source-b"},
            ]},
            {"role": "assistant", "tool_calls": [
                {"name": "write_c", "args": {"value": 1}, "id": "source-c"},
            ]},
        ],
    })

    model = _ScriptedLLM(batches)
    _, _, _, first, _ = model.query("", None)
    _, _, _, second, _ = model.query("", None)
    _, _, _, finished, _ = model.query("", None)

    assert len(first[-1]["tool_calls"]) == 2
    assert len(second[-1]["tool_calls"]) == 1
    assert first[-1]["tool_calls"][0].id != first[-1]["tool_calls"][1].id
    assert finished[-1]["tool_calls"] is None
    same_calls_with_new_ids = [
        [
            FunctionCall(function=call.function, args=dict(call.args), id="new-id")
            for call in batch
        ]
        for batch in batches
    ]
    assert _call_sequence_sha256(batches) == _call_sequence_sha256(same_calls_with_new_ids)
