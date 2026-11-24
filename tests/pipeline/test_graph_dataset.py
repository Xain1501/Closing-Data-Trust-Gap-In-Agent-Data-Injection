from classifier.graph_dataset import _benchmark_events, _events, _trace_graph
from clone.tvm import load_tool_matrix


def test_benchmark_result_without_tool_calls_has_no_graph_events():
    assert _events({"messages": []}) == []


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
    graph, calls, decision_graphs = _trace_graph(trace, events, load_tool_matrix(), "run-1")

    assert calls == 2
    assert len(decision_graphs) == len(events)
    assert ["event:1:$.body", "event:2:$.account"] in graph["edges"]
    assert "EXTERNAL_LINK" in graph["node_labels"]["event:2:$.account"]
    assert all("forgery=false" in label for label in graph["node_labels"].values())
