"""The benign trace recorder (scripts/record_traces.py) and the traces it saved."""
import datetime
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TRACES = ROOT / "tests" / "fixtures" / "traces" / "benign"

_spec = importlib.util.spec_from_file_location("record_traces", ROOT / "scripts" / "record_traces.py")
record_traces = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record_traces)


def test_one_task_trace_has_the_prompt_and_paired_calls_and_results():
    trace = record_traces.record_task("banking", "user_task_0")
    assert trace["label"] == "benign" and trace["run_id"] == "banking:user_task_0"
    assert trace["user_prompt"]
    pre = [e for e in trace["events"] if e["direction"] == "pre"]
    post = [e for e in trace["events"] if e["direction"] == "post"]
    assert len(pre) == len(post) == trace["ground_truth_calls"] > 0
    assert [e["interception_id"] for e in trace["events"]] == [f"i-{n}" for n in range(1, len(trace["events"]) + 1)]
    assert all("args" in e for e in pre)
    for result in post:
        assert result["pre_interception_id"] in {e["interception_id"] for e in pre}
        assert isinstance(result["result_text"], str) and "raw_result" in result
    json.dumps(trace)                                   # everything stored is plain JSON


def test_recording_the_same_task_twice_gives_the_same_trace():
    # workspace user_task_13 creates an email and edits a file, which stamp the wall clock
    first = record_traces.record_task("workspace", "user_task_13")
    second = record_traces.record_task("workspace", "user_task_13")
    assert first == second
    assert record_traces.FROZEN_NOW.isoformat() in json.dumps(first)


def test_the_clock_is_put_back_after_recording():
    from agentdojo.default_suites.v1.tools import email_client

    record_traces.record_task("banking", "user_task_0")
    assert email_client.datetime is datetime


def test_to_plain_handles_every_result_shape():
    from pydantic import BaseModel

    class Item(BaseModel):
        id: int
        when: datetime.datetime

    plain = record_traces.to_plain([Item(id=1, when=datetime.datetime(2024, 1, 2)), {"k": (1, 2)}, None, "s"])
    assert plain == [{"id": 1, "when": "2024-01-02T00:00:00"}, {"k": [1, 2]}, None, "s"]


def test_saved_traces_cover_every_user_task_and_block_nothing():
    files = sorted(TRACES.rglob("*.json"))
    if not files:
        pytest.skip("no saved traces; run scripts/record_traces.py")
    from agentdojo.task_suite.load_suites import get_suite

    expected = {(s, t) for s in record_traces.SUITES for t in get_suite("v1", s).user_tasks}
    saved = set()
    for path in files:
        trace = json.loads(path.read_text(encoding="utf-8"))
        saved.add((trace["suite"], trace["task_id"]))
        assert trace["events"], path
        # benign runs: the parser detector must not block any call or result
        assert all(e["decision"]["allowed"] for e in trace["events"]), path
    assert saved == expected


def test_a_saved_trace_matches_a_fresh_recording():
    path = TRACES / "slack" / "user_task_1.json"
    if not path.exists():
        pytest.skip("no saved traces; run scripts/record_traces.py")
    assert json.loads(path.read_text(encoding="utf-8")) == record_traces.record_task("slack", "user_task_1")


def test_raw_result_is_stored_as_the_detector_saw_it_not_as_it_ended_up():
    # Slack returns a live message list that a later send_channel_message appends to.
    # For structured results the stored object must still equal the recorded text.
    checked = 0
    for task_id in ("user_task_8", "user_task_18", "user_task_19"):   # tasks that read, then post
        for event in record_traces.record_task("slack", task_id)["events"]:
            if event["direction"] == "post" and isinstance(event["raw_result"], (dict, list)):
                try:
                    as_text = json.loads(event["result_text"])
                except ValueError:
                    continue
                if all(isinstance(item, dict) for item in (as_text if isinstance(as_text, list) else [as_text])):
                    assert as_text == event["raw_result"], (task_id, event["interception_id"])
                    checked += 1
    assert checked > 0
