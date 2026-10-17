from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from time import sleep

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage

from clone.interceptor import (
    DetectorDecision,
    TrustVerificationMatrix,
    TrustVerificationToolsExecutor,
)


def _runtime(calls: list[str]) -> FunctionsRuntime:
    runtime = FunctionsRuntime()

    def record(value: str) -> str:
        """Record a value.

        :param value: Value to record.
        """
        calls.append(value)
        return f"recorded:{value}"

    def reverse(value: str) -> str:
        """Reverse a value.

        :param value: Value to reverse.
        """
        calls.append(f"reverse:{value}")
        return value[::-1]

    runtime.register_function(record)
    runtime.register_function(reverse)
    return runtime


def _message() -> ChatAssistantMessage:
    return ChatAssistantMessage(
        role="assistant",
        content=None,
        tool_calls=[
            FunctionCall(function="record", args={"value": "first"}, id="call-1"),
            FunctionCall(function="reverse", args={"value": "second"}, id="call-2"),
        ],
    )


def test_passthrough_matches_off_and_records_linked_batch(tmp_path) -> None:
    off_calls: list[str] = []
    off_result = TrustVerificationToolsExecutor(mode="off").query(
        "", _runtime(off_calls), messages=[_message()]
    )
    matrix = TrustVerificationMatrix()
    seen: list[object] = []

    def detector(payload: dict | str) -> DetectorDecision:
        seen.append(payload)
        if isinstance(payload, dict):
            payload["args"]["value"] = "detector mutation"
        return DetectorDecision(True, "static-allow", score=1.0)

    original_message = _message()
    original_args = [dict(call.args) for call in original_message["tool_calls"]]
    clone_calls: list[str] = []
    clone_result = TrustVerificationToolsExecutor(
        detector, mode="passthrough", matrix=matrix
    ).query("", _runtime(clone_calls), messages=[original_message])

    off_observations = [block["content"][0]["content"] for block in off_result[3][1:]]
    clone_observations = [block["content"][0]["content"] for block in clone_result[3][1:]]
    assert off_calls == clone_calls == ["first", "reverse:second"]
    assert off_observations == clone_observations == ["recorded:first", "dnoces"]
    assert [sha256(value.encode("utf-8")).hexdigest() for value in off_observations] == [
        record.sha256 for record in matrix.records if record.phase == "post"
    ]
    assert [call.args for call in original_message["tool_calls"]] == original_args
    assert len(seen) == 4
    assert matrix.raw_payloads[0].payload == {
        "tool": "record",
        "args": {"value": "first"},
    }
    canonical_pre = json.dumps(
        {"tool": "record", "args": {"value": "first"}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert matrix.records[0].sha256 == sha256(canonical_pre).hexdigest()
    assert len({record.run_id for record in matrix.records}) == 1
    assert [record.phase for record in matrix.records] == ["pre", "post", "pre", "post"]
    assert [
        record.pre_interception_id
        for record in matrix.records
        if record.phase == "post"
    ] == [
        record.interception_id for record in matrix.records if record.phase == "pre"
    ]
    assert [record.seq for record in matrix.records] == [1, 2, 3, 4]
    assert all(record.tool_call_id in {"call-1", "call-2"} for record in matrix.records)
    assert len(matrix.ledger) > len(matrix.records)
    assert all(entry.event_seq == index for index, entry in enumerate(matrix.ledger, start=1))
    ledger_path = tmp_path / "ledger.jsonl"
    payload_path = tmp_path / "payloads.jsonl"
    matrix.export_ledger(ledger_path)
    matrix.export_raw_payloads(payload_path)
    assert len(ledger_path.read_text(encoding="utf-8").splitlines()) == len(matrix.ledger)
    exported_raw = [json.loads(line) for line in payload_path.read_text(encoding="utf-8").splitlines()]
    assert len(exported_raw) == len(matrix.raw_payloads)
    assert exported_raw[0]["label"] == "static-allow"

    tool_calls = [
        {
            "tool_call_id": call.id,
            "tool": call.function,
            "args": call.args,
        }
        for call in original_message["tool_calls"]
    ]
    print("\n=== Tool call comparison: off vs clone ===")
    print(
        json.dumps(
            {
                "off": {
                    "calls": tool_calls,
                    "observations": off_observations,
                },
                "clone": {
                    "calls": tool_calls,
                    "observations": clone_observations,
                    "executed_calls": clone_calls,
                },
            },
            indent=2,
        )
    )
    print("\n=== Trust Verification Matrix records ===")
    print(json.dumps([asdict(record) for record in matrix.records], indent=2))
    print("\n=== Trust Verification Matrix state-change ledger ===")
    print(json.dumps([asdict(entry) for entry in matrix.ledger], indent=2))


def test_enforcement_blocks_pre_hop_without_running_tool() -> None:
    calls: list[str] = []
    matrix = TrustVerificationMatrix()
    result = TrustVerificationToolsExecutor(
        lambda payload: DetectorDecision(False, "deny", reason="not permitted"),
        mode="enforce",
        matrix=matrix,
    ).query("", _runtime(calls), messages=[_message()])

    assert calls == []
    assert "not permitted" in result[3][1]["content"][0]["content"]
    assert len([record for record in matrix.records if record.phase == "pre"]) == 2
    assert len([record for record in matrix.records if record.phase == "post"]) == 2
    assert all(record.pre_interception_id for record in matrix.records if record.phase == "post")


def test_detector_failure_blocks_and_is_logged() -> None:
    matrix = TrustVerificationMatrix()

    def fail(_: dict | str) -> bool:
        raise RuntimeError("static detector failure")

    result = TrustVerificationToolsExecutor(
        fail, mode="enforce", matrix=matrix
    ).query("", _runtime([]), messages=[_message()])

    assert "Detector error: RuntimeError: static detector failure" in result[3][1]["content"][0]["content"]
    assert matrix.records[0].state == "blocked"
    assert matrix.records[0].error == "Detector error: RuntimeError: static detector failure"


def test_passthrough_releases_even_when_detector_denies() -> None:
    matrix = TrustVerificationMatrix()
    calls: list[str] = []
    result = TrustVerificationToolsExecutor(
        lambda _: DetectorDecision(False, "deny"),
        mode="passthrough",
        matrix=matrix,
    ).query("", _runtime(calls), messages=[_message()])

    assert calls == ["first", "reverse:second"]
    assert [message["content"][0]["content"] for message in result[3][1:]] == [
        "recorded:first",
        "dnoces",
    ]
    assert all(record.detector_decision is False for record in matrix.records)
    assert all(record.released is True for record in matrix.records)


def test_post_hop_block_hashes_denial_and_retains_raw_result() -> None:
    matrix = TrustVerificationMatrix()

    def detector(payload: dict | str) -> DetectorDecision:
        return DetectorDecision(
            isinstance(payload, dict),
            "static-check",
            reason="sensitive result",
        )

    result = TrustVerificationToolsExecutor(
        detector, mode="enforce", matrix=matrix
    ).query("", _runtime([]), messages=[_message()])
    observation = result[3][1]["content"][0]["content"]
    post = next(record for record in matrix.records if record.phase == "post")

    assert observation == "Blocked by Trust Verification Matrix: sensitive result"
    assert post.sha256 == sha256(observation.encode("utf-8")).hexdigest()
    assert matrix.raw_payloads[1].payload == "recorded:first"
    assert post.pre_interception_id == matrix.records[0].interception_id
    assert post.released is False


def test_detector_timeout_fails_closed() -> None:
    matrix = TrustVerificationMatrix()

    def slow(_: dict | str) -> bool:
        sleep(0.05)
        return True

    result = TrustVerificationToolsExecutor(
        slow,
        mode="enforce",
        detector_timeout_s=0.001,
        matrix=matrix,
    ).query("", _runtime([]), messages=[_message()])

    assert "Detector timed out" in result[3][1]["content"][0]["content"]
    assert matrix.records[0].state == "blocked"
