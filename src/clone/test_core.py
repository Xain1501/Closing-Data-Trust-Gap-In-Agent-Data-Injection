from __future__ import annotations

import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from clone.core import DetectorContext, DetectorDecision, InterceptionCore
from clone.ledger import InterceptionLedger
from clone.tvm import ToolMatrixEntry, TrustMatrix


def _matrix() -> TrustMatrix:
    return TrustMatrix(
        (
            ToolMatrixEntry(
                tool_name="demo",
                internal_tool_id="test.demo",
                impact_tier=1,
                impact_tier_source="policy default",
                authority_arguments=(),
                field_trust_classes={"value": "unclassified"},
                expected_keys=("value",),
            ),
        )
    )


def test_core_holds_then_releases_original_call_and_result() -> None:
    ledger = InterceptionLedger()
    core = InterceptionCore(ledger, lambda _: True, _matrix())

    call = core.check_call(
        "run-1", "call-1", "demo", {"value": "original"}, {"value"}
    )
    assert call.allowed is True
    assert call.denial_text is None
    assert call.record is not None

    core.mark_executed(call.record, executed=True)
    result = core.check_result(
        "run-1",
        "call-1",
        call.record.interception_id,
        "demo",
        "original result",
    )

    assert result.allowed is True
    assert result.denial_text is None
    assert result.record is not None
    assert result.record.phase == "post"
    assert result.record.released is True
    assert [record.phase for record in ledger.records] == ["pre", "post"]
    assert ledger.raw_payloads[0].payload == {
        "tool": "demo",
        "args": {"value": "original"},
    }


def test_core_blocks_call_and_creates_denial_delivery_record() -> None:
    ledger = InterceptionLedger()
    core = InterceptionCore(
        ledger,
        lambda _: DetectorDecision(False, "policy-deny", reason="not allowed"),
        _matrix(),
    )

    verdict = core.check_call(
        "run-1", "call-1", "demo", {"value": "original"}, {"value"}
    )

    assert verdict.allowed is False
    assert verdict.denial_text == "Blocked by Trust Verification Matrix: not allowed"
    assert verdict.record is not None
    assert verdict.record.state == "blocked"
    assert verdict.record.released is False
    denial_record = ledger.records[1]
    assert denial_record.phase == "post"
    assert denial_record.state == "denial_delivered"
    assert denial_record.released is False
    assert denial_record.pre_interception_id == verdict.record.interception_id


def test_core_off_mode_does_not_capture() -> None:
    ledger = InterceptionLedger()
    core = InterceptionCore(ledger, None, _matrix(), mode="off")

    verdict = core.check_call(
        "run-1", "call-1", "demo", {"value": "original"}, {"value"}
    )

    assert verdict.allowed is True
    assert verdict.record is None
    assert ledger.records == []


def test_context_detector_receives_metadata_and_only_a_deep_copy() -> None:
    ledger = InterceptionLedger()
    received = []

    def detector(payload, context=None):
        received.append((payload, context))
        payload["args"]["value"] = "detector mutation"
        return DetectorDecision(
            True, "inspected", score=0.25, contains_adi=False
        )

    core = InterceptionCore(ledger, detector, _matrix())
    verdict = core.check_call(
        "run-1", "call-1", "demo", {"value": "original"}, {"value"}
    )

    assert verdict.allowed is True
    assert verdict.record is not None
    inspected, context = received[0]
    assert inspected["args"]["value"] == "detector mutation"
    assert isinstance(context, DetectorContext)
    assert context.direction == "pre"
    assert context.tool_name == "demo"
    assert context.tool_call_id == "call-1"
    assert context.matrix_entry.internal_tool_id == "test.demo"
    assert ledger.raw_payloads[0].payload["args"]["value"] == "original"
    assert verdict.record.score == 0.25
    assert verdict.record.contains_adi is False
    assert ledger.ledger[-1].contains_adi is False

    with pytest.raises(FrozenInstanceError):
        context.tool_name = "changed"
    with pytest.raises(TypeError):
        context.matrix_entry.field_trust_classes["value"] = "trusted"


def test_legacy_one_argument_detector_remains_supported() -> None:
    ledger = InterceptionLedger()
    seen = []

    def detector(payload):
        seen.append(payload)
        return True

    core = InterceptionCore(ledger, detector, _matrix())
    verdict = core.check_call(
        "run-1", "call-1", "demo", {"value": "original"}, {"value"}
    )

    assert verdict.allowed is True
    assert seen == [{"tool": "demo", "args": {"value": "original"}}]
    assert verdict.record is not None
    assert verdict.record.contains_adi is None


def test_package_core_imports_with_agentdojo_blocked_in_fresh_interpreter() -> None:
    script = """
import sys
sys.modules["agentdojo"] = None
import clone
from clone import InterceptionCore, InterceptionLedger
assert clone.InterceptionLedger is InterceptionLedger
assert clone.InterceptionCore is InterceptionCore
assert not any(
    name.startswith("agentdojo") and module is not None
    for name, module in sys.modules.items()
)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_executor_export_is_loaded_lazily() -> None:
    from clone import TrustVerificationToolsExecutor

    from clone.adapters.agentdojo import TrustVerificationToolsExecutor as AdapterExecutor

    assert TrustVerificationToolsExecutor is AdapterExecutor
