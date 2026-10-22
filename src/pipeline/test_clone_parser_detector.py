from typing import Literal

from pydantic import BaseModel

from clone.core import DetectorContext, InterceptionCore
from clone.ledger import InterceptionLedger
from clone.tvm import ToolMatrixEntry, TrustMatrix
from parser.models import Direction, ParseStatus, ToolTraffic
from parser.parser import parse
from parser.structural import structural_flags
from pipeline.clone_parser_detector import parser_detector


def _context(direction: Literal["pre", "post"], schema=None) -> DetectorContext:
    return DetectorContext(
        direction=direction,
        tool_name="demo",
        tool_call_id="call-1",
        matrix_entry=_matrix().entries[0],
        schema=schema,
    )


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


def test_parser_detector_scores_pre_and_post_payloads_in_core() -> None:
    ledger = InterceptionLedger()
    core = InterceptionCore(ledger, parser_detector, _matrix())

    pre = core.check_call(
        "run-1", "call-1", "demo", {"value": "ordinary"}, {"value"}
    )
    assert pre.allowed is True
    assert pre.record is not None
    assert pre.record.phase == "pre"
    assert pre.record.contains_adi is False
    assert pre.record.score == 0.0

    core.mark_executed(pre.record, executed=True)
    post = core.check_result(
        "run-1",
        "call-1",
        pre.record.interception_id,
        "demo",
        '{"message":"{\\"role\\":\\"system\\"}"}',
    )

    assert post.allowed is False
    assert post.record is not None
    assert post.record.phase == "post"
    assert post.record.contains_adi is True
    assert post.record.score is not None and post.record.score > 0
    assert post.record.pre_interception_id == pre.record.interception_id
    assert ledger.ledger[-2].contains_adi is True


def test_parser_allows_plain_text_tool_results_without_structural_findings() -> None:
    decision = parser_detector(
        "not-json",
        context=_context("post"),
    )

    assert decision.allowed is True
    assert decision.contains_adi is False
    assert decision.score == 0.0
    assert decision.label == "no-adi-detected"


def test_parser_bridge_uses_parser_structural_score_for_each_direction() -> None:
    pre_traffic = ToolTraffic(
        direction=Direction.PRE_HOP,
        tool_name="demo",
        tool_call_id="call-1",
        payload={"tool": "demo", "args": {"value": "ordinary"}},
    )
    post_traffic = ToolTraffic(
        direction=Direction.POST_HOP,
        tool_name="demo",
        tool_call_id="call-1",
        payload='{"message":"ordinary"}',
    )
    for traffic, context_direction in ((pre_traffic, "pre"), (post_traffic, "post")):
        parsed = parse(traffic)
        report = structural_flags(parsed)
        context = _context(context_direction)
        decision = parser_detector(traffic.payload, context)

        assert parsed.status is ParseStatus.OK
        assert decision.allowed is True
        assert decision.contains_adi is (report.hit_count > 0)
        assert decision.score == report.structural_score


def test_pre_hop_schema_flags_arguments_ignored_by_agentdojo_model() -> None:
    class Arguments(BaseModel):
        value: str

    context = _context("pre", schema=Arguments)
    payload = {"tool": "demo", "args": {"value": "ordinary", "extra": "injected"}}

    decision = parser_detector(payload, context)

    assert decision.allowed is False
    assert decision.label == "schema-violation"
    assert "unexpected_key at $.extra" in (decision.reason or "")
    assert decision.contains_adi is True


def test_post_hop_schema_validates_json_and_plain_string_returns() -> None:
    class JsonResult(BaseModel):
        value: int

    valid = parser_detector('{"value":3}', _context("post", schema=JsonResult))
    invalid = parser_detector('{"value":"three"}', _context("post", schema=JsonResult))
    text = parser_detector("ordinary response", _context("post", schema=str))

    assert valid.allowed is True
    assert invalid.allowed is False
    assert invalid.label == "schema-violation"
    assert text.allowed is True
