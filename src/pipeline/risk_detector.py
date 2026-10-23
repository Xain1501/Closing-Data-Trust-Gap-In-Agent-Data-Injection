"""Opt-in classifier/risk composition for the existing clone detector contract."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from classifier.wl_svm import WLGraphSVM
from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from parser.models import Direction, ToolTraffic
from parser.parser import parse
from parser.structural import structural_flags
from pipeline.classifier_gate import classify_and_assess
from pipeline.clone_parser_detector import parser_detector
from pipeline.evidence_panel import EvidencePanel
from pipeline.risk_gate import RiskAssessment, resolve_review
from trust_graph import build_trust_graph, tag_fields

ReviewCallback = Callable[[RiskAssessment, EvidencePanel], str]


def make_risk_detector(
    classifier: WLGraphSVM,
    *,
    reviewer: ReviewCallback | None = None,
    user_query: Callable[[DetectorContext], str] | None = None,
) -> Callable[[DetectorPayload, DetectorContext | None], DetectorDecision]:
    """Create a clone-compatible detector with graph classification and review.

    Parser/schema hard failures remain blocked. If risk requires review but no
    reviewer is configured, the detector fails closed. The callback can render
    the evidence packet in a UI and return allow/deny/evidence_only.
    """

    def detector(payload: DetectorPayload, context: DetectorContext | None = None) -> DetectorDecision:
        if context is None:
            raise ValueError("Risk detector requires interception context.")
        base = parser_detector(payload, context)
        if not base.allowed:
            return base
        if context.matrix_entry.impact_tier not in (1, 5, 10):
            return DetectorDecision(False, "risk-unclassified", base.score,
                                    "Trusted impact tier is unavailable.", base.contains_adi)

        direction = Direction.PRE_HOP if context.direction == "pre" else Direction.POST_HOP
        parser_payload: Any = (
            payload.get("args", payload)
            if direction is Direction.PRE_HOP and isinstance(payload, dict)
            else payload
        )
        traffic = ToolTraffic(
            direction=direction,
            tool_name=context.tool_name,
            tool_call_id=context.tool_call_id,
            payload=parser_payload,
        )
        parsed = parse(traffic)
        report = structural_flags(parsed)
        tagged = tag_fields(parsed, dict(context.matrix_entry.field_trust_classes))
        graph = build_trust_graph(tagged, report.findings)
        result = classify_and_assess(
            graph,
            classifier,
            base.score or 0.0,
            context.matrix_entry.impact_tier,
        )
        assessment = result.assessment
        action = "allow" if assessment.route == "auto_allow" else None

        panel = EvidencePanel.from_evidence(
            original_user_query=user_query(context) if user_query else "",
            direction=context.direction,
            tool_name=context.tool_name,
            proposed_call_or_result=payload,
            untrusted_content=[
                str(field.value) for field in tagged
                if field.trust.value == "UT" and isinstance(field.value, str)
            ],
            provenance=[f"{field.path}:{field.trust.value}" for field in tagged],
            structural_warnings=[
                f"{finding.kind} at {finding.path}" for finding in report.findings
            ],
            assessment=assessment,
            expected_side_effect=(
                "Tool call may execute" if context.direction == "pre"
                else "Tool call already executed; result may be released to the agent"
            ),
        )

        if action is None and reviewer is not None:
            action = reviewer(assessment, panel)
        if action is None:
            action = "deny"
        try:
            resolution = resolve_review(
                assessment,
                action,  # type: ignore[arg-type]
                direction="pre_hop" if context.direction == "pre" else "post_hop",
            )
        except ValueError as exc:
            return DetectorDecision(False, "review-invalid", assessment.risk_score,
                                    str(exc), base.contains_adi)

        allowed = resolution.execute_tool if context.direction == "pre" else resolution.release_raw_content
        label = f"risk-{assessment.tier}"
        reason = (
            f"Risk {assessment.risk_score:.3f} ({assessment.tier}); "
            f"action={resolution.action}."
        )
        if resolution.observation:
            reason = f"{reason} {resolution.observation}"
        return DetectorDecision(
            allowed=allowed,
            label=label,
            score=assessment.risk_score,
            reason=reason,
            contains_adi=base.contains_adi or result.classifier.predicted_label == "attack",
        )

    detector.__name__ = "risk_detector"
    return detector
