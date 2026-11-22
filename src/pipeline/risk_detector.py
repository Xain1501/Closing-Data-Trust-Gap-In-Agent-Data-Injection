"""Opt-in classifier/risk composition for the existing clone detector contract."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from classifier.wl_svm import WLGraphSVM
from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from pipeline.classifier_gate import classify_and_assess
from pipeline.evidence_panel import EvidencePanel
from pipeline.decision import decide
from pipeline.tagging_stage import analyze_and_tag
from pipeline.risk_gate import RiskAssessment, resolve_review
from provenance.run_state import RunStateStore
from trust_graph import build_trust_graph

ReviewCallback = Callable[[RiskAssessment, EvidencePanel], str]


def make_risk_detector(
    classifier: WLGraphSVM,
    *,
    reviewer: ReviewCallback | None = None,
    user_query: Callable[[DetectorContext], str] | None = None,
    run_states: RunStateStore | None = None,
) -> Callable[[DetectorPayload, DetectorContext | None], DetectorDecision]:
    """Create a clone-compatible detector with graph classification and review.

    Parser/schema hard failures remain blocked. If risk requires review but no
    reviewer is configured, the detector fails closed. The callback can render
    the evidence packet in a UI and return allow/deny/evidence_only.
    """

    state_store = run_states or RunStateStore()

    def detector(payload: DetectorPayload, context: DetectorContext | None = None) -> DetectorDecision:
        if context is None:
            raise ValueError("Risk detector requires interception context.")
        tagged = analyze_and_tag(payload, context, state_store)
        analysis = tagged.analysis
        base_contains_adi = analysis.structural.hit_count > 0
        evidence = {"forgery_found": base_contains_adi, "schema_ok": analysis.schema_ok,
                    "parse_health": analysis.parse_health, "skeleton": analysis.skeleton}
        # Hard blocks come from the shared decision layer; structural findings on
        # inspectable content go on to the classifier/risk stages instead.
        verdict = decide(analysis)
        if verdict.label in ("parser-untrusted", "schema-violation"):
            return DetectorDecision(False, verdict.label, analysis.structural.structural_score,
                                    verdict.reason, base_contains_adi, decided_by="parser", **evidence)
        report = analysis.structural
        if context.matrix_entry.impact_tier not in (1, 5, 10):
            return DetectorDecision(False, "risk-unclassified", report.structural_score,
                                    "Trusted impact tier is unavailable.", base_contains_adi,
                                    decided_by="matrix", **evidence)

        graph = build_trust_graph(list(tagged.tags), report.findings,
                                  mentions=tuple(getattr(tagged.run_state, "mentions", ())))
        result = classify_and_assess(
            graph,
            classifier,
            report.structural_score,
            context.matrix_entry.impact_tier,
            structural_hits=report.hit_count,
        )
        assessment = result.assessment
        lineage_incomplete = tagged.run_state.blind or tagged.run_state.overflowed
        if lineage_incomplete and context.matrix_entry.impact_tier >= 5:
            assessment = replace(
                assessment,
                route="human_review",
                review_reasons=(*assessment.review_reasons, "lineage_incomplete"),
            )
        action = "allow" if assessment.route == "auto_allow" else None

        parsed_by_path = {field.path: field for field in analysis.true_fields}
        tagged_by_path = {field.path: field for field in tagged.tags}

        panel = EvidencePanel.from_evidence(
            original_user_query=(user_query(context) if user_query else context.user_prompt or ""),
            direction=context.direction,
            tool_name=context.tool_name,
            proposed_call_or_result=payload,
            untrusted_content=[
                str(parsed_by_path[path].value)
                for path, field in tagged_by_path.items()
                if path in parsed_by_path and field.trust.value == "UT"
                and isinstance(parsed_by_path[path].value, str)
            ],
            provenance=[f"{field.path}:{field.trust.value}" for field in tagged.tags],
            structural_warnings=[
                f"{finding.kind} at {finding.path}" for finding in report.findings
            ] + (["Run lineage is incomplete; review required for this impact tier."] if lineage_incomplete else []),
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
                                    str(exc), base_contains_adi, decided_by="review", **evidence)

        allowed = resolution.execute_tool if context.direction == "pre" else resolution.release_raw_content
        label = f"risk-{assessment.tier}"
        reason = (
            f"Risk {assessment.risk_score:.3f} ({assessment.tier}); "
            f"action={resolution.action}."
        )
        if assessment.review_reasons:
            reason = f"{reason} Review reasons: {', '.join(assessment.review_reasons)}."
        if resolution.observation:
            reason = f"{reason} {resolution.observation}"
        return DetectorDecision(
            allowed=allowed,
            label=label,
            score=assessment.risk_score,
            reason=reason,
            # contains_adi means forged structure only; the classifier's view is in label/score.
            contains_adi=base_contains_adi,
            decided_by="risk",
            **evidence,
        )

    detector.__name__ = "risk_detector"
    detector.end_run = state_store.end_run  # type: ignore[attr-defined]
    detector.get_run_state = state_store.get  # type: ignore[attr-defined]
    detector.run_state_store = state_store  # type: ignore[attr-defined]
    return detector
