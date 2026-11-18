from __future__ import annotations

from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from pipeline.decision import decide
from pipeline.tagging_stage import analyze_and_tag
from provenance.run_state import RunStateStore

_RUN_STATES = RunStateStore()


def parser_detector(
    payload: DetectorPayload, context: DetectorContext | None = None
) -> DetectorDecision:
    """Analyze a cloned payload with the parser and decide over its evidence."""
    if context is None:
        raise ValueError("Parser detector requires interception context.")

    tagged = analyze_and_tag(payload, context, _RUN_STATES)
    analysis = tagged.analysis
    verdict = decide(analysis)
    return DetectorDecision(
        allowed=verdict.allowed,
        label=verdict.label,
        score=analysis.structural.structural_score,
        reason=verdict.reason,
        contains_adi=verdict.contains_adi,
        forgery_found=verdict.contains_adi,
        schema_ok=analysis.schema_ok,
        parse_health=analysis.parse_health,
        decided_by="parser",
    )


def end_run(run_id: str) -> bool:
    """Clear ephemeral prompts, values, and tags after the task is complete."""
    return _RUN_STATES.end_run(run_id)


def get_run_state(run_id: str):
    """Read-only-by-convention access for evaluation and audit tooling."""
    return _RUN_STATES.get(run_id)


parser_detector.end_run = end_run  # type: ignore[attr-defined]
parser_detector.get_run_state = get_run_state  # type: ignore[attr-defined]
