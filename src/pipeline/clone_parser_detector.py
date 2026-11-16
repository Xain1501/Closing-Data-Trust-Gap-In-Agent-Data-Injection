from __future__ import annotations

from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from pipeline.decision import decide
from pipeline.parser_analysis import analyze_clone_payload


def parser_detector(
    payload: DetectorPayload, context: DetectorContext | None = None
) -> DetectorDecision:
    """Analyze a cloned payload with the parser and decide over its evidence."""
    if context is None:
        raise ValueError("Parser detector requires interception context.")

    analysis = analyze_clone_payload(payload, context)
    verdict = decide(analysis)
    return DetectorDecision(
        allowed=verdict.allowed,
        label=verdict.label,
        score=analysis.structural.structural_score,
        reason=verdict.reason,
        contains_adi=verdict.contains_adi,
    )
