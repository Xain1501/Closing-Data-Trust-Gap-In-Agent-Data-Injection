from __future__ import annotations

from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from parser.models import ParseStatus
from pipeline.parser_analysis import analyze_clone_payload


def parser_detector(
    payload: DetectorPayload, context: DetectorContext | None = None
) -> DetectorDecision:
    """Analyze a cloned payload with the parser's structural ADI signals."""
    if context is None:
        raise ValueError("Parser detector requires interception context.")

    analysis = analyze_clone_payload(payload, context)
    parsed, report = analysis.parsed, analysis.structural
    contains_adi = report.hit_count > 0
    parse_usable = analysis.usable
    schema_invalid = analysis.schema_invalid

    if not parse_usable:
        reason = f"Parser status: {parsed.status.value}."
        label = "parser-untrusted"
    elif schema_invalid:
        details = "; ".join(
            f"{finding.kind} at {finding.path}"
            for finding in [*report.findings, *report.uncounted_findings]
            if finding.kind in ("unexpected_key", "schema_violation")
        )
        reason = f"Tool schema validation failed: {details}."
        label = "schema-violation"
    elif contains_adi:
        details = "; ".join(
            f"{finding.kind} at {finding.path}" for finding in report.findings[:3]
        )
        reason = f"Structural ADI findings: {details}."
        label = "adi-detected"
    else:
        reason = "No counted structural ADI findings."
        label = "no-adi-detected"

    return DetectorDecision(
        allowed=parse_usable and not contains_adi and not schema_invalid,
        label=label,
        score=report.structural_score,
        reason=reason,
        contains_adi=contains_adi,
    )
