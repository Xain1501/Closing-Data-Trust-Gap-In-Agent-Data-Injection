from __future__ import annotations

from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from parser.models import Direction, ParseStatus, ToolTraffic
from parser.parser import parse
from parser.structural import structural_flags


def parser_detector(
    payload: DetectorPayload, context: DetectorContext | None = None
) -> DetectorDecision:
    """Analyze a cloned payload with the parser's structural ADI signals."""
    if context is None:
        raise ValueError("Parser detector requires interception context.")

    traffic = ToolTraffic(
        direction=(
            Direction.PRE_HOP if context.direction == "pre" else Direction.POST_HOP
        ),
        tool_name=context.tool_name,
        tool_call_id=context.tool_call_id,
        payload=payload,
    )
    parsed = parse(traffic)
    report = structural_flags(parsed)
    contains_adi = report.hit_count > 0
    parse_usable = parsed.status in (ParseStatus.OK, ParseStatus.NOT_JSON)

    if not parse_usable:
        reason = f"Parser status: {parsed.status.value}."
        label = "parser-untrusted"
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
        allowed=parse_usable and not contains_adi,
        label=label,
        score=report.structural_score,
        reason=reason,
        contains_adi=contains_adi,
    )
