from __future__ import annotations

from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from parser.models import Direction, ParseStatus, ToolTraffic
from parser.parser import parse
from parser.schema_registry import ToolSchemaRegistry
from parser.structural import structural_flags


def parser_detector(
    payload: DetectorPayload, context: DetectorContext | None = None
) -> DetectorDecision:
    """Analyze a cloned payload with the parser's structural ADI signals."""
    if context is None:
        raise ValueError("Parser detector requires interception context.")

    direction = Direction.PRE_HOP if context.direction == "pre" else Direction.POST_HOP
    # Clone captures pre-hop traffic as {tool, args}; schema validation applies
    # to the actual function arguments. Post-hop remains the exact formatted
    # result string sent to the model.
    parser_payload = (
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
    schema_registry = ToolSchemaRegistry()
    if context.schema is not None:
        schema_registry.register(context.tool_name, direction.value, context.schema)
    schema_findings = (
        schema_registry.validate(traffic)
        if context.schema is not None and parsed.status in (ParseStatus.OK, ParseStatus.NOT_JSON)
        else ()
    )
    report = structural_flags(parsed, schema_findings=schema_findings)
    contains_adi = report.hit_count > 0
    parse_usable = parsed.status in (ParseStatus.OK, ParseStatus.NOT_JSON)
    schema_invalid = any(
        finding.kind in ("unexpected_key", "schema_violation")
        for finding in [*report.findings, *report.uncounted_findings]
    )

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
