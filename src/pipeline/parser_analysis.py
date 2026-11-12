"""One shared parser pass for the Clone -> Parser detector stages."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clone.core import DetectorContext
from clone.ledger import DetectorPayload
from parser.models import Direction, ParseResult, ParseStatus, StructuralReport, ToolTraffic
from parser.parser import parse
from parser.schema_registry import ToolSchemaRegistry
from parser.structural import structural_flags


@dataclass(frozen=True)
class ParserAnalysis:
    traffic: ToolTraffic
    parsed: ParseResult
    structural: StructuralReport
    schema_registered: bool
    schema_invalid: bool

    @property
    def usable(self) -> bool:
        if self.parsed.status is ParseStatus.OK:
            return True
        # Plain text is accepted only when a trusted, direction-specific schema
        # explicitly validates it (for example, a tool whose return type is str).
        # Without that contract, NOT_JSON is an opaque untrusted payload.
        return (
            self.parsed.status is ParseStatus.NOT_JSON
            and self.schema_registered
            and not self.schema_invalid
        )


def analyze_clone_payload(payload: DetectorPayload, context: DetectorContext) -> ParserAnalysis:
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
    schema_findings = ()
    if context.schema is not None and parsed.status in (ParseStatus.OK, ParseStatus.NOT_JSON):
        schemas = ToolSchemaRegistry()
        schemas.register(context.tool_name, direction.value, context.schema)
        schema_findings = schemas.validate(traffic)
    structural = structural_flags(parsed, schema_findings=schema_findings)
    schema_invalid = any(
        finding.kind in ("unexpected_key", "schema_violation")
        for finding in (*structural.findings, *structural.uncounted_findings)
    )
    return ParserAnalysis(traffic, parsed, structural, context.schema is not None, schema_invalid)
