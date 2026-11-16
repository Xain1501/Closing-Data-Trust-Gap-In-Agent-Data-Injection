"""One shared parser pass for the Clone -> Parser detector stages."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from clone.core import DetectorContext
from clone.ledger import DetectorPayload
from parser.models import Direction, ParseResult, ParseStatus, StructuralReport, ToolTraffic
from parser.parser import parse
from parser.schema_registry import ToolSchemaRegistry
from parser.structural import structural_flags

ParseHealth = Literal["clean", "salvaged_repr", "salvaged_repaired", "uninspectable"]

@dataclass(frozen=True)
class ParserAnalysis:
    traffic: ToolTraffic
    parsed: ParseResult
    structural: StructuralReport
    schema_registered: bool
    schema_invalid: bool

    # The parser reports EVIDENCE; it does not gate. pipeline/decision.py decides.
    @property
    def parse_health(self) -> ParseHealth:
        """How well the payload could be read.

        clean             - ok / empty / not_json: every field was scanned as written
        salvaged_repr     - invalid_json that is a Python literal (dict/list repr): fields recovered exactly
        salvaged_repaired - truncated JSON closed by guesswork: fields are a best guess
        uninspectable     - nothing could be read (too large / deep / many fields, unsalvageable JSON)
        """
        status = self.parsed.status
        if status in (ParseStatus.OK, ParseStatus.EMPTY, ParseStatus.NOT_JSON):
            return "clean"
        if status is ParseStatus.INVALID_JSON and self.parsed.salvage == "repr":
            return "salvaged_repr"
        if status is ParseStatus.INVALID_JSON and self.parsed.salvage == "repaired":
            return "salvaged_repaired"
        return "uninspectable"

    @property
    def inspectable(self) -> bool:
        return self.parse_health != "uninspectable"


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
