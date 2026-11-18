"""One shared parser pass for the Clone -> Parser detector stages."""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from typing import Any, Literal

from clone.core import DetectorContext
from clone.ledger import DetectorPayload
from parser.models import Direction, ParsedField, ParseResult, ParseStatus, StructuralReport, ToolTraffic
from parser.parser import parse, payload_text
from parser.schema_registry import ToolSchemaRegistry
from parser.skeleton import Skeleton, build_skeleton
from parser.structural import structural_flags

ParseHealth = Literal["clean", "salvaged_repr", "salvaged_repaired", "uninspectable"]


@dataclass(frozen=True)
class ParserAnalysis:
    traffic: ToolTraffic
    parsed: ParseResult
    structural: StructuralReport
    schema_registered: bool
    schema_invalid: bool
    schema_checked: bool = False      # False = no schema, or the payload could not be checked against it
    # True field list from the result OBJECT (post-hop, when the adapter supplied it).
    # This is the provenance source for tagging / lineage; pass it on as-is.
    skeleton: Skeleton | None = None

    @property
    def skeleton_fields(self) -> tuple[ParsedField, ...]:
        """Fields from the result object; empty when there is no structured object."""
        return self.skeleton.fields if self.skeleton is not None and self.skeleton.structured else ()

    @property
    def skeleton_matches(self) -> bool | None:
        """True when the skeleton's paths equal the parser's paths.

        None when there is nothing to compare (no structured result object).
        False means the text the model sees does not have the structure of the
        real object: forged structure, a lossy formatter, or a non-JSON format.
        """
        if not self.skeleton_fields:
            return None
        return [f.path for f in self.skeleton_fields] == [f.path for f in self.parsed.fields]

    @property
    def skeleton_diff(self) -> dict[str, list[str]]:
        """Paths present on one side only (empty lists when they match or cannot be compared)."""
        if not self.skeleton_fields:
            return {"only_in_skeleton": [], "only_in_text": []}
        real = {f.path for f in self.skeleton_fields}
        seen = {f.path for f in self.parsed.fields}
        return {"only_in_skeleton": sorted(real - seen), "only_in_text": sorted(seen - real)}

    @property
    def true_fields(self) -> tuple[ParsedField, ...]:
        """The field list later stages should tag: the skeleton when there is one, else the parser's."""
        return self.skeleton_fields or tuple(self.parsed.fields)

    @property
    def schema_ok(self) -> bool | None:
        """True / False when a schema check ran, None when none did."""
        return (not self.schema_invalid) if self.schema_checked else None

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
    schema_traffic = None
    if context.schema is not None:
        if parsed.status in (ParseStatus.OK, ParseStatus.NOT_JSON):
            schema_traffic = traffic
        elif parsed.status is ParseStatus.INVALID_JSON and parsed.salvage == "repr":
            # A Python-literal result (dict/list repr) carries the same data as its
            # JSON form, so it gets the same schema check (was skipped before).
            schema_traffic = _repr_as_json_traffic(traffic)
    if schema_traffic is not None:
        schemas = ToolSchemaRegistry()
        schemas.register(context.tool_name, direction.value, context.schema)
        schema_findings = schemas.validate(schema_traffic)
    skeleton = None
    if direction is Direction.POST_HOP and context.raw_result is not None:
        skeleton = build_skeleton(context.raw_result, tool_name=context.tool_name,
                                  interception_id=context.interception_id)
    source_fields = skeleton.fields if skeleton is not None and skeleton.structured else None
    structural = structural_flags(
        parsed, schema_findings=schema_findings, source_fields=source_fields,
    )
    schema_invalid = any(
        finding.kind in ("unexpected_key", "schema_violation")
        for finding in (*structural.findings, *structural.uncounted_findings)
    )
    return ParserAnalysis(traffic, parsed, structural, context.schema is not None, schema_invalid,
                          schema_checked=schema_traffic is not None, skeleton=skeleton)


def _repr_as_json_traffic(traffic: ToolTraffic) -> ToolTraffic | None:
    try:
        value = ast.literal_eval(payload_text(traffic).lstrip("﻿").strip())
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    return ToolTraffic(direction=traffic.direction, tool_name=traffic.tool_name,
                       tool_call_id=traffic.tool_call_id, payload=json.dumps(value, default=str),
                       internal_id=traffic.internal_id)
