"""Data contracts shared by ALL modules of the Detector Agent.

Everything that crosses a module boundary is a Pydantic model, so the three of
you can work in parallel: Member 1 produces ParseResult (+ StructuralReport),
Member 2 consumes them and produces the graph, Member 3 consumes the graph.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Direction(str, Enum):
    PRE_HOP = "pre_hop"    # agent -> tool (proposed call)
    POST_HOP = "post_hop"  # tool -> agent (response)


class Trust(str, Enum):
    T = "T"      # provenance-trusted   (section 6.3)
    UT = "UT"    # untrusted


class ParseStatus(str, Enum):
    """Malformed != malicious. Status says WHETHER we could parse; it is never
    mixed into the structural score. Any non-OK status => whole payload is
    Untrusted by default (6.2) and the risk gate must read the status itself."""
    OK = "ok"
    INVALID_JSON = "invalid_json"
    TOO_LARGE = "too_large"
    TOO_DEEP = "too_deep"


# ---------------------------------------------------------------- INPUT ----
class ToolTraffic(BaseModel):
    """One cloned call or response entering the Detector Agent (sec 6.1/6.2).
    This is THE canonical shape for live runs, training data and evaluation."""
    model_config = ConfigDict(frozen=True)

    internal_id: UUID = Field(default_factory=uuid4)  # id you map in the TVM
    direction: Direction
    tool_name: str
    tool_call_id: str | None = None
    payload: str | dict[str, Any] | list[Any]          # raw, unmodified


# ------------------------------------------------- STAGE 1: parse output ----
ValueType = Literal["object", "array", "string", "number", "boolean", "null"]

FindingKind = Literal[
    "parse_failure", "payload_too_large", "depth_exceeded",   # status-level
    "duplicate_key",                                           # parse-level fact
    "illegal_delimiter", "embedded_json", "unexpected_key",    # counted toward S
    "weak_signal", "schema_violation",                         # NOT counted toward S
]


class ParsedField(BaseModel):
    """One addressable field. Becomes a graph node in section 6.4."""
    model_config = ConfigDict(frozen=True)

    path: str                      # e.g. $.emails[0].body  (unique per payload)
    key: str | None                # None for root and array items
    parent_path: str | None        # None for root -> gives you the graph edges
    depth: int = Field(ge=0)
    value_type: ValueType
    value: str | int | float | bool | None = None  # leaves only


class Finding(BaseModel):
    kind: FindingKind
    path: str
    detail: str


class ParseResult(BaseModel):
    """Output of parse(). Pure parsing: NO scoring, NO trust judgment."""
    internal_id: UUID
    direction: Direction
    tool_name: str
    tool_call_id: str | None

    status: ParseStatus
    fields: list[ParsedField]
    findings: list[Finding]          # parse-level facts only
    boundary_count: int = Field(ge=1)   # containers + keys (denominator for S)


# ---------------------------------------- STAGE 1b: structural flag output ----
class StructuralReport(BaseModel):
    """Output of structural_flags(): the S from section 6.2."""
    findings: list[Finding]              # each one counts toward S
    uncounted_findings: list[Finding]    # weak signals / schema errors: logged only
    hit_count: int = Field(ge=0)
    boundary_count: int = Field(ge=1)
    structural_score: float = Field(ge=0.0, le=1.0)


# ------------------------------------------------- STAGE 2 (tagging) stub ----
class TaggedField(ParsedField):
    """Produced by tagging.py (section 6.3). Left here so the interface is fixed."""
    trust: Trust


# ---------------------------------------------- DATASET + DECISION LOG ----
class LabeledCase(BaseModel):
    """One test/training case. Same ToolTraffic shape everywhere - no drift."""
    traffic: ToolTraffic
    label: Literal["benign", "attack"]
    attack_type: str | None = None
    expected_status: ParseStatus = ParseStatus.OK
    expected_untrusted_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _attack_type_matches_label(self) -> "LabeledCase":
        if self.label == "attack" and not self.attack_type:
            raise ValueError("attack cases need an attack_type")
        if self.label == "benign" and self.attack_type:
            raise ValueError("benign cases must not have an attack_type")
        return self


class DecisionLogRecord(BaseModel):
    """Section 8.4.7. Stores the FULL raw traffic (inside `traffic`), not a
    summary, so logs can be replayed as training data in the canonical shape."""
    traffic: ToolTraffic
    parse: ParseResult
    structural: StructuralReport
    # Members 2/3 extend: classifier_score, risk_score, human_decision, ...