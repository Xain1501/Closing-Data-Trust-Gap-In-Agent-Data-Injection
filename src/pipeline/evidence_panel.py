"""Deterministic evidence packet and text renderer for a human reviewer."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Mapping

from pipeline.risk_gate import RiskAssessment


@dataclass(frozen=True)
class EvidencePanel:
    original_user_query: str
    direction: str
    tool_name: str
    proposed_call_or_result: Any
    untrusted_content: tuple[str, ...]
    provenance: tuple[str, ...]
    structural_warnings: tuple[str, ...]
    classifier_confidence: float | None
    structural_score: float
    risk_score: float
    risk_tier: str
    impact: int
    expected_side_effect: str
    options: tuple[str, ...]

    @classmethod
    def from_evidence(
        cls,
        *,
        original_user_query: str,
        direction: str,
        tool_name: str,
        proposed_call_or_result: Any,
        untrusted_content: tuple[str, ...] | list[str],
        provenance: tuple[str, ...] | list[str],
        structural_warnings: tuple[str, ...] | list[str],
        assessment: RiskAssessment,
        expected_side_effect: str,
    ) -> "EvidencePanel":
        return cls(
            original_user_query=original_user_query,
            direction=direction,
            tool_name=tool_name,
            proposed_call_or_result=proposed_call_or_result,
            untrusted_content=tuple(untrusted_content),
            provenance=tuple(provenance),
            structural_warnings=tuple(structural_warnings),
            classifier_confidence=assessment.classifier_score,
            structural_score=assessment.structural_score,
            risk_score=assessment.risk_score,
            risk_tier=assessment.tier,
            impact=assessment.impact,
            expected_side_effect=expected_side_effect,
            options=assessment.options,
        )

    def render(self) -> str:
        """Serialize a stable, human-readable packet without an LLM."""
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True, indent=2, default=_json_default)


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return dict(value)
    return str(value)
