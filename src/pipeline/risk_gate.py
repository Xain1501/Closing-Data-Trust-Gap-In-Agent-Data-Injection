"""Deterministic confidence/impact risk assessment and review policy."""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Literal

RiskTier = Literal["low", "moderate", "high"]
ReviewAction = Literal["allow", "deny", "evidence_only"]
ImpactTier = Literal[1, 5, 10]


@dataclass(frozen=True)
class RiskAssessment:
    structural_score: float
    classifier_score: float | None
    confidence: float
    impact: ImpactTier
    risk_score: float
    tier: RiskTier
    route: Literal["auto_allow", "human_review"]
    options: tuple[ReviewAction, ...]


def _probability(value: float, name: str) -> float:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be a finite value in [0, 1]")
    return value


def assess_risk(
    structural_score: float,
    classifier_score: float | None,
    impact: int | None,
) -> RiskAssessment:
    """Apply proposal 6.6 confidence aggregation and policy thresholds.

    If the classifier is not trained/available, its contribution is treated as
    zero and remains explicitly ``None`` in the returned evidence.
    """
    structural = _probability(structural_score, "structural_score")
    classifier = 0.0 if classifier_score is None else _probability(classifier_score, "classifier_score")
    if impact not in (1, 5, 10):
        raise ValueError("impact must be one of 1, 5, or 10")
    confidence = 1.0 - (1.0 - structural) * (1.0 - classifier)
    risk = confidence * impact
    if risk < 1.0:
        tier: RiskTier = "low"
        route: Literal["auto_allow", "human_review"] = "auto_allow"
        options: tuple[ReviewAction, ...] = ("allow",)
    elif risk < 5.0:
        tier, route = "moderate", "human_review"
        options = ("allow", "deny", "evidence_only")
    else:
        tier, route = "high", "human_review"
        options = ("deny", "evidence_only")
    return RiskAssessment(structural, classifier_score, confidence, impact, risk, tier, route, options)


@dataclass(frozen=True)
class ReviewResolution:
    action: ReviewAction
    execute_tool: bool
    release_raw_content: bool
    observation: str | None


def resolve_review(
    assessment: RiskAssessment,
    action: ReviewAction,
    *,
    direction: Literal["pre_hop", "post_hop"],
) -> ReviewResolution:
    """Validate a human action and map it to execution/release behavior.

    ``evidence_only`` never runs a pre-hop call and never returns raw post-hop
    content to the agent. Post-hop review cannot reverse an already-completed
    tool side effect; it controls only the observation released to the agent.
    """
    if action not in assessment.options or action == "allow" and assessment.tier == "high":
        raise ValueError(f"action {action!r} is not permitted for {assessment.tier} risk")
    if direction not in ("pre_hop", "post_hop"):
        raise ValueError("direction must be 'pre_hop' or 'post_hop'")
    if action == "allow":
        return ReviewResolution(action, direction == "pre_hop", direction == "post_hop", None)
    if action == "deny":
        return ReviewResolution(action, False, False, "Blocked by human review.")
    return ReviewResolution(
        action,
        False,
        False,
        "Untrusted content retained as inert evidence; raw content withheld.",
    )
