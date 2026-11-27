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
    confidence: float | None
    impact: ImpactTier
    risk_score: float
    tier: RiskTier
    route: Literal["auto_allow", "human_review"]
    options: tuple[ReviewAction, ...]
    review_reasons: tuple[str, ...] = ()


def _probability(value: float, name: str) -> float:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be a finite value in [0, 1]")
    return value


def assess_risk(
    structural_score: float,
    classifier_score: float | None,
    impact: int | None,
    *,
    structural_hits: int = 0,
    classifier_out_of_distribution: bool = False,
    classifier_score_affects_risk: bool = True,
) -> RiskAssessment:
    """Apply classifier-risk thresholds and independent review triggers.

    ``structural_score`` is a parser density heuristic, not a probability, so it
    is retained as evidence but never combined arithmetically with classifier
    confidence. A counted structural hit, missing classifier, or explicit
    out-of-distribution signal forces review. Callers may retain a classifier
    score for evidence while excluding it from risk decisions. The run-level
    WL-SVM supplies an OOD signal from unseen WL-feature mass; this is a novelty
    heuristic, not an attack probability or proof of malicious intent.
    """
    structural = _probability(structural_score, "structural_score")
    classifier = None if classifier_score is None else _probability(classifier_score, "classifier_score")
    if isinstance(structural_hits, bool) or not isinstance(structural_hits, int) or structural_hits < 0:
        raise ValueError("structural_hits must be a non-negative integer")
    if not isinstance(classifier_out_of_distribution, bool):
        raise ValueError("classifier_out_of_distribution must be a boolean")
    if not isinstance(classifier_score_affects_risk, bool):
        raise ValueError("classifier_score_affects_risk must be a boolean")
    if impact not in (1, 5, 10):
        raise ValueError("impact must be one of 1, 5, or 10")
    confidence = classifier
    risk = (classifier or 0.0) * impact if classifier_score_affects_risk else 0.0
    review_reasons = []
    if classifier_score is None:
        review_reasons.append("classifier_unavailable")
    if classifier_out_of_distribution:
        review_reasons.append("classifier_out_of_distribution")
    # Density is evidence only.  Located parser findings are counted by
    # ``structural_hits``; anomaly density alone must never force review.
    if structural_hits:
        review_reasons.append("structural_findings")
    if risk < 1.0:
        tier: RiskTier = "low"
        options: tuple[ReviewAction, ...] = ("allow", "deny", "evidence_only")
    elif risk < 5.0:
        tier = "moderate"
        options = ("allow", "deny", "evidence_only")
    else:
        tier = "high"
        options = ("deny", "evidence_only")
    auto_allow = not review_reasons and risk < 1.0
    if classifier_score_affects_risk and risk >= 1.0:
        review_reasons.append("classifier_risk_threshold")
    route: Literal["auto_allow", "human_review"] = "auto_allow" if auto_allow else "human_review"
    return RiskAssessment(
        structural, classifier_score, confidence, impact, risk, tier, route, options,
        tuple(review_reasons),
    )


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
