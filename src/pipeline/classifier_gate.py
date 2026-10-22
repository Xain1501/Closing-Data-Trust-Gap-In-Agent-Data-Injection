"""Connect graph classification output to the deterministic risk gate."""
from __future__ import annotations

from dataclasses import dataclass

from classifier.wl_svm import ClassifierResult, GraphSnapshot, WLGraphSVM
from pipeline.risk_gate import RiskAssessment, assess_risk


@dataclass(frozen=True)
class GraphRiskResult:
    classifier: ClassifierResult
    assessment: RiskAssessment


def classify_and_assess(
    graph: GraphSnapshot,
    classifier: WLGraphSVM,
    structural_score: float,
    impact: int | None,
) -> GraphRiskResult:
    """Score one trust graph and combine it with the parser's structural score."""
    prediction = classifier.predict(graph)
    risk = assess_risk(structural_score, prediction.attack_probability, impact)
    return GraphRiskResult(prediction, risk)
