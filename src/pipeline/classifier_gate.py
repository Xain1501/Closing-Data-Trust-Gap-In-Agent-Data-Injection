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
    *,
    structural_hits: int = 0,
    classifier_out_of_distribution: bool = False,
) -> GraphRiskResult:
    """Classify a trust graph; keep parser hit evidence separate from probability."""
    if not isinstance(classifier_out_of_distribution, bool):
        raise ValueError("classifier_out_of_distribution must be a boolean")
    prediction = classifier.predict(graph)
    risk = assess_risk(
        structural_score,
        prediction.attack_probability,
        impact,
        structural_hits=structural_hits,
        classifier_out_of_distribution=(
            classifier_out_of_distribution or prediction.out_of_distribution
        ),
        classifier_predicted_attack=prediction.predicted_label == "attack",
    )
    return GraphRiskResult(prediction, risk)
