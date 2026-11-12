"""Detector pipeline orchestration components.

Keep optional classifier dependencies lazy so the parser-only bridge can run
without importing the sklearn/joblib-backed risk-composition path.
"""

from importlib import import_module

__all__ = [
    "GraphRiskResult",
    "RiskAssessment",
    "assess_risk",
    "classify_and_assess",
    "make_risk_detector",
    "resolve_review",
]


def __getattr__(name: str):
    if name in {"GraphRiskResult", "classify_and_assess"}:
        module = import_module(".classifier_gate", __name__)
        return getattr(module, name)
    if name in {"RiskAssessment", "assess_risk", "resolve_review"}:
        module = import_module(".risk_gate", __name__)
        return getattr(module, name)
    if name == "make_risk_detector":
        module = import_module(".risk_detector", __name__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
