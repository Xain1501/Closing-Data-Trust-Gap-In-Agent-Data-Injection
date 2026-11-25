"""Compatibility guard for the offline-only run-level WL-SVM."""
from __future__ import annotations

from collections.abc import Callable

from classifier.wl_svm import WLGraphSVM
from clone.core import DetectorContext, DetectorDecision
from clone.ledger import DetectorPayload
from pipeline.evidence_panel import EvidencePanel
from pipeline.risk_gate import RiskAssessment
from provenance.run_state import RunStateStore

ReviewCallback = Callable[[RiskAssessment, EvidencePanel], str]


def make_risk_detector(
    classifier: WLGraphSVM,
    *,
    reviewer: ReviewCallback | None = None,
    user_query: Callable[[DetectorContext], str] | None = None,
    run_states: RunStateStore | None = None,
) -> Callable[[DetectorPayload, DetectorContext | None], DetectorDecision]:
    """Reject using a complete-run classifier at per-interception time."""
    raise RuntimeError(
        "WL-SVM is trained and evaluated on complete run graphs and is offline-only; "
        "use parser_detector for live interception"
    )
