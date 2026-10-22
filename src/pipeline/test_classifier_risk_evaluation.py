import pytest

from classifier.wl_svm import GraphSnapshot, WLGraphSVM, wl_features
from pipeline.evaluation import EvaluationCase, calculate_metrics
from pipeline.evidence_panel import EvidencePanel
from pipeline.risk_gate import assess_risk, resolve_review


def _graph(attack: bool, index: int = 0) -> GraphSnapshot:
    root = f"root-{index}"
    field = f"field-{index}"
    if attack:
        return GraphSnapshot(
            {root: "T:object", field: "UT:nested_call"},
            ((root, field),),
        )
    return GraphSnapshot(
        {root: "T:object", field: "UT:string"},
        ((root, field),),
    )


def test_wl_features_are_stable_and_include_neighbor_structure():
    graph = _graph(True)
    assert wl_features(graph) == wl_features(graph)
    assert any(feature.startswith("wl:2:") for feature in wl_features(graph))
    assert wl_features(graph) != wl_features(_graph(False))


def test_wl_svm_fits_and_returns_calibrated_attack_probability():
    graphs = [_graph(label == "attack", index) for index, label in enumerate(
        ["benign"] * 6 + ["attack"] * 6
    )]
    labels = ["benign"] * 6 + ["attack"] * 6
    model = WLGraphSVM(iterations=2).fit(graphs, labels)

    benign = model.predict(_graph(False, 100))
    attack = model.predict(_graph(True, 101))

    assert 0.0 <= benign.attack_probability <= 1.0
    assert 0.0 <= attack.attack_probability <= 1.0
    assert attack.attack_probability > benign.attack_probability


def test_risk_thresholds_match_proposal_and_remove_allow_at_high_risk():
    low = assess_risk(0.1, 0.0, 5)
    moderate = assess_risk(0.2, 0.2, 5)
    high = assess_risk(0.5, 0.5, 10)

    assert low.tier == "low" and low.route == "auto_allow"
    assert moderate.tier == "moderate" and "allow" in moderate.options
    assert high.tier == "high" and high.risk_score == pytest.approx(7.5)
    assert high.options == ("deny", "evidence_only")
    with pytest.raises(ValueError, match="not permitted"):
        resolve_review(high, "allow", direction="pre_hop")


def test_review_resolution_controls_pre_execution_and_post_release():
    moderate = assess_risk(0.2, 0.2, 5)
    pre_allow = resolve_review(moderate, "allow", direction="pre_hop")
    post_allow = resolve_review(moderate, "allow", direction="post_hop")
    evidence = resolve_review(moderate, "evidence_only", direction="post_hop")

    assert pre_allow.execute_tool and not pre_allow.release_raw_content
    assert not post_allow.execute_tool and post_allow.release_raw_content
    assert not evidence.release_raw_content
    assert evidence.observation and "inert evidence" in evidence.observation


def test_evidence_panel_rendering_is_deterministic_and_complete():
    assessment = assess_risk(0.25, 0.2, 5)
    panel = EvidencePanel.from_evidence(
        original_user_query="Summarize this email",
        direction="post_hop",
        tool_name="read_email",
        proposed_call_or_result={"body": "untrusted"},
        untrusted_content=["untrusted"],
        provenance=["tool:read_email.body"],
        structural_warnings=["embedded_json at $.body"],
        assessment=assessment,
        expected_side_effect="Tool response will be shown to the agent",
    )

    rendered = panel.render()
    assert rendered == panel.render()
    assert '"risk_tier": "moderate"' in rendered
    assert '"original_user_query": "Summarize this email"' in rendered


def test_evaluation_metrics_report_proposal_rates():
    cases = [
        EvaluationCase("b1", "benign", task_success=True, flagged=False, human_decision="allow"),
        EvaluationCase("b2", "benign", task_success=False, flagged=True),
        EvaluationCase("a1", "attack", task_success=True, flagged=True, attack_success=False,
                       human_decision="deny"),
        EvaluationCase("a2", "attack", task_success=False, flagged=False, attack_success=True),
    ]
    metrics = calculate_metrics(cases)

    assert metrics.attack_success_rate == pytest.approx(0.5)
    assert metrics.benign_utility == pytest.approx(0.5)
    assert metrics.utility_under_attack == pytest.approx(0.5)
    assert metrics.false_positive_rate == pytest.approx(0.5)
    assert metrics.false_negative_rate == pytest.approx(0.5)
    assert metrics.human_approval_accuracy == pytest.approx(1.0)


def test_attack_metrics_require_attack_success_labels():
    with pytest.raises(ValueError, match="needs attack_success"):
        calculate_metrics([EvaluationCase("a1", "attack", True, False)])
