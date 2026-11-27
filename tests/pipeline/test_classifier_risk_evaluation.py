import json
import pytest
from uuid import uuid4

import joblib

from classifier.evaluate import evaluate
from classifier.ablation import _write_jsonl
from classifier.train import _load_graph_jsonl
from classifier.baselines import _group_bootstrap_ci, _parser_rule
from classifier.wl_svm import ClassifierResult, GraphSnapshot, WLGraphSVM, wl_features
from pipeline.classifier_gate import classify_and_assess
from pipeline.evaluation import EvaluationCase, calculate_metrics
from pipeline.evidence_panel import EvidencePanel
from pipeline.risk_gate import assess_risk, resolve_review
from pipeline.risk_detector import make_risk_detector
from parser.models import Direction, ParseResult, ParsedField, ParseStatus
from trust_graph import build_trust_graph, tag_fields


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
    features = wl_features(graph)
    assert features == wl_features(graph)
    assert any(feature.startswith("wl:2:") for feature in features)
    assert features != wl_features(_graph(False))
    assert sum(value for key, value in features.items() if key.startswith("wl:0:")) == pytest.approx(1.0)
    raw_counts = wl_features(graph, normalize_counts=False)
    assert sum(value for key, value in raw_counts.items() if key.startswith("wl:0:")) == 2


def test_parser_baseline_counts_leaf_forgery_as_suspicious():
    graph = GraphSnapshot({"n0": "T:string:forgery=leaf"}, ())

    assert _parser_rule(graph) == "attack"


def test_baseline_bootstrap_resamples_whole_groups_deterministically():
    actual = ["attack", "benign", "attack", "benign"]
    predicted = ["attack", "attack", "benign", "benign"]
    groups = ["task-1", "task-1", "task-2", "task-2"]

    intervals = _group_bootstrap_ci(actual, predicted, groups, repeats=100)

    assert set(intervals) == {"accuracy", "attack_recall", "attack_f1"}
    assert intervals == _group_bootstrap_ci(
        actual, predicted, groups, repeats=100
    )
    assert all(len(bounds) == 2 and bounds[0] <= bounds[1] for bounds in intervals.values())


def test_ablation_jsonl_keeps_run_level_contract(tmp_path):
    path = tmp_path / "train.jsonl"

    _write_jsonl(
        path,
        [_graph(False), _graph(True)],
        ["benign", "attack"],
        ["group-benign", "group-attack"],
        "train",
    )

    graphs, labels, groups = _load_graph_jsonl(
        path,
        expected_split="train",
        require_groups=True,
        expected_unit="run",
    )
    assert len(graphs) == 2
    assert labels == ["benign", "attack"]
    assert groups == ["group-benign", "group-attack"]


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


def test_classifier_outputs_keep_svm_and_ood_signals_separate():
    attack = ClassifierResult(0.7, "attack")
    unfamiliar = ClassifierResult(0.2, "benign", 0.3, True)
    benign = ClassifierResult(0.1, "benign")

    assert attack.svm_attack_flag
    assert not attack.ood_flag
    assert not attack.review_flag
    assert not unfamiliar.svm_attack_flag
    assert unfamiliar.ood_flag
    assert unfamiliar.review_flag
    assert not benign.svm_attack_flag
    assert not benign.ood_flag
    assert not benign.review_flag


def test_wl_svm_artifact_retains_training_groups(tmp_path):
    labels = ["benign"] * 6 + ["attack"] * 6
    graphs = [_graph(label == "attack", index) for index, label in enumerate(labels)]
    groups = [f"group-{index}" for index in range(len(labels))]
    model_path = tmp_path / "wl_svm.joblib"

    model = WLGraphSVM(iterations=1).fit(graphs, labels, group_ids=groups)
    model.save(model_path)
    loaded = WLGraphSVM.load(model_path)
    artifact = joblib.load(model_path)

    assert loaded.training_group_ids == frozenset(groups)
    assert loaded.training_unit == "run"
    assert artifact["feature_schema_version"] == 2
    assert artifact["training_unit"] == "run"
    assert loaded.ood_threshold == pytest.approx(model.ood_threshold)


def test_unseen_graph_features_abstain_and_force_review():
    labels = ["benign"] * 6 + ["attack"] * 6
    graphs = [_graph(label == "attack", index) for index, label in enumerate(labels)]
    groups = [f"group-{index}" for index in range(len(labels))]
    model = WLGraphSVM(iterations=1).fit(graphs, labels, group_ids=groups)
    unfamiliar = GraphSnapshot({"new-node": "T:unseen:structure"}, ())

    prediction = model.predict(unfamiliar)
    result = classify_and_assess(unfamiliar, model, 0.0, 1)

    assert prediction.novelty_score > model.ood_threshold
    assert prediction.out_of_distribution
    assert prediction.ood_flag
    assert prediction.review_flag
    assert result.assessment.route == "human_review"
    assert "classifier_out_of_distribution" in result.assessment.review_reasons


def test_classifier_attack_prediction_is_evidence_only(monkeypatch):
    labels = ["benign"] * 6 + ["attack"] * 6
    graphs = [_graph(label == "attack", index) for index, label in enumerate(labels)]
    model = WLGraphSVM(iterations=1).fit(
        graphs, labels, group_ids=[f"group-{index}" for index in range(len(labels))]
    )
    monkeypatch.setattr(
        model,
        "predict",
        lambda graph: ClassifierResult(0.99, "attack"),
    )

    result = classify_and_assess(_graph(False, 100), model, 0.0, 10)

    assert result.classifier.svm_attack_flag
    assert result.classifier.attack_probability == pytest.approx(0.99)
    assert not result.classifier.ood_flag
    assert result.assessment.classifier_score == pytest.approx(0.99)
    assert result.assessment.risk_score == 0.0
    assert result.assessment.route == "auto_allow"
    assert "classifier_attack_prediction" not in result.assessment.review_reasons


def test_known_graph_is_not_marked_ood_by_feature_vocabulary():
    labels = ["benign"] * 6 + ["attack"] * 6
    graphs = [_graph(label == "attack", index) for index, label in enumerate(labels)]
    model = WLGraphSVM(iterations=1).fit(
        graphs, labels, group_ids=[f"group-{index}" for index in range(len(labels))]
    )

    assert not model.predict(_graph(False, 100)).out_of_distribution


def test_risk_thresholds_match_proposal_and_remove_allow_at_high_risk():
    low = assess_risk(0.0, 0.0, 5)
    moderate = assess_risk(0.2, 0.2, 5)
    high = assess_risk(0.5, 0.5, 10)

    assert low.tier == "low" and low.route == "auto_allow"
    assert moderate.tier == "moderate" and "allow" in moderate.options
    assert high.tier == "high" and high.risk_score == pytest.approx(5.0)
    assert high.options == ("deny", "evidence_only")
    with pytest.raises(ValueError, match="not permitted"):
        resolve_review(high, "allow", direction="pre_hop")


def test_structural_density_is_evidence_not_classifier_probability():
    dense = assess_risk(0.9, 0.0, 1)
    sparse = assess_risk(0.01, 0.0, 1)

    assert dense.risk_score == sparse.risk_score == 0.0
    # Density is evidence only; without a counted hit it cannot force review.
    assert dense.route == sparse.route == "auto_allow"


def test_structural_hit_forces_review_even_when_density_is_diluted():
    result = assess_risk(0.00001, 0.0, 1, structural_hits=1)

    assert result.risk_score == 0.0
    assert result.route == "human_review"
    assert "structural_findings" in result.review_reasons


def test_missing_classifier_forces_review_instead_of_auto_allow():
    result = assess_risk(0.0, None, 1)

    assert result.route == "human_review"
    assert "classifier_unavailable" in result.review_reasons


def test_explicit_out_of_distribution_signal_forces_review_even_at_low_score():
    result = assess_risk(
        0.0,
        0.0,
        1,
        classifier_out_of_distribution=True,
    )

    assert result.route == "human_review"
    assert result.review_reasons == ("classifier_out_of_distribution",)


def test_out_of_distribution_signal_requires_boolean():
    with pytest.raises(ValueError, match="must be a boolean"):
        assess_risk(0.0, 0.0, 1, classifier_out_of_distribution=1)
    with pytest.raises(ValueError, match="must be a boolean"):
        assess_risk(0.0, 0.0, 1, classifier_score_affects_risk=1)


def test_review_resolution_controls_pre_execution_and_post_release():
    moderate = assess_risk(0.2, 0.2, 5)
    pre_allow = resolve_review(moderate, "allow", direction="pre_hop")
    post_allow = resolve_review(moderate, "allow", direction="post_hop")
    evidence = resolve_review(moderate, "evidence_only", direction="post_hop")
    pre_evidence = resolve_review(moderate, "evidence_only", direction="pre_hop")

    assert pre_allow.execute_tool and not pre_allow.release_raw_content
    assert not post_allow.execute_tool and post_allow.release_raw_content
    assert not evidence.release_raw_content
    assert evidence.observation and "inert evidence" in evidence.observation
    assert not pre_evidence.execute_tool and not pre_evidence.release_raw_content
    assert pre_evidence.observation and "inert evidence" in pre_evidence.observation


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


def test_tagging_defaults_unknown_classes_to_untrusted_and_graph_preserves_paths():
    parsed = ParseResult(
        internal_id=uuid4(),
        direction=Direction.PRE_HOP,
        tool_name="demo",
        tool_call_id="c1",
        status=ParseStatus.OK,
        fields=[
            ParsedField(path="$", key=None, parent_path=None, depth=0, value_type="object"),
            ParsedField(path="$.account", key="account", parent_path="$", depth=1,
                        value_type="object"),
            ParsedField(path="$.account.id", key="id", parent_path="$.account", depth=2,
                        value_type="string", value="123"),
        ],
        findings=[],
        boundary_count=3,
    )
    tagged = tag_fields(parsed, {"account": "trusted"})
    graph = build_trust_graph(tagged)

    assert tagged[1].trust.value == "T"
    assert tagged[2].trust.value == "T"
    assert tagged[0].trust.value == "UT"
    assert ("$.account", "$.account.id") in graph.edges


def test_run_level_classifier_is_rejected_by_live_risk_factory():
    with pytest.raises(RuntimeError, match="complete run graphs.*offline-only"):
        make_risk_detector(WLGraphSVM())


def test_per_decision_metrics_reject_run_level_labels():
    from classifier.per_decision import evaluate_per_decision

    with pytest.raises(ValueError, match="not valid per-decision ground truth"):
        evaluate_per_decision("unused-model", "unused-dataset")


def test_evaluation_reports_metrics_by_attack_family_and_collection_mode(tmp_path):
    train_rows = []
    train_labels = ["benign", "attack"] * 4
    for index, label in enumerate(train_labels):
        train_rows.append({
            "case_id": f"train-{index}",
            "label": label,
            "split": "train",
            "classification_unit": "run",
            "group_id": f"train-group-{index}",
            "graph": _graph(label == "attack", index).__dict__,
        })
    test_rows = []
    for index, label in enumerate(["attack", "attack", "benign", "benign"]):
        test_rows.append({
            "case_id": f"test-{index}",
            "label": label,
            "split": "test",
            "classification_unit": "run",
            "group_id": f"test-group-{index}",
            "attack_family": "unseen-family" if label == "attack" else None,
            "collection_mode": (
                "injected_attack_replay" if label == "attack"
                else "matched_clean_counterfactual"
            ),
            "graph": _graph(label == "attack", 100 + index).__dict__,
        })
    train_path = tmp_path / "train.jsonl"
    test_path = tmp_path / "test.jsonl"
    train_path.write_text(
        "".join(json.dumps(row) + "\n" for row in train_rows), encoding="utf-8"
    )
    test_path.write_text(
        "".join(json.dumps(row) + "\n" for row in test_rows), encoding="utf-8"
    )
    model_path = tmp_path / "model.joblib"
    graphs = [_graph(row["label"] == "attack", index) for index, row in enumerate(train_rows)]
    model = WLGraphSVM(iterations=1).fit(
        graphs,
        train_labels,
        group_ids=[row["group_id"] for row in train_rows],
    )
    model.save(model_path)

    metrics = evaluate(model_path, test_path)

    assert metrics["subgroup_metrics"]["attack_family"]["unseen-family"]["examples"] == 2
    assert "out_of_distribution" in metrics
    expected_ood_flags = [
        model.predict(_graph(label == "attack", 100 + index)).ood_flag
        for index, label in enumerate(["attack", "attack", "benign", "benign"])
    ]
    ood_metrics = metrics["review_route_ood_only"]
    assert ood_metrics["flagged_examples"] == sum(expected_ood_flags)
    assert ood_metrics["flagged_rate"] == pytest.approx(sum(expected_ood_flags) / 4)
    assert ood_metrics["attack_capture_rate"] == pytest.approx(
        sum(expected_ood_flags[:2]) / 2
    )
    assert ood_metrics["benign_review_rate"] == pytest.approx(
        sum(expected_ood_flags[2:]) / 2
    )
    assert "svm_attack_flag" in metrics
    assert metrics["subgroup_metrics"]["collection_mode"]["matched_clean_counterfactual"]["label_counts"] == {
        "attack": 0,
        "benign": 2,
    }
