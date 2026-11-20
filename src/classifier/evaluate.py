"""Evaluate a trained WL-SVM on held-out graph JSONL."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from classifier.train import _load_graph_jsonl
from classifier.wl_svm import WLGraphSVM


def _calibration_bins(
    actual: list[int], probabilities: list[float], count: int = 10
) -> tuple[float, list[dict[str, float | int]]]:
    bins: list[dict[str, float | int]] = []
    weighted_error = 0.0
    total = len(actual)
    for index in range(count):
        lower = index / count
        upper = (index + 1) / count
        selected = [
            (truth, score)
            for truth, score in zip(actual, probabilities)
            if lower <= score < upper or index == count - 1 and score == 1.0
        ]
        if not selected:
            continue
        observed = sum(truth for truth, _ in selected) / len(selected)
        confidence = sum(score for _, score in selected) / len(selected)
        weighted_error += len(selected) / total * abs(confidence - observed)
        bins.append({
            "lower": lower,
            "upper": upper,
            "examples": len(selected),
            "mean_predicted_attack_probability": confidence,
            "observed_attack_rate": observed,
        })
    return weighted_error, bins


def evaluate(model_path: str | Path, test_path: str | Path) -> dict[str, object]:
    graphs, labels, group_ids = _load_graph_jsonl(
        test_path, expected_split="test", require_groups=True
    )
    model = WLGraphSVM.load(model_path)
    training_groups = model.training_group_ids
    test_groups = {group for group in group_ids if group is not None}
    if training_groups is None:
        raise ValueError("model artifact does not record its training groups")
    overlap = training_groups & test_groups
    if overlap:
        raise ValueError(f"training and test groups overlap: {sorted(overlap)[:5]}")
    predictions = [model.predict(graph) for graph in graphs]
    predicted_labels = [item.predicted_label for item in predictions]
    probabilities = [item.attack_probability for item in predictions]
    actual = [int(label == "attack") for label in labels]
    ece, calibration_bins = _calibration_bins(actual, probabilities)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted_labels, labels=["attack", "benign"], average="binary", pos_label="attack", zero_division=0,
    )
    metrics: dict[str, object] = {
        "examples": len(labels),
        "groups": len(test_groups),
        "label_counts": {label: labels.count(label) for label in ("attack", "benign")},
        "accuracy": float(accuracy_score(labels, predicted_labels)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predicted_labels)),
        "attack_precision": float(precision),
        "attack_recall": float(recall),
        "attack_f1": float(f1),
        "confusion_matrix": {
            "labels": ["attack", "benign"],
            "counts": confusion_matrix(
                labels, predicted_labels, labels=["attack", "benign"]
            ).tolist(),
        },
        "attack_brier_score": sum(
            (truth - score) ** 2 for truth, score in zip(actual, probabilities)
        ) / len(actual),
        "attack_ece": ece,
        "reliability_bins": calibration_bins,
    }
    if len(set(actual)) == 2:
        metrics["attack_roc_auc"] = float(roc_auc_score(actual, probabilities))
        metrics["attack_pr_auc"] = float(average_precision_score(actual, probabilities))
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model")
    parser.add_argument("test_jsonl")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.model, args.test_jsonl), indent=2))


if __name__ == "__main__":
    main()
