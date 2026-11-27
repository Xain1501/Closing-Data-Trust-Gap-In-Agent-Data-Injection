"""Evaluate a trained WL-SVM on held-out graph JSONL."""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    recall_score,
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
        test_path, expected_split="test", require_groups=True, expected_unit="run"
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
    ood_flags = [item.out_of_distribution for item in predictions]
    svm_attack_flags = [item.svm_attack_flag for item in predictions]
    ece, calibration_bins = _calibration_bins(actual, probabilities)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted_labels, labels=["attack", "benign"], average="binary", pos_label="attack", zero_division=0,
    )
    metrics: dict[str, object] = {
        "classification_unit": model.training_unit,
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
        "out_of_distribution": {
            "threshold": model.ood_threshold,
            "flagged_examples": sum(ood_flags),
            "flagged_rate": sum(ood_flags) / len(ood_flags),
            "attack_capture_rate": (
                sum(flag for flag, label in zip(ood_flags, labels) if label == "attack")
                / labels.count("attack")
                if "attack" in labels else 0.0
            ),
            "benign_review_rate": (
                sum(flag for flag, label in zip(ood_flags, labels) if label == "benign")
                / labels.count("benign")
                if "benign" in labels else 0.0
            ),
        },
        "svm_attack_flag": {
            "flagged_examples": sum(svm_attack_flags),
            "flagged_rate": sum(svm_attack_flags) / len(svm_attack_flags),
            "attack_capture_rate": (
                sum(flag for flag, label in zip(svm_attack_flags, labels) if label == "attack")
                / labels.count("attack")
                if "attack" in labels else 0.0
            ),
            "benign_review_rate": (
                sum(flag for flag, label in zip(svm_attack_flags, labels) if label == "benign")
                / labels.count("benign")
                if "benign" in labels else 0.0
            ),
        },
        "review_route_ood_only": {
            "flagged_examples": sum(ood_flags),
            "flagged_rate": sum(ood_flags) / len(ood_flags),
            "attack_capture_rate": (
                sum(flag for flag, label in zip(ood_flags, labels) if label == "attack")
                / labels.count("attack") if "attack" in labels else 0.0
            ),
            "benign_review_rate": (
                sum(flag for flag, label in zip(ood_flags, labels) if label == "benign")
                / labels.count("benign") if "benign" in labels else 0.0
            ),
        },
    }
    rows = [json.loads(line) for line in Path(test_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    subgroup_metrics: dict[str, dict[str, dict[str, object]]] = {}
    for dimension in (
        "benchmark_family", "attack_family", "source", "collection_mode",
        "label_basis", "suite",
    ):
        grouped_indices: dict[str, list[int]] = {}
        for index, row in enumerate(rows):
            value = row.get(dimension)
            if value is not None:
                grouped_indices.setdefault(str(value), []).append(index)
        if not grouped_indices:
            continue
        subgroup_metrics[dimension] = {}
        for value, indices in sorted(grouped_indices.items()):
            subgroup_labels = [labels[index] for index in indices]
            subgroup_predictions = [predicted_labels[index] for index in indices]
            subgroup_precision, subgroup_recall, subgroup_f1, _ = (
                precision_recall_fscore_support(
                    subgroup_labels,
                    subgroup_predictions,
                    labels=["attack", "benign"],
                    average="binary",
                    pos_label="attack",
                    zero_division=0,
                )
            )
            subgroup_metrics[dimension][value] = {
                "examples": len(indices),
                "label_counts": {
                    label: subgroup_labels.count(label)
                    for label in ("attack", "benign")
                },
                "accuracy": float(accuracy_score(subgroup_labels, subgroup_predictions)),
                "attack_precision": float(subgroup_precision),
                "attack_recall": float(subgroup_recall),
                "attack_f1": float(subgroup_f1),
            }
    metrics["subgroup_metrics"] = subgroup_metrics
    success_values = [row.get("attack_success") for row in rows if row.get("label") == "attack"]
    metrics["attack_success_counts"] = {
        "success": sum(value is True for value in success_values),
        "not_success": sum(value is False for value in success_values),
        "unknown": sum(value is None for value in success_values),
    }
    success_breakdown: dict[str, dict[str, float | int]] = {}
    for success, name in ((True, "successful_attack"), (False, "unsuccessful_attack")):
        indices = [i for i, row in enumerate(rows) if row.get("label") == "attack" and row.get("attack_success") is success]
        if indices:
            truth = [labels[i] for i in indices]
            guess = [predicted_labels[i] for i in indices]
            success_breakdown[name] = {
                "examples": len(indices),
                "recall": float(recall_score(truth, guess, pos_label="attack", zero_division=0)),
            }
    metrics["attack_success_breakdown"] = success_breakdown
    metrics["group_bootstrap_95ci"] = _group_bootstrap_ci(
        labels, predicted_labels, probabilities, group_ids
    )
    if len(set(actual)) == 2:
        metrics["attack_roc_auc"] = float(roc_auc_score(actual, probabilities))
        metrics["attack_pr_auc"] = float(average_precision_score(actual, probabilities))
    return metrics


def _group_bootstrap_ci(
    labels: list[str], predicted: list[str], probabilities: list[float],
    groups: list[str | None], *, repeats: int = 1000, seed: int = 0,
) -> dict[str, list[float]]:
    """Bootstrap whole task groups so examples from one task stay together."""
    grouped: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        grouped.setdefault(group or f"row:{index}", []).append(index)
    keys = list(grouped)
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {"accuracy": [], "attack_recall": [], "attack_f1": []}
    for _ in range(repeats):
        indices = [index for key in (rng.choice(keys) for _ in keys) for index in grouped[key]]
        truth = [labels[index] for index in indices]
        guess = [predicted[index] for index in indices]
        accuracy = accuracy_score(truth, guess)
        _, recall, f1, _ = precision_recall_fscore_support(
            truth, guess, labels=["attack", "benign"], average="binary",
            pos_label="attack", zero_division=0,
        )
        samples["accuracy"].append(float(accuracy))
        samples["attack_recall"].append(float(recall))
        samples["attack_f1"].append(float(f1))
    return {
        name: [float(sorted(values)[int(0.025 * (len(values) - 1))]),
               float(sorted(values)[int(0.975 * (len(values) - 1))])]
        for name, values in samples.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model")
    parser.add_argument("test_jsonl")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.model, args.test_jsonl), indent=2))


if __name__ == "__main__":
    main()
