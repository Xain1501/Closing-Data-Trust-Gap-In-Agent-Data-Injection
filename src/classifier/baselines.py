"""Evaluate simple parser-only and summary-feature baselines."""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

from classifier.train import _load_graph_jsonl
from classifier.wl_svm import GraphSnapshot, wl_features


def _parser_rule(graph: GraphSnapshot) -> str:
    labels = graph.node_labels.values()
    suspicious = any(
        label.startswith("finding:")
        or ":forgery=true" in label
        or ":forgery=leaf" in label
        or ":mimicry=true" in label
        for label in labels
    )
    return "attack" if suspicious else "benign"


def _metrics(actual: list[str], predicted: list[str]) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(actual, predicted)),
        "attack_precision": float(precision_score(actual, predicted, pos_label="attack", zero_division=0)),
        "attack_recall": float(recall_score(actual, predicted, pos_label="attack", zero_division=0)),
        "attack_f1": float(f1_score(actual, predicted, pos_label="attack", zero_division=0)),
    }


def _group_bootstrap_ci(
    actual: list[str],
    predicted: list[str],
    groups: list[str | None],
    *,
    repeats: int = 1000,
    seed: int = 0,
) -> dict[str, list[float]]:
    grouped: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        grouped.setdefault(group or f"row:{index}", []).append(index)
    keys = sorted(grouped)
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {
        "accuracy": [],
        "attack_recall": [],
        "attack_f1": [],
    }
    for _ in range(repeats):
        indices = [
            index
            for key in (rng.choice(keys) for _ in keys)
            for index in grouped[key]
        ]
        metrics = _metrics(
            [actual[index] for index in indices],
            [predicted[index] for index in indices],
        )
        for name in samples:
            samples[name].append(metrics[name])
    return {
        name: [
            sorted(values)[int((repeats - 1) * 0.025)],
            sorted(values)[int((repeats - 1) * 0.975)],
        ]
        for name, values in samples.items()
    }


def evaluate_baselines(train_path: str | Path, test_path: str | Path) -> dict[str, object]:
    train, train_labels, train_groups = _load_graph_jsonl(
        train_path, expected_split="train", require_groups=True, expected_unit="run"
    )
    test, test_labels, test_groups = _load_graph_jsonl(
        test_path, expected_split="test", require_groups=True, expected_unit="run"
    )
    overlap = set(train_groups) & set(test_groups)
    if overlap:
        raise ValueError(f"training and test groups overlap: {sorted(overlap)[:5]}")
    parser_predictions = [_parser_rule(graph) for graph in test]
    keys = sorted({key for graph in train for key in wl_features(graph) if key.startswith("summary:")})
    def vector(graph: GraphSnapshot) -> list[float]:
        values = wl_features(graph)
        return [values.get(key, 0.0) for key in keys]
    model = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000, random_state=0))
    model.fit([vector(graph) for graph in train], train_labels)
    logistic_predictions = list(model.predict([vector(graph) for graph in test]))
    parser_metrics = _metrics(test_labels, parser_predictions)
    logistic_metrics = _metrics(test_labels, logistic_predictions)
    return {
        "examples": len(test_labels),
        "groups": len(set(test_groups)),
        "parser_rule": {
            **parser_metrics,
            "group_bootstrap_95ci": _group_bootstrap_ci(
                test_labels, parser_predictions, test_groups
            ),
        },
        "summary_logistic_regression": {
            **logistic_metrics,
            "group_bootstrap_95ci": _group_bootstrap_ci(
                test_labels, logistic_predictions, test_groups
            ),
        },
        "features": keys,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True)
    parser.add_argument("--test", required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate_baselines(args.train, args.test), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
