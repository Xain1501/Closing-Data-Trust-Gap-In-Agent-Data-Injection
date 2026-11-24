"""Evaluate simple parser-only and summary-feature baselines."""
from __future__ import annotations

import argparse
import json
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


def evaluate_baselines(train_path: str | Path, test_path: str | Path) -> dict[str, object]:
    train, train_labels, _ = _load_graph_jsonl(train_path, expected_split="train", require_groups=True)
    test, test_labels, _ = _load_graph_jsonl(test_path, expected_split="test", require_groups=True)
    parser_predictions = [_parser_rule(graph) for graph in test]
    keys = sorted({key for graph in train for key in wl_features(graph) if key.startswith("summary:")})
    def vector(graph: GraphSnapshot) -> list[float]:
        values = wl_features(graph)
        return [values.get(key, 0.0) for key in keys]
    model = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000, random_state=0))
    model.fit([vector(graph) for graph in train], train_labels)
    logistic_predictions = list(model.predict([vector(graph) for graph in test]))
    return {
        "parser_rule": _metrics(test_labels, parser_predictions),
        "summary_logistic_regression": _metrics(test_labels, logistic_predictions),
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
