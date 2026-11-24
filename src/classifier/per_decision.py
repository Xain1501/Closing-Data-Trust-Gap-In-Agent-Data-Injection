"""Evaluate a run-level model at each recorded interception decision point."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sklearn.metrics import accuracy_score, precision_recall_fscore_support, recall_score

from classifier.wl_svm import GraphSnapshot, WLGraphSVM


def evaluate_per_decision(model_path: str | Path, test_path: str | Path) -> dict[str, object]:
    model = WLGraphSVM.load(model_path)
    rows = [json.loads(line) for line in Path(test_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    labels: list[str] = []
    predictions: list[str] = []
    directions: dict[str, int] = {}
    for row in rows:
        for point in row.get("decision_graphs", []):
            graph = GraphSnapshot(
                node_labels=point["node_labels"],
                edges=tuple(tuple(edge) for edge in point["edges"]),
            )
            labels.append(row["label"])
            predictions.append(model.predict(graph).predicted_label)
            direction = str(point.get("direction", "unknown"))
            directions[direction] = directions.get(direction, 0) + 1
    if not labels:
        raise ValueError("test data contains no decision_graphs; rebuild the dataset")
    _, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, labels=["attack", "benign"], average="binary",
        pos_label="attack", zero_division=0,
    )
    return {
        "decisions": len(labels),
        "directions": directions,
        "accuracy": float(accuracy_score(labels, predictions)),
        "attack_recall": float(recall),
        "attack_f1": float(f1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model")
    parser.add_argument("test_jsonl")
    args = parser.parse_args()
    print(json.dumps(evaluate_per_decision(args.model, args.test_jsonl), indent=2))


if __name__ == "__main__":
    main()
