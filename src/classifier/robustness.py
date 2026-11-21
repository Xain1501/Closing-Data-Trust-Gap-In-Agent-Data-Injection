"""Sanity checks for the offline graph classifier evaluation."""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from sklearn.metrics import accuracy_score, balanced_accuracy_score, recall_score

from classifier.train import _load_graph_jsonl
from classifier.wl_svm import WLGraphSVM


def _rows(path: str | Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _graph(row: dict):
    from classifier.wl_svm import GraphSnapshot
    data = row["graph"]
    return GraphSnapshot(node_labels=data["node_labels"], edges=tuple(tuple(e) for e in data["edges"]))


def label_shuffle(train_path: str | Path, test_path: str | Path, repeats: int = 10) -> dict[str, float]:
    train, _, groups = _load_graph_jsonl(train_path, expected_split="train", require_groups=True)
    _, test_labels, _ = _load_graph_jsonl(test_path, expected_split="test", require_groups=True)
    rows = _rows(train_path)
    original = [row["label"] for row in rows]
    scores = []
    for seed in range(repeats):
        labels = original[:]
        random.Random(seed).shuffle(labels)
        model = WLGraphSVM().fit(train, labels, group_ids=[g for g in groups if g is not None])
        predictions = [model.predict(g).predicted_label for g in _load_graph_jsonl(test_path, expected_split="test", require_groups=True)[0]]
        scores.append({
            "accuracy": accuracy_score(test_labels, predictions),
            "balanced_accuracy": balanced_accuracy_score(test_labels, predictions),
            "attack_recall": recall_score(test_labels, predictions, pos_label="attack", zero_division=0),
        })
    return {key: sum(item[key] for item in scores) / len(scores) for key in scores[0]}


def leave_one_suite_out(train_path: str | Path, test_path: str | Path) -> dict[str, dict[str, float | int | str]]:
    train_rows = _rows(train_path)
    test_rows = _rows(test_path)
    rows = train_rows + test_rows
    result = {}
    for suite in sorted({row.get("suite") for row in rows}):
        train = [row for row in rows if row.get("suite") != suite]
        test = [row for row in rows if row.get("suite") == suite]
        if len({row["label"] for row in train}) < 2 or len({row["label"] for row in test}) < 2:
            result[suite] = {"status": "insufficient_both_class_examples", "train": len(train), "test": len(test)}
            continue
        model = WLGraphSVM().fit([_graph(row) for row in train], [row["label"] for row in train], group_ids=[row["group_id"] for row in train])
        actual = [row["label"] for row in test]
        predicted = [model.predict(_graph(row)).predicted_label for row in test]
        result[suite] = {
            "status": "ok", "train": len(train), "test": len(test),
            "accuracy": float(accuracy_score(actual, predicted)),
            "balanced_accuracy": float(balanced_accuracy_score(actual, predicted)),
            "attack_recall": float(recall_score(actual, predicted, pos_label="attack", zero_division=0)),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True)
    parser.add_argument("--test", required=True)
    args = parser.parse_args()
    print(json.dumps({"label_shuffle": label_shuffle(args.train, args.test), "leave_one_suite_out": leave_one_suite_out(args.train, args.test)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
