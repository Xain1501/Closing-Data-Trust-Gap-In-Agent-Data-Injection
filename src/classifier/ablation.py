"""Run WL-SVM feature ablations on a fixed grouped train/test split.

This is an analysis tool, not part of the online risk path.  It removes
parser finding nodes and/or forgery markers while keeping the examples,
labels, groups, and split unchanged.  That makes the comparison answer what
the classifier is learning from the graph.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from classifier.evaluate import evaluate
from classifier.train import _load_graph_jsonl
from classifier.wl_svm import GraphSnapshot, WLGraphSVM


def _transform(graph: GraphSnapshot, *, remove_findings: bool, remove_forgery: bool) -> GraphSnapshot:
    labels = dict(graph.node_labels)
    flag_pattern = re.compile(r":(?:forgery|mimicry|anomaly)=(?:true|leaf|false)")
    kept = {
        node: (flag_pattern.sub("", label)
               if remove_forgery else label)
        for node, label in labels.items()
        if not (remove_findings and label.startswith("finding:"))
    }
    edges = tuple((left, right) for left, right in graph.edges if left in kept and right in kept)
    return GraphSnapshot(node_labels=kept, edges=edges)


def _write_jsonl(path: Path, graphs: list[GraphSnapshot], labels: list[str], groups: list[str | None], split: str) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index, (graph, label, group) in enumerate(zip(graphs, labels, groups)):
            row: dict[str, Any] = {
                "case_id": f"{split}-{index}",
                "label": label,
                "split": split,
                "classification_unit": "run",
                "group_id": group,
                "graph": {"node_labels": dict(graph.node_labels), "edges": [list(edge) for edge in graph.edges]},
            }
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def run_ablation(train_path: str | Path, test_path: str | Path, output_dir: str | Path) -> dict[str, dict[str, object]]:
    train_graphs, train_labels, train_groups = _load_graph_jsonl(train_path, expected_split="train", require_groups=True)
    test_graphs, test_labels, test_groups = _load_graph_jsonl(test_path, expected_split="test", require_groups=True)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    variants = {
        "full": (False, False),
        "without_findings": (True, False),
        "without_forgery": (False, True),
        "without_findings_and_forgery": (True, True),
    }
    results: dict[str, dict[str, object]] = {}
    for name, (remove_findings, remove_forgery) in variants.items():
        train_variant = [_transform(g, remove_findings=remove_findings, remove_forgery=remove_forgery) for g in train_graphs]
        test_variant = [_transform(g, remove_findings=remove_findings, remove_forgery=remove_forgery) for g in test_graphs]
        variant_dir = output / name
        variant_dir.mkdir(exist_ok=True)
        train_jsonl = variant_dir / "train.jsonl"
        test_jsonl = variant_dir / "test.jsonl"
        model_path = variant_dir / "wl_svm.joblib"
        _write_jsonl(train_jsonl, train_variant, train_labels, train_groups, "train")
        _write_jsonl(test_jsonl, test_variant, test_labels, test_groups, "test")
        model = WLGraphSVM().fit(train_variant, train_labels, group_ids=[g for g in train_groups if g is not None])
        model.save(model_path)
        metrics = evaluate(model_path, test_jsonl)
        metrics.update({"variant": name, "removed_findings": remove_findings, "removed_forgery": remove_forgery})
        results[name] = metrics
    (output / "metrics.json").write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    print(json.dumps(run_ablation(args.train, args.test, args.output_dir), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
