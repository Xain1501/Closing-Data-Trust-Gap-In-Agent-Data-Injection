"""Train/save the calibrated WL-SVM from trusted, labeled graph JSONL.

Each line format:
{"case_id":"...","label":"benign|attack","graph":{"node_labels":{"n0":"T:object"},"edges":[]}}

Example: ``python -m classifier.train graphs.jsonl model.joblib`` (run with
``src`` on ``PYTHONPATH``). Only load artifacts produced from trusted sources.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from classifier.wl_svm import GraphSnapshot, WLGraphSVM


def load_training_jsonl(path: str | Path) -> tuple[list[GraphSnapshot], list[str]]:
    graphs: list[GraphSnapshot] = []
    labels: list[str] = []
    case_ids: set[str] = set()
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row: dict[str, Any] = json.loads(line)
                case_id = row["case_id"]
                if not isinstance(case_id, str) or not case_id or case_id in case_ids:
                    raise ValueError("case_id must be a unique non-empty string")
                label = row["label"]
                if label not in ("benign", "attack"):
                    raise ValueError("label must be 'benign' or 'attack'")
                graph_data = row["graph"]
                graph = GraphSnapshot(
                    node_labels=graph_data["node_labels"],
                    edges=tuple(tuple(edge) for edge in graph_data["edges"]),
                )
            except Exception as exc:
                raise ValueError(f"invalid training row at line {line_no}: {exc}") from exc
            case_ids.add(case_id)
            graphs.append(graph)
            labels.append(label)
    return graphs, labels


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("training_jsonl")
    parser.add_argument("output_model")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--c", type=float, default=1.0)
    args = parser.parse_args()
    graphs, labels = load_training_jsonl(args.training_jsonl)
    model = WLGraphSVM(iterations=args.iterations, c=args.c).fit(graphs, labels)
    model.save(args.output_model)
    print(f"trained on {len(graphs)} graphs; saved classifier to {args.output_model}")


if __name__ == "__main__":
    main()
