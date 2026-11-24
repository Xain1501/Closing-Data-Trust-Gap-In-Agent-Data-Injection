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


def _load_graph_jsonl(
    path: str | Path,
    *,
    expected_split: str | None = None,
    require_groups: bool = False,
) -> tuple[list[GraphSnapshot], list[str], list[str | None]]:
    graphs: list[GraphSnapshot] = []
    labels: list[str] = []
    group_ids: list[str | None] = []
    case_ids: set[str] = set()
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row: Any = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("row must be a JSON object")
                case_id = row["case_id"]
                if not isinstance(case_id, str) or not case_id or case_id in case_ids:
                    raise ValueError("case_id must be a unique non-empty string")
                label = row["label"]
                if label not in ("benign", "attack"):
                    raise ValueError("label must be 'benign' or 'attack'")
                if expected_split is not None and row.get("split") != expected_split:
                    raise ValueError(f"expected split {expected_split!r}")
                group_id = row.get("group_id")
                if require_groups and (not isinstance(group_id, str) or not group_id):
                    raise ValueError("group_id must be a non-empty string")
                if group_id is not None and (not isinstance(group_id, str) or not group_id):
                    raise ValueError("group_id must be a non-empty string when present")
                graph_data = row["graph"]
                if not isinstance(graph_data, dict):
                    raise ValueError("graph must be an object")
                graph = GraphSnapshot.from_payload(graph_data)
            except Exception as exc:
                raise ValueError(f"invalid training row at line {line_no}: {exc}") from exc
            case_ids.add(case_id)
            graphs.append(graph)
            labels.append(label)
            group_ids.append(group_id)
    if not graphs:
        raise ValueError(f"no graph examples found in {path}")
    return graphs, labels, group_ids


def load_training_jsonl(path: str | Path) -> tuple[list[GraphSnapshot], list[str]]:
    graphs, labels, _ = _load_graph_jsonl(path)
    return graphs, labels


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("training_jsonl")
    parser.add_argument("output_model")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--c", type=float, default=1.0)
    args = parser.parse_args()
    graphs, labels, group_ids = _load_graph_jsonl(
        args.training_jsonl, expected_split="train", require_groups=True
    )
    model = WLGraphSVM(iterations=args.iterations, c=args.c).fit(
        graphs, labels, group_ids=[group_id for group_id in group_ids if group_id is not None]
    )
    model.save(args.output_model)
    print(f"trained on {len(graphs)} graphs; saved classifier to {args.output_model}")


if __name__ == "__main__":
    main()
