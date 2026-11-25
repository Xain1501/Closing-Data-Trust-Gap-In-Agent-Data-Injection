"""Measure false positives on the held-out no-injection direct-goal controls."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from classifier.train import _load_graph_jsonl  # noqa: E402
from classifier.wl_svm import WLGraphSVM  # noqa: E402


def evaluate_controls(model_path: Path, dataset_path: Path) -> dict:
    graphs, labels, groups = _load_graph_jsonl(
        dataset_path,
        expected_split="test",
        require_groups=True,
        expected_unit="run",
    )
    if not graphs or set(labels) != {"benign"}:
        raise ValueError("the control dataset must contain only no-injection benign rows")
    model = WLGraphSVM.load(model_path)
    if model.training_group_ids is None:
        raise ValueError("model artifact does not record its training groups")
    overlap = model.training_group_ids & {group for group in groups if group is not None}
    if overlap:
        raise ValueError(f"training and control groups overlap: {sorted(overlap)[:5]}")

    predictions = [model.predict(graph) for graph in graphs]
    predicted_attack = sum(item.predicted_label == "attack" for item in predictions)
    rows = [
        json.loads(line)
        for line in dataset_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return {
        "evaluation_scope": "held-out no-injection direct-goal controls",
        "label_basis": "no_injection_direct_user_goal_control",
        "examples": len(labels),
        "independent_groups": len({group for group in groups if group is not None}),
        "predicted_as_attack": predicted_attack,
        "false_positive_rate": predicted_attack / len(labels),
        "specificity": 1.0 - predicted_attack / len(labels),
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "predictions": [
            {
                "case_id": row["case_id"],
                "task_id": row["task_id"],
                "predicted_label": prediction.predicted_label,
                "attack_probability": prediction.attack_probability,
            }
            for row, prediction in zip(rows, predictions)
        ],
        "limitations": [
            "Only seven text-derived runs are available.",
            "These are successful direct user-goal objectives with no injected tool data.",
            "This is a no-injection false-positive check, not an attack-recall benchmark.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        type=Path,
        default=ROOT / "out/fyp1_natural_matched_v4/wl_svm.joblib",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=ROOT / "out/direct_goal_challenge_v1/graphs.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "out/direct_goal_challenge_v1/v4_model_evaluation.json",
    )
    args = parser.parse_args()
    report = evaluate_controls(args.model, args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        key: report[key]
        for key in ("examples", "predicted_as_attack", "false_positive_rate", "specificity")
    }, indent=2))
    print(f"report: {args.output}")


if __name__ == "__main__":
    main()
