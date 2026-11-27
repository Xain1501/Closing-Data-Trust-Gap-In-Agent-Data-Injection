"""Evaluate one attack family as a strict run-grouped zero-shot holdout."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from classifier.evaluate import evaluate  # noqa: E402
from classifier.train import _load_graph_jsonl  # noqa: E402
from classifier.wl_svm import WLGraphSVM  # noqa: E402


def _read_rows(path: Path, expected_split: str) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: row must be a JSON object")
            if row.get("split") != expected_split:
                raise ValueError(
                    f"{path}:{line_no}: expected split {expected_split!r}"
                )
            if row.get("classification_unit") != "run":
                raise ValueError(
                    f"{path}:{line_no}: expected classification_unit 'run'"
                )
            rows.append(row)
    if not rows:
        raise ValueError(f"no rows found in {path}")
    return rows


def prepare_family_holdout(
    train_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
    attack_family: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    """Move every run group containing the target family wholly into test."""
    train_groups = {row.get("group_id") for row in train_rows}
    test_groups = {row.get("group_id") for row in test_rows}
    if None in train_groups or None in test_groups:
        raise ValueError("all rows must have group_id values")
    if any(not isinstance(group, str) or not group for group in train_groups | test_groups):
        raise ValueError("all group_id values must be non-empty strings")
    overlap = train_groups & test_groups
    if overlap:
        raise ValueError(f"input train/test groups overlap: {sorted(overlap)[:5]}")

    all_rows = train_rows + test_rows
    heldout_groups = {
        row["group_id"]
        for row in all_rows
        if row.get("label") == "attack" and row.get("attack_family") == attack_family
    }
    if not heldout_groups:
        raise ValueError(f"attack family {attack_family!r} is absent from the dataset")

    adjusted_train = [
        {**row, "split": "train"}
        for row in train_rows
        if row["group_id"] not in heldout_groups
    ]
    adjusted_test = [
        {**row, "split": "test"}
        for row in all_rows
        if row["group_id"] in test_groups or row["group_id"] in heldout_groups
    ]
    if any(
        row.get("attack_family") == attack_family and row.get("label") == "attack"
        for row in adjusted_train
    ):
        raise RuntimeError("held-out attack family leaked into adjusted training rows")
    if {row["label"] for row in adjusted_train} != {"benign", "attack"}:
        raise ValueError("training split must retain both benign and attack examples")
    if {row["label"] for row in adjusted_test} != {"benign", "attack"}:
        raise ValueError(
            "test split must contain both labels; hold out matched benign runs "
            "in the same task groups as the attack family"
        )
    return adjusted_train, adjusted_test, heldout_groups


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def evaluate_unseen_family(
    dataset_dir: Path,
    output_dir: Path,
    attack_family: str,
) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {output_dir}")
    train_rows = _read_rows(dataset_dir / "graphs_train.jsonl", "train")
    test_rows = _read_rows(dataset_dir / "graphs_test.jsonl", "test")
    train_rows, test_rows, heldout_groups = prepare_family_holdout(
        train_rows, test_rows, attack_family
    )

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output_dir.name}-", dir=output_dir.parent
    ) as temporary_dir:
        staging = Path(temporary_dir)
        train_path = staging / "graphs_train.jsonl"
        test_path = staging / "graphs_test.jsonl"
        model_path = staging / "wl_svm.joblib"
        _write_rows(train_path, train_rows)
        _write_rows(test_path, test_rows)
        graphs, labels, groups = _load_graph_jsonl(
            train_path,
            expected_split="train",
            require_groups=True,
            expected_unit="run",
        )
        model = WLGraphSVM().fit(
            graphs,
            labels,
            group_ids=[group for group in groups if group is not None],
        )
        model.save(model_path)
        metrics = evaluate(model_path, test_path)

        heldout_attacks = [
            row for row in test_rows
            if row.get("label") == "attack"
            and row.get("attack_family") == attack_family
        ]
        family_metrics = (
            metrics.get("subgroup_metrics", {})
            .get("attack_family", {})
            .get(attack_family)
        )
        test_graphs, _, _ = _load_graph_jsonl(
            test_path,
            expected_split="test",
            require_groups=True,
            expected_unit="run",
        )
        heldout_group_predictions = [
            (row, model.predict(graph))
            for graph, row in zip(test_graphs, test_rows)
            if row.get("group_id") in heldout_groups
        ]
        heldout_attack_predictions = [
            prediction for row, prediction in heldout_group_predictions
            if row.get("label") == "attack"
            and row.get("attack_family") == attack_family
        ]
        heldout_benign_predictions = [
            prediction for row, prediction in heldout_group_predictions
            if row.get("label") == "benign"
        ]
        report: dict[str, Any] = {
            "evaluation_mode": "zero_shot_attack_family_holdout",
            "attack_family": attack_family,
            "heldout_attack_examples": len(heldout_attacks),
            "heldout_task_groups": len(heldout_groups),
            "heldout_group_examples": sum(
                row["group_id"] in heldout_groups for row in test_rows
            ),
            "train_examples": len(train_rows),
            "test_examples": len(test_rows),
            "training_group_leakage": False,
            "heldout_family_metrics": family_metrics,
            "heldout_family_ood_flagged_examples": sum(
                prediction.out_of_distribution
                for prediction in heldout_attack_predictions
            ),
            "heldout_family_svm_attack_flagged_examples": sum(
                prediction.svm_attack_flag
                for prediction in heldout_attack_predictions
            ),
            "heldout_group_benign_examples": len(heldout_benign_predictions),
            "heldout_group_benign_ood_flagged_examples": sum(
                prediction.out_of_distribution
                for prediction in heldout_benign_predictions
            ),
            "heldout_group_benign_svm_attack_flagged_examples": sum(
                prediction.svm_attack_flag
                for prediction in heldout_benign_predictions
            ),
            "metrics": metrics,
            "interpretation": (
                "Zero-shot family evaluation only. A small number of held-out "
                "examples or task groups cannot establish generalization."
            ),
        }
        (staging / "FINAL_REPORT.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        staging.rename(output_dir)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--attack-family", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate_unseen_family(
        args.dataset_dir, args.output_dir, args.attack_family
    )
    print(json.dumps({
        "attack_family": report["attack_family"],
        "heldout_attack_examples": report["heldout_attack_examples"],
        "heldout_task_groups": report["heldout_task_groups"],
        "heldout_attack_recall": report["heldout_family_metrics"]["attack_recall"],
        "heldout_attack_ood_flagged": report["heldout_family_ood_flagged_examples"],
        "heldout_attack_svm_attack_flagged": report["heldout_family_svm_attack_flagged_examples"],
        "heldout_benign_examples": report["heldout_group_benign_examples"],
        "heldout_benign_ood_flagged": (
            report["heldout_group_benign_ood_flagged_examples"]
        ),
        "heldout_benign_svm_attack_flagged": (
            report["heldout_group_benign_svm_attack_flagged_examples"]
        ),
    }, indent=2))
    print(f"report: {args.output_dir / 'FINAL_REPORT.json'}")


if __name__ == "__main__":
    main()
