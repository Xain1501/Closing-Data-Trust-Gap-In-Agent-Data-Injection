"""Build a leakage-safe validation split and produce the final prototype report."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from classifier.evaluate import evaluate
from classifier.train import _load_graph_jsonl
from classifier.wl_svm import WLGraphSVM


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write(path: Path, rows: list[dict], split: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({**row, "split": split}, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def _validation_groups(rows: list[dict]) -> set[str]:
    groups = sorted({row["group_id"] for row in rows})
    selected = {group for group in groups if int.from_bytes(hashlib.sha256(group.encode()).digest()[:4], "big") % 5 == 1}
    if not selected:
        selected = {groups[0]}
    # Keep both classes in validation.  If the deterministic selection misses a
    # class, add the first group containing that class.
    for label in ("benign", "attack"):
        if not any(row["label"] == label and row["group_id"] in selected for row in rows):
            selected.add(next(row["group_id"] for row in rows if row["label"] == label))
    return selected


def _family_counts(rows: list[dict]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("benchmark_family", "unknown")) for row in rows).items()))


def _counts_by(
    rows: list[dict], dimension: str, *, split: bool = False, include_label: bool = False
) -> dict[str, int]:
    keys = []
    for row in rows:
        value = row.get(dimension) or "unknown"
        parts = [str(row.get("split", "unspecified"))] if split else []
        parts.append(str(value))
        if include_label:
            parts.append(str(row["label"]))
        keys.append(":".join(parts))
    return dict(sorted(Counter(keys).items()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("out/fyp1_raw_object"))
    parser.add_argument("--output", type=Path, default=Path("out/fyp1_final_prototype"))
    args = parser.parse_args()
    manifest_path = args.dataset / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_train = _read(args.dataset / "graphs_train.jsonl")
    source_test = _read(args.dataset / "graphs_test.jsonl")
    all_source_rows = source_train + source_test
    if not all_source_rows or any(
        row.get("classification_unit") != "run" for row in all_source_rows
    ):
        raise ValueError(
            "dataset is not explicitly run-level; rebuild it with classifier.graph_dataset"
        )
    validation_groups = _validation_groups(source_train)
    validation = [row for row in source_train if row["group_id"] in validation_groups]
    train = [row for row in source_train if row["group_id"] not in validation_groups]
    if {row["label"] for row in train} != {"benign", "attack"} or {row["label"] for row in validation} != {"benign", "attack"}:
        raise RuntimeError("validation split does not contain both labels")
    _write(args.output / "graphs_train.jsonl", train, "train")
    _write(args.output / "graphs_validation.jsonl", validation, "test")
    _write(args.output / "graphs_test.jsonl", source_test, "test")
    graphs, labels, groups = _load_graph_jsonl(args.output / "graphs_train.jsonl", expected_split="train", require_groups=True)
    model_path = args.output / "wl_svm.joblib"
    WLGraphSVM().fit(graphs, labels, group_ids=[group for group in groups if group is not None]).save(model_path)
    validation_metrics = evaluate(model_path, args.output / "graphs_validation.jsonl")
    test_metrics = evaluate(model_path, args.output / "graphs_test.jsonl")
    all_rows = train + validation + source_test
    for row in train:
        row["split"] = "train"
    for row in validation:
        row["split"] = "validation"
    for row in source_test:
        row["split"] = "test"
    all_rows = train + validation + source_test
    sources_by_label = {
        label: sorted({
            str(row.get("source") or "unknown")
            for row in all_rows if row["label"] == label
        })
        for label in ("benign", "attack")
    }
    adi_present = any(row.get("benchmark_family") == "adi" for row in all_rows)
    limitations = []
    if not adi_present:
        limitations.extend([
            "No separately labeled ADI benchmark family is present in the local traces.",
            "Unseen-family performance must be reported separately after adding a genuine ADI benchmark corpus.",
        ])
    if set(sources_by_label["benign"]) != set(sources_by_label["attack"]):
        limitations.append(
            "Benign and attack traces use different collection sources; reported metrics "
            "may reflect collection-process differences as well as behavior."
        )
    report = {
        "schema_version": 2,
        "classification_unit": "run",
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "dataset": str(args.dataset),
        "dataset_manifest": {
            "counts": manifest.get("counts", {}),
            "holdout_benchmark_families": manifest.get("holdout_benchmark_families", []),
            "holdout_attack_families": manifest.get("holdout_attack_families", []),
            "holdout_sources": manifest.get("holdout_sources", []),
            "requires_matched_pairs": manifest.get("requires_matched_pairs", False),
        },
        "provenance": {
            "total": len(all_rows),
            "text_derived": sum(bool(row.get("text_derived")) for row in all_rows),
            "real_object": sum(not bool(row.get("text_derived")) for row in all_rows),
            "benchmark_families": _family_counts(all_rows),
            "attack_families": dict(sorted(Counter(
                str(row["attack_family"]) for row in all_rows if row.get("attack_family")
            ).items())),
            "sources_by_label": sources_by_label,
            "collection_modes_by_label": {
                label: dict(sorted(Counter(
                    str(row.get("collection_mode") or "unknown")
                    for row in all_rows if row["label"] == label
                ).items()))
                for label in ("benign", "attack")
            },
            "traces_by_benchmark_split_label": _counts_by(
                all_rows, "benchmark_family", split=True, include_label=True
            ),
            "labels_by_attack_family": _counts_by(
                [row for row in all_rows if row["label"] == "attack"],
                "attack_family",
            ),
            "traces_by_label_basis": _counts_by(
                all_rows, "label_basis", include_label=True
            ),
            "adi_present": adi_present,
        },
        "splits": {
            "train": {"rows": len(train), "groups": len({row["group_id"] for row in train})},
            "validation": {"rows": len(validation), "groups": len(validation_groups)},
            "test": {"rows": len(source_test), "groups": len({row["group_id"] for row in source_test})},
        },
        "validation": validation_metrics,
        "test": test_metrics,
        "limitations": limitations,
    }
    (args.output / "FINAL_REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"validation": validation_metrics, "test": test_metrics, "provenance": report["provenance"], "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
