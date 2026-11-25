"""Reject invalid decision-level evaluation of a run-level WL-SVM."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def evaluate_per_decision(model_path: str | Path, test_path: str | Path) -> dict[str, object]:
    raise ValueError(
        "per-decision evaluation is unavailable: the WL-SVM is trained on complete "
        "run graphs, and trace-level labels are not valid per-decision ground truth"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model")
    parser.add_argument("test_jsonl")
    args = parser.parse_args()
    print(json.dumps(evaluate_per_decision(args.model, args.test_jsonl), indent=2))


if __name__ == "__main__":
    main()
