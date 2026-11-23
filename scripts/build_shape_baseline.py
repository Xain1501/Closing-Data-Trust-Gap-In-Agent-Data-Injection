"""Build src/parser/shape_baseline.json from the benign traces.

Usage: python scripts/build_shape_baseline.py [trace_dir ...]
Default trace dir: tests/fixtures/traces/benign. Each post-hop result is walked with
the skeleton builder (text results are one field "$"); for every string field the
largest shape seen per tool and field pattern is kept.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parser.anomaly import BASELINE_PATH, field_key, shape, update_baseline  # noqa: E402
from parser.skeleton import build_skeleton  # noqa: E402


def build(dirs: list[Path]) -> dict[str, dict[str, int]]:
    baseline: dict[str, dict[str, int]] = {}
    for folder in dirs:
        for path in sorted(folder.rglob("*.json")):
            trace = json.loads(path.read_text(encoding="utf-8"))
            for event in trace.get("events", []):
                if event.get("direction") != "post":
                    continue
                tool, raw = event.get("tool_name"), event.get("raw_result")
                if isinstance(raw, str):
                    update_baseline(baseline, field_key(tool, "$"), shape(raw))
                    continue
                sk = build_skeleton(raw)
                for leaf in sk.string_leaves:
                    update_baseline(baseline, field_key(tool, leaf.path), shape(leaf.value))
    return dict(sorted(baseline.items()))


def main() -> None:
    dirs = [Path(a) for a in sys.argv[1:]] or [ROOT / "tests/fixtures/traces/benign"]
    baseline = build(dirs)
    BASELINE_PATH.write_text(json.dumps(baseline, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(baseline)} field patterns -> {BASELINE_PATH}")


if __name__ == "__main__":
    main()
