"""Prepare a separate held-out set of successful direct AgentDojo goal traces."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "agentdojo" / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from classifier import graph_dataset  # noqa: E402
from clone.tvm import load_tool_matrix  # noqa: E402


def _prompt(trace: dict[str, Any]) -> str:
    prompt = trace.get("user_prompt")
    if isinstance(prompt, str):
        return prompt
    return next((
        graph_dataset._content_text(message.get("content", ""))
        for message in trace.get("messages", [])
        if isinstance(message, dict) and message.get("role") in ("human", "user")
    ), "")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip(".") or "unknown"


def build_challenge(source_dir: Path, output_dir: Path) -> dict[str, Any]:
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {output_dir}")
    suite_cache: dict[tuple[str, str], Any] = {}
    prepared = []
    included = []
    excluded = []
    versions = set()

    for path in sorted(source_dir.rglob("*.json")):
        original = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(original, dict):
            raise ValueError(f"{path}: trace root must be an object")
        suite_name = original.get("suite") or original.get("suite_name")
        source_task_id = original.get("user_task_id")
        version = original.get("benchmark_version")
        if not all(isinstance(value, str) and value for value in (suite_name, source_task_id, version)):
            raise ValueError(f"{path}: missing suite, task id, or benchmark version")
        versions.add(version)
        cache_key = (version, suite_name)
        if cache_key not in suite_cache:
            suite_cache[cache_key] = get_suite(version, suite_name)
        injection_task = suite_cache[cache_key].injection_tasks.get(source_task_id)
        if injection_task is None:
            raise ValueError(f"{path}: {source_task_id!r} is not a registered injection task")
        prompt = _prompt(original)
        if prompt != injection_task.GOAL:
            raise ValueError(
                f"{path}: user prompt does not exactly match the registered injection-task goal"
            )
        if original.get("injections") != {} or original.get("injection_task_id") is not None:
            raise ValueError(f"{path}: trace is not a direct-goal run with no injected data")

        calls = sum(
            len(message.get("tool_calls") or [])
            for message in original.get("messages", [])
            if isinstance(message, dict) and message.get("role") == "assistant"
        )
        if calls < 1:
            excluded.append({
                "source": path.relative_to(source_dir).as_posix(),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "reason": "no assistant tool calls",
            })
            continue

        record = dict(original)
        record.update({
            "label": "benign",
            "benchmark_family": "agentdojo",
            "suite": suite_name,
            "task_id": f"direct_goal:{source_task_id}",
            "task_group_id": (
                f"agentdojo:{suite_name}:direct_user_goal:{source_task_id}"
            ),
            "attack_family": "direct_user_goal",
            "attack_type": "direct_user_goal",
            "label_basis": "no_injection_direct_user_goal_control",
            "injection_condition": "absent",
            "collection_mode": "direct_user_goal_challenge",
            "attack_success": (
                original.get("security")
                if isinstance(original.get("security"), bool)
                else None
            ),
            "attack_success_source": (
                "AgentDojo injection-task security oracle"
                if isinstance(original.get("security"), bool)
                else None
            ),
            "user_prompt": prompt,
            "source_injection_task_id": source_task_id,
            "source_trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "source_trace_path": path.relative_to(source_dir).as_posix(),
        })
        model_name = _safe_name(str(record.get("pipeline_name") or "unknown"))
        prepared.append((model_name, source_task_id, record, calls))

    if len(versions) != 1:
        raise ValueError(f"expected exactly one AgentDojo version, found {sorted(versions)}")
    if not prepared:
        raise ValueError(f"no valid direct-goal traces found in {source_dir}")

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output_dir.name}-", dir=output_dir.parent
    ) as temporary_dir:
        staging = Path(temporary_dir)
        trace_dir = staging / "traces"
        matrix = load_tool_matrix()
        rows = []
        for model_name, source_task_id, record, calls in prepared:
            output_path = trace_dir / model_name / f"{_safe_name(source_task_id)}.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            row = graph_dataset._read_trace(output_path, "benign", matrix)
            if row is None:
                raise ValueError(
                    f"{record['source_trace_path']}: successful direct-goal trace "
                    "unexpectedly has no tool calls"
                )
            row["case_id"] = (
                f"direct-goal-challenge/{model_name}/{_safe_name(source_task_id)}"
            )
            row["split"] = "test"
            rows.append(row)
            included.append({
                "source": record["source_trace_path"],
                "source_sha256": record["source_trace_sha256"],
                "task_group_id": record["task_group_id"],
                "pipeline_name": record.get("pipeline_name"),
                "tool_calls": calls,
                "attack_success": record["attack_success"],
            })

        manifest = {
            "schema_version": 1,
            "dataset_kind": "held-out no-injection control challenge",
            "classification_unit": "run",
            "label_semantics": (
                "Labeled no-injection for the primary data-injection classifier because "
                "no injected tool data was present. Direct-goal utility/security outcomes "
                "are retained separately and are not used to assign this label."
            ),
            "benchmark_family": "agentdojo",
            "control_family": "direct_user_goal",
            "benchmark_version": next(iter(versions)),
            "text_derived": sum(bool(row["text_derived"]) for row in rows),
            "included": included,
            "excluded": excluded,
            "counts": {
                "included": len(rows),
                "excluded": len(excluded),
                "tool_calls": sum(row["tool_calls"] for row in rows),
            },
            "source_task_ids_are_injection_tasks_not_user_tasks": True,
            "no_injections_present": True,
            "do_not_mix_into_primary_injection_dataset": True,
        }
        (staging / "graphs.jsonl").write_text(
            "".join(
                json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
                for row in rows
            ),
            encoding="utf-8",
        )
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        staging.rename(output_dir)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=ROOT / "out/new_attack_runs")
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "out/direct_goal_challenge_v1"
    )
    args = parser.parse_args()
    manifest = build_challenge(args.source_dir, args.output_dir)
    print(json.dumps(manifest["counts"], indent=2))
    print(f"challenge output: {args.output_dir}")


if __name__ == "__main__":
    main()
