"""Replay recorded AgentDojo attack calls through the clone executor.

The benchmark JSON files contain assistant tool calls and formatted tool
messages.  Feeding those messages directly to the dataset builder loses the
real return object.  This script re-executes the calls against the same
injected environment and records both the raw object and its formatted text at
the clone interception point.

Run from the repository root::

    python scripts/record_attack_traces.py --input runs/baseline_openai_gpt-oss-120b
    python scripts/record_attack_traces.py --input runs/baseline_openai_gpt-oss-120b runs/baseline_llama-3.3-70b-versatile
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "agentdojo" / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop  # noqa: E402
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from clone.core import DetectorContext, DetectorDecision  # noqa: E402
from clone.interceptor import TrustVerificationToolsExecutor  # noqa: E402
from clone.ledger import InterceptionLedger  # noqa: E402
from pipeline.clone_parser_detector import parser_detector  # noqa: E402

_RUN_ID_KEY = "_clone_tvm_run_id"
_HASH_SEED = "0"
_BENCHMARK_VERSION = "v1"


class _ScriptedLLM(BasePipelineElement):
    def __init__(self, batches: list[list[FunctionCall]]) -> None:
        self._batches: list[list[FunctionCall]] = []
        call_index = 0
        for batch in batches:
            replay_batch: list[FunctionCall] = []
            for call in batch:
                call_index += 1
                replay_batch.append(FunctionCall(
                    function=call.function, args=dict(call.args), id=f"replay-{call_index}",
                ))
            self._batches.append(replay_batch)

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        batch = self._batches.pop(0) if self._batches else None
        message = ChatAssistantMessage(
            role="assistant",
            tool_calls=batch,
            content=None if batch else [text_content_block_from_string("done")],
        )
        return query, runtime, env, [*messages, message], extra_args or {}


def to_plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_plain(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _calls(trace: dict[str, Any]) -> list[list[FunctionCall]]:
    batches: list[list[FunctionCall]] = []
    for message in trace.get("messages", []):
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        batch: list[FunctionCall] = []
        for raw in message.get("tool_calls") or []:
            if not isinstance(raw, dict):
                raise ValueError("assistant tool call must be an object")
            function = raw.get("name")
            args = raw.get("args")
            if isinstance(raw.get("function"), dict):
                function = function or raw["function"].get("name")
                args = args if args is not None else raw["function"].get("arguments")
            if isinstance(args, str):
                args = json.loads(args)
            if not isinstance(function, str) or not function or not isinstance(args, dict):
                raise ValueError("assistant tool call has invalid function or arguments")
            batch.append(FunctionCall(
                function=function, args=args, id=f"source-{len(batches)}-{len(batch)}",
            ))
        if batch:
            batches.append(batch)
    return batches


def _call_sequence_sha256(batches: list[list[FunctionCall]]) -> str:
    sequence = [
        {"tool_name": call.function, "args": to_plain(call.args)}
        for batch in batches
        for call in batch
    ]
    payload = json.dumps(sequence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _decision_row(decision: DetectorDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "label": decision.label,
        "score": decision.score,
        "forgery_found": decision.forgery_found,
        "schema_ok": decision.schema_ok,
        "parse_health": decision.parse_health,
        "decided_by": decision.decided_by,
    }


def replay(path: Path, *, include_injections: bool = True) -> dict[str, Any]:
    trace = json.loads(path.read_text(encoding="utf-8"))
    suite_name = trace.get("suite") or trace.get("suite_name")
    task_id = trace.get("task_id") or trace.get("user_task_id")
    if not isinstance(suite_name, str) or not isinstance(task_id, str):
        raise ValueError("trace is missing suite/task id")
    injections = trace.get("injections")
    if not isinstance(injections, dict):
        raise ValueError("attack trace is missing its injection mapping")
    benchmark_version = trace.get("benchmark_version", _BENCHMARK_VERSION)
    if not isinstance(benchmark_version, str) or not benchmark_version:
        raise ValueError("trace has an invalid benchmark version")
    suite = get_suite(benchmark_version, suite_name)
    task = suite.user_tasks[task_id]
    environment_injections = injections if include_injections else {}
    environment = task.init_environment(
        suite.load_and_inject_default_environment(environment_injections)
    )
    calls = _calls(trace)
    seen: list[tuple[Any, DetectorContext, DetectorDecision, Any]] = []

    def detector(payload: Any, context: DetectorContext | None = None) -> DetectorDecision:
        decision = parser_detector(payload, context)
        raw = context.raw_result if context is not None else payload
        seen.append((payload, context, decision, to_plain(raw)))
        return decision

    run_kind = "injected" if include_injections else "clean-counterfactual"
    run_id = f"replayed:{run_kind}:{path.stem}:{suite_name}:{task_id}"
    executor = TrustVerificationToolsExecutor(detector, mode="passthrough", ledger=InterceptionLedger())
    # ToolsExecutionLoop must use the same scripted model instance throughout;
    # otherwise only the first call would be emitted.
    model = _ScriptedLLM(calls)
    pipeline = AgentPipeline([
        SystemMessage("attack trace recorder"), InitQuery(), model,
        ToolsExecutionLoop(
            [executor, model],
            max_iters=max(100, sum(map(len, calls)) * 2 + 2),
        ),
    ])
    try:
        pipeline.query(trace.get("user_prompt") or next(
            (m.get("content", "") for m in trace.get("messages", [])
             if isinstance(m, dict) and m.get("role") == "human"), ""),
            FunctionsRuntime(suite.tools), environment, extra_args={_RUN_ID_KEY: run_id})
    finally:
        executor.end_run(run_id)
        parser_detector.end_run(run_id)

    stable = {ctx.interception_id: f"i-{n}" for n, (_, ctx, _, _) in enumerate(seen, 1) if ctx}
    last_pre: dict[str | None, str] = {}
    events = []
    for payload, context, decision, raw in seen:
        if context is None:
            continue
        event: dict[str, Any] = {
            "interception_id": stable[context.interception_id],
            "direction": context.direction,
            "tool_name": context.tool_name,
            "tool_call_id": context.tool_call_id,
            "batch_id": context.batch_id,
            "impact_tier": context.matrix_entry.impact_tier,
        }
        if context.direction == "pre":
            last_pre[context.tool_call_id] = event["interception_id"]
            event["args"] = to_plain(payload.get("args", payload) if isinstance(payload, dict) else payload)
        else:
            event.update({
                "pre_interception_id": last_pre.get(context.tool_call_id),
                "result_format": context.result_format,
                "raw_result_type": type(context.raw_result).__name__,
                "raw_result": raw,
                "result_text": payload,
                "text_derived": False,
            })
        event["decision"] = _decision_row(decision)
        events.append(event)
    attack_type = trace.get("attack_type")
    pipeline_name = trace.get("pipeline_name") or trace.get("source") or "unknown"
    matched_pair_id = hashlib.sha256(
        f"{pipeline_name}:{suite_name}:{task_id}:{attack_type}:{path.name}".encode("utf-8")
    ).hexdigest()
    return {
        "trace_schema_version": 1,
        "label": "attack" if include_injections else "benign",
        "source": "clone_executor_replay",
        "benchmark_family": "agentdojo",
        "attack_family": attack_type if include_injections else None,
        "benchmark_version": benchmark_version,
        "pipeline_name": pipeline_name,
        "collection_mode": (
            "injected_attack_replay" if include_injections
            else "matched_clean_counterfactual"
        ),
        "injection_condition": "present" if include_injections else "absent",
        "label_basis": (
            "injection_present" if include_injections
            else "injection_absent_counterfactual"
        ),
        "suite": suite_name,
        "task_id": task_id,
        "task_group_id": f"agentdojo:{suite_name}:{task_id}",
        "matched_pair_id": matched_pair_id,
        "call_sequence_sha256": _call_sequence_sha256(calls),
        "injection_task_id": trace.get("injection_task_id") if include_injections else None,
        "attack_type": attack_type if include_injections else None,
        "matched_attack_type": attack_type,
        "attack_success": (
            trace.get("security")
            if include_injections and isinstance(trace.get("security"), bool)
            else None
        ),
        "attack_success_source": (
            "source_agentdojo_trace" if include_injections
            and isinstance(trace.get("security"), bool) else None
        ),
        "run_id": run_id,
        "injections": environment_injections,
        "user_prompt": trace.get("user_prompt") or next(
            (m.get("content", "") for m in trace.get("messages", [])
             if isinstance(m, dict) and m.get("role") == "human"), ""),
        "events": events,
    }


def _safe_path_component(value: Any) -> str:
    component = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip(".")
    return component or "unknown"


def _output_path(output: Path, row: dict[str, Any], filename: str) -> Path:
    return (
        output
        / _safe_path_component(row.get("pipeline_name"))
        / _safe_path_component(row.get("suite"))
        / _safe_path_component(row.get("task_id"))
        / _safe_path_component(row.get("attack_type") or row.get("matched_attack_type"))
        / filename
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", nargs="+", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "out" / "attack_traces_raw")
    parser.add_argument(
        "--paired-clean-output", type=Path,
        help=(
            "also replay each recorded call sequence in the clean environment and "
            "write matched benign counterfactual traces here"
        ),
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="replace existing trace files at the output path",
    )
    args = parser.parse_args()
    if os.environ.get("PYTHONHASHSEED") != _HASH_SEED:
        env = dict(os.environ, PYTHONHASHSEED=_HASH_SEED)
        raise SystemExit(subprocess.run([sys.executable, *sys.argv], env=env).returncode)
    files = [p for root in args.input for p in (sorted(root.rglob("*.json")) if root.is_dir() else [root])]
    failures = []
    written = 0
    paired_clean_written = 0
    for path in files:
        try:
            row = replay(path)
            out = _output_path(args.output, row, path.name)
            if out.exists() and not args.overwrite:
                raise FileExistsError(f"output already exists (pass --overwrite to replace): {out}")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            written += 1
            if args.paired_clean_output is not None:
                clean_row = replay(path, include_injections=False)
                clean_out = _output_path(args.paired_clean_output, clean_row, path.name)
                if clean_out.exists() and not args.overwrite:
                    raise FileExistsError(
                        f"clean counterfactual already exists (pass --overwrite to replace): "
                        f"{clean_out}"
                    )
                clean_out.parent.mkdir(parents=True, exist_ok=True)
                clean_out.write_text(
                    json.dumps(clean_row, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                paired_clean_written += 1
        except Exception as exc:
            failures.append(f"{path}: {type(exc).__name__}: {exc}")
    print(
        f"raw attack traces written: {written}; paired clean traces written: "
        f"{paired_clean_written}; failed: {len(failures)}"
    )
    for failure in failures:
        print(f"FAILED {failure}")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
