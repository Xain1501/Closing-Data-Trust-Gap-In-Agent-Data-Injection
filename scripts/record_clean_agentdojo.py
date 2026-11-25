"""Record natural, non-injected AgentDojo runs through the clone executor."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "agentdojo" / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from dotenv import load_dotenv  # noqa: E402

from agentdojo.agent_pipeline.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    get_llm,
    load_system_message,
)
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from clone.core import DetectorContext, DetectorDecision  # noqa: E402
from clone.interceptor import TrustVerificationToolsExecutor  # noqa: E402
from clone.ledger import InterceptionLedger  # noqa: E402
from pipeline.clone_parser_detector import parser_detector  # noqa: E402

_RUN_ID_KEY = "_clone_tvm_run_id"
_MODELS = ("openai/gpt-oss-120b", "llama-3.3-70b-versatile")


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip(".") or "unknown"


def _clean_trace_row(
    suite_name: str,
    task_id: str,
    *,
    benchmark_version: str,
    model_name: str,
    run_id: str,
    user_prompt: str,
    events: list[dict[str, Any]],
    sequence: list[dict[str, Any]],
) -> dict[str, Any]:
    sequence_json = json.dumps(
        sequence, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    pipeline_name = f"baseline_{model_name.replace('/', '_')}"
    return {
        "trace_schema_version": 1,
        "label": "benign",
        "source": "natural_clean_agent_run",
        "benchmark_family": "agentdojo",
        "benchmark_version": benchmark_version,
        "pipeline_name": pipeline_name,
        "collection_mode": "natural_clean_agent_run",
        "injection_condition": "absent",
        "label_basis": "no_injection_natural_model_run",
        "suite": suite_name,
        "task_id": task_id,
        "task_group_id": f"agentdojo:{suite_name}:{task_id}",
        "call_sequence_sha256": hashlib.sha256(sequence_json.encode("utf-8")).hexdigest(),
        "run_id": run_id,
        "injections": {},
        "user_prompt": user_prompt,
        "events": events,
    }


def _record_task(
    suite_name: str,
    task_id: str,
    *,
    benchmark_version: str,
    model_name: str,
    max_iterations: int,
) -> dict[str, Any]:
    suite = get_suite(benchmark_version, suite_name)
    if task_id not in suite.user_tasks:
        raise ValueError(f"{suite_name}:{task_id} is not a user task in {benchmark_version}")
    task = suite.user_tasks[task_id]
    environment = task.init_environment(suite.load_and_inject_default_environment({}))
    run_id = f"natural-clean:{uuid4()}"
    seen: list[tuple[Any, DetectorContext | None, DetectorDecision, Any]] = []

    def detector(payload: Any, context: DetectorContext | None = None) -> DetectorDecision:
        decision = parser_detector(payload, context)
        raw_result = context.raw_result if context is not None else payload
        seen.append((payload, context, decision, _plain(raw_result)))
        return decision

    executor = TrustVerificationToolsExecutor(
        detector,
        mode="passthrough",
        ledger=InterceptionLedger(),
    )
    model = get_llm("groq", model_name, None, "tool")
    pipeline = AgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        model,
        ToolsExecutionLoop(
            [executor, model],
            max_iters=max_iterations,
        ),
    ])
    try:
        pipeline.query(
            task.PROMPT,
            FunctionsRuntime(suite.tools),
            environment,
            extra_args={_RUN_ID_KEY: run_id},
        )
    finally:
        executor.end_run(run_id)
        parser_detector.end_run(run_id)

    stable_ids = {
        context.interception_id: f"i-{index}"
        for index, (_, context, _, _) in enumerate(seen, 1)
        if context is not None
    }
    last_pre: dict[str | None, str] = {}
    events: list[dict[str, Any]] = []
    sequence: list[dict[str, Any]] = []
    for payload, context, decision, raw_result in seen:
        if context is None:
            continue
        event: dict[str, Any] = {
            "interception_id": stable_ids[context.interception_id],
            "direction": context.direction,
            "tool_name": context.tool_name,
            "tool_call_id": context.tool_call_id,
            "batch_id": context.batch_id,
            "impact_tier": context.matrix_entry.impact_tier,
            "decision": {
                "allowed": decision.allowed,
                "label": decision.label,
                "score": decision.score,
                "forgery_found": decision.forgery_found,
                "schema_ok": decision.schema_ok,
                "parse_health": decision.parse_health,
                "decided_by": decision.decided_by,
            },
        }
        if context.direction == "pre":
            last_pre[context.tool_call_id] = event["interception_id"]
            args = payload.get("args", payload) if isinstance(payload, dict) else payload
            event["args"] = _plain(args)
            sequence.append({
                "tool_name": context.tool_name,
                "args": _plain(args),
            })
        else:
            event.update({
                "pre_interception_id": last_pre.get(context.tool_call_id),
                "result_format": context.result_format,
                "raw_result_type": type(context.raw_result).__name__,
                "raw_result": raw_result,
                "result_text": payload,
                "text_derived": False,
            })
        events.append(event)

    return _clean_trace_row(
        suite_name,
        task_id,
        benchmark_version=benchmark_version,
        model_name=model_name,
        run_id=run_id,
        user_prompt=task.PROMPT,
        events=events,
        sequence=sequence,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--task",
        action="append",
        required=True,
        help="AgentDojo suite and user task as suite:user_task_N (repeatable)",
    )
    parser.add_argument("--model", choices=_MODELS, default="openai/gpt-oss-120b")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--max-iterations", type=int, default=8)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "runs" / "natural_benign_gpt_oss_120b_v1_2_2",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.max_iterations <= 16:
        parser.error("--max-iterations must be between 1 and 16")

    load_dotenv(ROOT / ".env", override=False)
    if not os.getenv("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY is missing from the environment/.env")

    requested: list[tuple[str, str]] = []
    for value in args.task:
        suite_name, separator, task_id = value.partition(":")
        if not separator or not suite_name or not task_id:
            parser.error(f"invalid --task {value!r}; expected suite:user_task_N")
        requested.append((suite_name, task_id))
    if len(set(requested)) != len(requested):
        parser.error("--task values must be unique")

    paths = [
        args.output_dir
        / _safe_component(args.model.replace("/", "_"))
        / _safe_component(suite_name)
        / f"{_safe_component(task_id)}.json"
        for suite_name, task_id in requested
    ]
    existing = [path for path in paths if path.exists()]
    if existing and not args.overwrite:
        raise FileExistsError(
            "clean trace output already exists (pass --overwrite): "
            + ", ".join(str(path) for path in existing)
        )

    for (suite_name, task_id), path in zip(requested, paths):
        row = _record_task(
            suite_name,
            task_id,
            benchmark_version=args.benchmark_version,
            model_name=args.model,
            max_iterations=args.max_iterations,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(row, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"{suite_name}:{task_id}: {len(row['events']) // 2} tool calls -> {path}")


if __name__ == "__main__":
    main()
