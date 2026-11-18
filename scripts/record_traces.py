"""Record benign tool-call traces for the AgentDojo user tasks, with no LLM.

Each task's ground-truth tool calls are replayed through the real suite tools,
with the clone in passthrough mode and the parser detector attached. One JSON
file per task is written, holding every call and result exactly as the detector
saw them, plus the detector's decision.

Run from the repository root:

    python scripts/record_traces.py                       # all four suites
    python scripts/record_traces.py --suite banking       # one suite
    python scripts/record_traces.py --out some/folder

Limits: benign runs only (default environment, no injected data), and one
correct path per task (a real model may call tools in a different order).
"""
from __future__ import annotations

import argparse
import datetime
import importlib
import json
import os
import subprocess
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "agentdojo" / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from pydantic import BaseModel  # noqa: E402

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop  # noqa: E402
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402

from clone.core import DetectorContext, DetectorDecision  # noqa: E402
from clone.interceptor import TrustVerificationToolsExecutor  # noqa: E402
from clone.ledger import InterceptionLedger  # noqa: E402
from pipeline.clone_parser_detector import parser_detector  # noqa: E402

BENCHMARK_VERSION = "v1"
SUITES = ("banking", "slack", "travel", "workspace")
DEFAULT_OUT = ROOT / "tests" / "fixtures" / "traces" / "benign"
TRACE_SCHEMA_VERSION = 1
_RUN_ID_KEY = "_clone_tvm_run_id"
_MAX_ITERS = 100
_HASH_SEED = "0"
FROZEN_NOW = datetime.datetime(2024, 5, 15, 12, 0, 0)
_CLOCK_MODULES = (
    "agentdojo.default_suites.v1.tools.cloud_drive_client",
    "agentdojo.default_suites.v1.tools.email_client",
)


class _FrozenDatetime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN_NOW if tz is None else FROZEN_NOW.replace(tzinfo=tz)


class _FrozenDatetimeModule:
    """Stands in for the ``datetime`` module inside a tool module: only ``now()`` changes."""

    datetime = _FrozenDatetime

    def __getattr__(self, name: str) -> Any:
        return getattr(datetime, name)


@contextmanager
def frozen_clock() -> Iterator[None]:
    """Some tools stamp new emails and files with the wall clock. Freeze it while
    recording so the same task always produces the same trace. The AgentDojo
    files are not edited; the name is swapped in memory and put back afterwards."""
    originals = {name: importlib.import_module(name).datetime for name in _CLOCK_MODULES}
    try:
        for name in _CLOCK_MODULES:
            sys.modules[name].datetime = _FrozenDatetimeModule()
        yield
    finally:
        for name, original in originals.items():
            sys.modules[name].datetime = original


class _ScriptedLLM(BasePipelineElement):
    """Stands in for the model: emits the ground-truth calls one per turn, then stops."""

    def __init__(self, calls: Sequence[FunctionCall]) -> None:
        self._calls = [
            FunctionCall(function=c.function, args=dict(c.args), id=f"call-{i}")
            for i, c in enumerate(calls, start=1)
        ]

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        call = self._calls.pop(0) if self._calls else None
        message = ChatAssistantMessage(
            role="assistant",
            tool_calls=[call] if call is not None else None,
            content=None if call is not None else [text_content_block_from_string("done")],
        )
        return query, runtime, env, [*messages, message], extra_args or {}


def to_plain(value: Any) -> Any:
    """A tool's result object as plain JSON data (models -> dicts), for storage."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_plain(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


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


def record_task(suite_name: str, task_id: str) -> dict[str, Any]:
    """Replay one user task's ground truth through the clone and return its trace."""
    suite = get_suite(BENCHMARK_VERSION, suite_name)
    task = suite.user_tasks[task_id]
    environment = task.init_environment(suite.load_and_inject_default_environment({}))
    ground_truth = task.ground_truth(environment)
    run_id = f"{suite_name}:{task_id}"

    seen: list[tuple[Any, DetectorContext, DetectorDecision, Any]] = []

    def recording_detector(payload: Any, context: DetectorContext | None = None) -> DetectorDecision:
        decision = parser_detector(payload, context)
        # Copy now: some tools return a live list from the environment (Slack channel
        # messages), and a later call in the same task appends to it. The trace must
        # hold the result as it was when the detector saw it.
        snapshot = to_plain(payload.get("args", payload) if isinstance(payload, dict) else context.raw_result)
        seen.append((payload, context, decision, snapshot))
        return decision

    executor = TrustVerificationToolsExecutor(
        recording_detector, mode="passthrough", ledger=InterceptionLedger()
    )
    llm = _ScriptedLLM(ground_truth)
    pipeline = AgentPipeline([
        SystemMessage("trace recorder"),
        InitQuery(),
        llm,
        ToolsExecutionLoop([executor, llm], max_iters=_MAX_ITERS),
    ])
    with frozen_clock():
        pipeline.query(task.PROMPT, FunctionsRuntime(suite.tools), environment, extra_args={_RUN_ID_KEY: run_id})
    parser_detector.end_run(run_id)

    # Interception ids are random; renumber them in order so the files are stable.
    stable_id = {context.interception_id: f"i-{n}" for n, (_, context, _, _) in enumerate(seen, start=1)}
    last_pre: dict[str | None, str] = {}
    events = []
    for payload, context, decision, snapshot in seen:
        event: dict[str, Any] = {
            "interception_id": stable_id[context.interception_id],
            "direction": context.direction,
            "tool_name": context.tool_name,
            "tool_call_id": context.tool_call_id,
            "impact_tier": context.matrix_entry.impact_tier,
        }
        if context.direction == "pre":
            last_pre[context.tool_call_id] = event["interception_id"]
            event["args"] = snapshot
        else:
            event["pre_interception_id"] = last_pre.get(context.tool_call_id)
            event["result_format"] = context.result_format
            event["raw_result_type"] = type(context.raw_result).__name__
            event["raw_result"] = snapshot
            event["result_text"] = payload
        event["decision"] = _decision_row(decision)
        events.append(event)

    return {
        "trace_schema_version": TRACE_SCHEMA_VERSION,
        "label": "benign",
        "source": "ground_truth_replay",
        "benchmark_version": BENCHMARK_VERSION,
        "suite": suite_name,
        "task_id": task_id,
        "run_id": run_id,
        "user_prompt": task.PROMPT,
        "frozen_now": FROZEN_NOW.isoformat(),
        "ground_truth_calls": len(ground_truth),
        "events": events,
    }


def record_all(suites: Sequence[str] = SUITES, out_dir: Path = DEFAULT_OUT) -> tuple[list[Path], list[tuple[str, str, str]]]:
    """Record every user task of the given suites. Returns (written files, failures)."""
    written: list[Path] = []
    failures: list[tuple[str, str, str]] = []
    for suite_name in suites:
        suite = get_suite(BENCHMARK_VERSION, suite_name)
        for task_id in suite.user_tasks:
            try:
                trace = record_task(suite_name, task_id)
            except Exception as error:  # one bad task must not stop the rest
                failures.append((suite_name, task_id, f"{type(error).__name__}: {error}"))
                continue
            path = out_dir / suite_name / f"{task_id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(trace, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
                            encoding="utf-8", newline="\n")
            written.append(path)
    return written, failures


def main() -> None:
    arg_parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    arg_parser.add_argument("--suite", action="append", choices=SUITES, help="suite to record (repeatable)")
    arg_parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output folder")
    args = arg_parser.parse_args()

    # Some AgentDojo tools build lists from sets (e.g. calendar participants), so their
    # order follows Python's per-process string hashing. Pin it so every recording run
    # writes the same files.
    if os.environ.get("PYTHONHASHSEED") != _HASH_SEED:
        env = dict(os.environ, PYTHONHASHSEED=_HASH_SEED)
        raise SystemExit(subprocess.run([sys.executable, *sys.argv], env=env).returncode)

    written, failures = record_all(args.suite or SUITES, args.out)
    events = blocked = 0
    for path in written:
        for event in json.loads(path.read_text(encoding="utf-8"))["events"]:
            events += 1
            blocked += not event["decision"]["allowed"]
    print(f"traces written: {len(written)}  events: {events}  would-block: {blocked}  failed: {len(failures)}")
    for suite_name, task_id, reason in failures:
        print(f"  FAILED {suite_name}/{task_id}: {reason}")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
