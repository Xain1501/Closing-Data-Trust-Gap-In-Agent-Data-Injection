"""Collect budget-capped important-instructions traces from AgentDojo."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT / "agentdojo" / "src", ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import openai  # noqa: E402
from openai._types import NOT_GIVEN  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

from agentdojo.agent_pipeline.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    load_system_message,
)
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.llms.openai_llm import (  # noqa: E402
    OpenAILLM,
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop  # noqa: E402
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatMessage  # noqa: E402

from clone.core import DetectorContext, DetectorDecision  # noqa: E402
from clone.interceptor import TrustVerificationToolsExecutor  # noqa: E402
from clone.ledger import InterceptionLedger  # noqa: E402
from pipeline.clone_parser_detector import parser_detector  # noqa: E402
from record_attack_traces import _output_path, replay, to_plain  # noqa: E402

MODEL = "openai/gpt-oss-120b"
BENCHMARK_VERSION = "v1.2.2"
SUITES = ("workspace", "travel", "slack", "banking")
CAP_USD = 2.0
INPUT_USD_PER_MILLION = 0.15
OUTPUT_USD_PER_MILLION = 0.60
MAX_INPUT_BYTES = 24_000
INPUT_FRAMING_RESERVE_TOKENS = 4_096
MAX_OUTPUT_TOKENS = 1_024
MAX_GROUPS = 10
MAX_RATE_LIMIT_RETRIES = 4
_RUN_ID_KEY = "_clone_tvm_run_id"


class CollectionStopped(RuntimeError):
    """Collection cannot safely continue within its configured limits."""


class BudgetLedger:
    def __init__(
        self,
        path: Path,
        cap_usd: float = CAP_USD,
        *,
        resume: bool = False,
    ) -> None:
        self.path = path
        self.cap_usd = cap_usd
        self.actual_usd = 0.0
        self.pending_usd = 0.0
        self.uncertain_usd = 0.0
        self.requests = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        if resume:
            if not path.is_file():
                raise FileNotFoundError(f"cannot resume without budget ledger: {path}")
            state = json.loads(path.read_text(encoding="utf-8"))
            if state.get("model") != MODEL or state.get("cap_usd") != cap_usd:
                raise ValueError("existing budget ledger model/cap does not match this run")
            self.actual_usd = float(state["actual_usd"])
            self.pending_usd = float(state["pending_reserved_usd"])
            self.uncertain_usd = float(state["uncertain_reserved_usd"])
            self.requests = int(state["request_count"])
            self.prompt_tokens = int(state["prompt_tokens"])
            self.completion_tokens = int(state["completion_tokens"])
            if self.pending_usd != 0:
                raise ValueError("cannot resume while a request reservation is pending")
            self._save()
        else:
            self._save()

    @staticmethod
    def estimate_max_cost(input_bytes: int) -> float:
        input_tokens = input_bytes + INPUT_FRAMING_RESERVE_TOKENS
        return (
            input_tokens * INPUT_USD_PER_MILLION
            + MAX_OUTPUT_TOKENS * OUTPUT_USD_PER_MILLION
        ) / 1_000_000

    def reserve(self, input_bytes: int) -> float:
        if input_bytes > MAX_INPUT_BYTES:
            raise CollectionStopped(
                f"request payload is {input_bytes} bytes; limit is {MAX_INPUT_BYTES}"
            )
        reservation = self.estimate_max_cost(input_bytes)
        exposure = self.actual_usd + self.pending_usd + self.uncertain_usd
        if exposure + reservation > self.cap_usd:
            raise CollectionStopped(
                f"request would exceed the ${self.cap_usd:.2f} reserved-spend cap"
            )
        self.pending_usd += reservation
        self.requests += 1
        self._save()
        return reservation

    def settle(
        self,
        reservation: float,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> None:
        actual = (
            prompt_tokens * INPUT_USD_PER_MILLION
            + completion_tokens * OUTPUT_USD_PER_MILLION
        ) / 1_000_000
        self.pending_usd -= reservation
        self.actual_usd += actual
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self._save()
        if self.actual_usd + self.pending_usd + self.uncertain_usd > self.cap_usd:
            raise CollectionStopped("reported provider usage exceeded the reserved-spend cap")

    def mark_uncertain(self, reservation: float) -> None:
        self.pending_usd -= reservation
        self.uncertain_usd += reservation
        self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "model": MODEL,
            "cap_usd": self.cap_usd,
            "actual_usd": round(self.actual_usd, 10),
            "pending_reserved_usd": round(self.pending_usd, 10),
            "uncertain_reserved_usd": round(self.uncertain_usd, 10),
            "maximum_exposure_usd": round(
                self.actual_usd + self.pending_usd + self.uncertain_usd, 10
            ),
            "request_count": self.requests,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "pricing_source": "https://console.groq.com/docs/models",
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)


class BudgetedGroqLLM(OpenAILLM):
    def __init__(
        self,
        client: openai.OpenAI,
        model: str,
        ledger: BudgetLedger,
    ) -> None:
        super().__init__(client, model)
        self.ledger = ledger
        self.last_messages: list[dict[str, Any]] = []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        openai_messages = [_message_to_openai(message, self.model) for message in messages]
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        request_payload = json.dumps(
            {"messages": openai_messages, "tools": openai_tools},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        completion = None
        for attempt in range(MAX_RATE_LIMIT_RETRIES + 1):
            reservation = self.ledger.reserve(len(request_payload))
            try:
                completion = self.client.chat.completions.create(
                    model=self.model,
                    messages=openai_messages,
                    tools=openai_tools or NOT_GIVEN,
                    tool_choice="auto" if openai_tools else NOT_GIVEN,
                    temperature=0,
                    max_completion_tokens=MAX_OUTPUT_TOKENS,
                )
                break
            except openai.RateLimitError as exc:
                self.ledger.mark_uncertain(reservation)
                delay = _rate_limit_delay(exc)
                if attempt < MAX_RATE_LIMIT_RETRIES and delay is not None:
                    time.sleep(delay + 3)
                    continue
                raise
            except Exception:
                self.ledger.mark_uncertain(reservation)
                raise
        if completion is None:
            raise CollectionStopped("request stopped after the bounded rate-limit retry")

        usage = completion.usage
        if usage is None:
            self.ledger.mark_uncertain(reservation)
            raise CollectionStopped("provider response omitted usage; stopping to preserve the cap")
        self.ledger.settle(
            reservation,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
        )
        output = _openai_to_assistant_message(completion.choices[0].message)
        updated_messages = [*messages, output]
        self.last_messages = [_serialize_message(message) for message in updated_messages]
        return query, runtime, env, updated_messages, extra_args or {}


def _rate_limit_delay(error: openai.RateLimitError) -> float | None:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", {}) or {}
    for key in ("retry-after", "retry-after-ms"):
        value = headers.get(key)
        if value is not None:
            try:
                delay = float(value)
            except ValueError:
                continue
            if key == "retry-after-ms":
                delay /= 1_000
            if 0 <= delay <= 60:
                return delay
    match = re.search(r"try again in ([0-9]+(?:\.[0-9]+)?)s", str(error), re.IGNORECASE)
    if match is None:
        return None
    delay = float(match.group(1))
    return delay if 0 <= delay <= 60 else None


class RunContextAgentPipeline(AgentPipeline):
    def __init__(self, elements, run_id: str) -> None:
        super().__init__(elements)
        self.run_id = run_id

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        run_args = dict(extra_args or {})
        run_args[_RUN_ID_KEY] = self.run_id
        return super().query(query, runtime, env, messages, run_args)


def _serialize_message(message: ChatMessage) -> dict[str, Any]:
    serialized: dict[str, Any] = {"role": message["role"]}
    content = message.get("content")
    if content is not None:
        serialized["content"] = "\n".join(
            block.get("content", "") for block in content if isinstance(block, dict)
        )
    tool_calls = message.get("tool_calls")
    if tool_calls:
        serialized["tool_calls"] = [
            {
                "name": call.function,
                "args": to_plain(call.args),
                "id": call.id,
            }
            for call in tool_calls
        ]
    return serialized


def _task_number(task_id: str) -> tuple[int, str]:
    match = re.fullmatch(r"(?:user|injection)_task_(\d+)", task_id)
    return (int(match.group(1)), task_id) if match else (2**31, task_id)


def select_task_groups(
    benchmark_version: str,
    max_groups: int = MAX_GROUPS,
) -> list[tuple[str, str, str]]:
    if not 1 <= max_groups <= MAX_GROUPS:
        raise ValueError(f"max_groups must be between 1 and {MAX_GROUPS}")

    candidates: dict[str, list[tuple[str, str, str]]] = {}
    for suite_name in SUITES:
        suite = get_suite(benchmark_version, suite_name)
        attack = ImportantInstructionsAttack(suite, model_name=MODEL)
        injection_ids = sorted(suite.injection_tasks, key=_task_number)
        suite_candidates = []
        for task_id in sorted(suite.user_tasks, key=_task_number):
            if suite_name == "workspace" and task_id == "user_task_0":
                continue
            user_task = suite.user_tasks[task_id]
            try:
                attack.get_injection_candidates(user_task)
            except ValueError:
                continue
            if not injection_ids:
                continue
            injection_id = injection_ids[len(suite_candidates) % len(injection_ids)]
            suite_candidates.append((suite_name, task_id, injection_id))
        candidates[suite_name] = suite_candidates

    selected: list[tuple[str, str, str]] = []
    positions = {suite_name: 0 for suite_name in SUITES}
    while len(selected) < max_groups:
        advanced = False
        for suite_name in SUITES:
            position = positions[suite_name]
            if position < len(candidates[suite_name]):
                selected.append(candidates[suite_name][position])
                positions[suite_name] += 1
                advanced = True
                if len(selected) == max_groups:
                    break
        if not advanced:
            break
    if len(selected) != max_groups:
        raise ValueError(
            f"only {len(selected)} injectable task groups are available; "
            f"{max_groups} were requested"
        )
    if len({(suite, task) for suite, task, _ in selected}) != len(selected):
        raise RuntimeError("task selection produced duplicate task groups")
    return selected


def _safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip(".") or "unknown"


def _record_group(
    suite_name: str,
    task_id: str,
    injection_task_id: str,
    *,
    benchmark_version: str,
    max_iterations: int,
    client: openai.OpenAI,
    ledger: BudgetLedger,
) -> dict[str, Any]:
    suite = get_suite(benchmark_version, suite_name)
    user_task = suite.user_tasks[task_id]
    injection_task = suite.injection_tasks[injection_task_id]
    attack = ImportantInstructionsAttack(suite, model_name=MODEL)
    injections = attack.attack(user_task, injection_task)
    run_id = f"important-instructions:{uuid4()}"
    seen: list[tuple[Any, DetectorContext | None, DetectorDecision, Any]] = []

    def detector(payload: Any, context: DetectorContext | None = None) -> DetectorDecision:
        decision = parser_detector(payload, context)
        raw_result = context.raw_result if context is not None else payload
        seen.append((payload, context, decision, to_plain(raw_result)))
        return decision

    executor = TrustVerificationToolsExecutor(
        detector,
        mode="passthrough",
        ledger=InterceptionLedger(),
    )
    model = BudgetedGroqLLM(client, MODEL, ledger)
    pipeline = RunContextAgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        model,
        ToolsExecutionLoop([executor, model], max_iters=max_iterations),
    ], run_id)
    try:
        utility, security, _, _, _ = suite.run_task_with_pipeline(
            pipeline,
            user_task,
            injection_task,
            injections,
        )
    finally:
        executor.end_run(run_id)
        parser_detector.end_run(run_id)

    if not model.last_messages:
        raise CollectionStopped(f"{suite_name}:{task_id} produced no model messages")
    return {
        "suite": suite_name,
        "task_id": task_id,
        "user_task_id": task_id,
        "injection_task_id": injection_task_id,
        "benchmark_version": benchmark_version,
        "model": MODEL,
        "attack_type": "important_instructions",
        "pipeline_name": f"groq_{MODEL.replace('/', '_')}",
        "run_id": run_id,
        "injections": injections,
        "user_prompt": user_task.PROMPT,
        "messages": model.last_messages,
        "utility": bool(utility),
        "security": bool(security),
        "tool_interceptions": len(seen),
        "classification_group_id": f"agentdojo:{suite_name}:{task_id}",
    }


def collect(
    output_dir: Path,
    *,
    benchmark_version: str = BENCHMARK_VERSION,
    max_groups: int = MAX_GROUPS,
    max_iterations: int = 8,
    resume: bool = False,
) -> list[dict[str, Any]]:
    if output_dir.exists() and not resume:
        raise FileExistsError(f"refusing to overwrite collection output: {output_dir}")
    if resume and not output_dir.is_dir():
        raise FileNotFoundError(f"collection output does not exist: {output_dir}")
    if not 1 <= max_iterations <= 8:
        raise ValueError("max_iterations must be between 1 and 8")

    load_dotenv(ROOT / ".env", override=False)
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is missing from the environment/.env")

    selections = select_task_groups(benchmark_version, max_groups)
    if resume:
        selection_path = output_dir / "selection.json"
        if not selection_path.is_file():
            raise FileNotFoundError(f"cannot resume without selection file: {selection_path}")
        old_selection = json.loads(selection_path.read_text(encoding="utf-8"))
        new_selection = [
            {"suite": suite, "task_id": task, "injection_task_id": injection}
            for suite, task, injection in selections
        ]
        if old_selection != new_selection:
            raise ValueError("existing selection does not match the requested benchmark groups")
    else:
        output_dir.mkdir(parents=True)
    ledger = BudgetLedger(output_dir / "budget_ledger.json", resume=resume)
    client = openai.OpenAI(
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1",
        max_retries=0,
        timeout=30,
    )
    source_dir = output_dir / "source_traces"
    attack_dir = output_dir / "attack_traces_raw"
    clean_dir = output_dir / "clean_traces_raw"
    selection_rows = [
        {"suite": suite, "task_id": task, "injection_task_id": injection}
        for suite, task, injection in selections
    ]
    if not resume:
        (output_dir / "selection.json").write_text(
            json.dumps(selection_rows, indent=2) + "\n",
            encoding="utf-8",
        )
    results_path = output_dir / "collection_results.json"
    results: list[dict[str, Any]] = (
        json.loads(results_path.read_text(encoding="utf-8"))
        if resume and results_path.is_file()
        else []
    )
    completed_groups = {
        (row["suite"], row["task_id"]): row
        for row in results
        if isinstance(row, dict) and "suite" in row and "task_id" in row
    }

    for suite_name, task_id, injection_task_id in selections:
        completed = completed_groups.get((suite_name, task_id))
        if completed and (output_dir / completed["attack_trace"]).is_file() and (
            output_dir / completed["clean_trace"]
        ).is_file():
            print(f"already complete {suite_name}:{task_id}; skipping")
            continue
        print(f"collecting {suite_name}:{task_id} ({injection_task_id})")
        source_path = (
            source_dir
            / _safe_component(suite_name)
            / f"{_safe_component(task_id)}.json"
        )
        if resume and source_path.is_file():
            source_row = json.loads(source_path.read_text(encoding="utf-8"))
        else:
            source_row = _record_group(
                suite_name,
                task_id,
                injection_task_id,
                benchmark_version=benchmark_version,
                max_iterations=max_iterations,
                client=client,
                ledger=ledger,
            )
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(
                json.dumps(source_row, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        attack_row = replay(source_path, include_injections=True)
        clean_row = replay(source_path, include_injections=False)
        attack_path = _output_path(attack_dir, attack_row, source_path.name)
        clean_path = _output_path(clean_dir, clean_row, source_path.name)
        for path, row in ((attack_path, attack_row), (clean_path, clean_row)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(row, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        result = {
            "suite": suite_name,
            "task_id": task_id,
            "injection_task_id": injection_task_id,
            "attack_success": source_row["security"],
            "utility": source_row["utility"],
            "tool_interceptions": source_row["tool_interceptions"],
            "attack_trace": str(attack_path.relative_to(output_dir)),
            "clean_trace": str(clean_path.relative_to(output_dir)),
        }
        if completed:
            results.remove(completed)
        results.append(result)
        results_path.write_text(
            json.dumps(results, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            f"  security={source_row['security']} utility={source_row['utility']} "
            f"requests={ledger.requests} reserved/actual="
            f"${ledger.actual_usd + ledger.pending_usd + ledger.uncertain_usd:.4f}"
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "out" / "important_instructions_collection_20261126",
    )
    parser.add_argument("--max-groups", type=int, default=MAX_GROUPS)
    parser.add_argument("--max-iterations", type=int, default=8)
    parser.add_argument("--benchmark-version", default=BENCHMARK_VERSION)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    results = collect(
        args.output_dir,
        benchmark_version=args.benchmark_version,
        max_groups=args.max_groups,
        max_iterations=args.max_iterations,
        resume=args.resume,
    )
    print(json.dumps({
        "groups_collected": len(results),
        "successful_attacks": sum(row["attack_success"] for row in results),
        "failed_attacks": sum(not row["attack_success"] for row in results),
        "collection_output": str(args.output_dir),
    }, indent=2))


if __name__ == "__main__":
    main()
