from __future__ import annotations

from ast import literal_eval
from functools import partial
import json
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from typing import Any
from uuid import uuid4

from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from clone.core import Detector, DetectorDecision, InterceptionCore, Mode
from clone.ledger import InterceptionLedger
from clone.tvm import TrustMatrix, load_tool_matrix

# A7, adapter contract: the run id and batch number travel in AgentDojo's extra_args,
# the only per-run channel its pipeline offers. A harness may set _clone_tvm_run_id to
# name a run; otherwise one is generated on the first call. Detectors read them only
# through DetectorContext (run_id, batch_id) and never write them.
_RUN_ID_KEY = "_clone_tvm_run_id"
_BATCH_ID_KEY = "_clone_tvm_batch_id"


class TrustVerificationToolsExecutor(ToolsExecutor):
    """AgentDojo tool executor with pre-hop and post-hop detector interception."""

    def __init__(
        self,
        detector: Detector | None = None,
        *,
        mode: Mode = "enforce",
        detector_timeout_s: float = 2.0,
        tool_output_formatter: Callable[[FunctionReturnType], str] | None = None,
        ledger: InterceptionLedger,
        tool_matrix: TrustMatrix | None = None,
    ) -> None:
        # D1: JSON output by default, so the format never depends on which AgentDojo
        # copy is imported (the pip copy formats with YAML / Python repr).
        super().__init__(tool_output_formatter or partial(tool_result_to_str, dump_fn=json.dumps))
        self.ledger = ledger
        self.tool_matrix = tool_matrix or load_tool_matrix()
        self.core = InterceptionCore(
            ledger,
            detector,
            self.tool_matrix,
            mode=mode,
            detector_timeout_s=detector_timeout_s,
        )
        # Runs this executor has started and not yet ended (see end_run).
        self._active_runs: set[str] = set()

    def end_run(self, run_id: str) -> bool:
        """Release the detector's run-local state (prompt, indexed values, tags).

        AgentDojo's ToolsExecutionLoop stops without calling the executor once the
        model gives its final answer, so the executor cannot see the end of a run by
        itself. It is ended here when the harness calls this, when the executor is
        called after a final answer, or when this executor starts its next run.
        A wrapped detector is followed through ``__wrapped__`` to find ``end_run``."""
        self._active_runs.discard(run_id)
        detector = self.detector
        seen = 0
        while detector is not None and seen < 10:
            end = getattr(detector, "end_run", None)
            if callable(end):
                return bool(end(run_id))
            detector = getattr(detector, "__wrapped__", None)
            seen += 1
        return False

    # A6: the settings live on the core only; these views cannot drift from it.
    @property
    def mode(self) -> Mode:
        return self.core.mode

    @mode.setter
    def mode(self, mode: Mode) -> None:
        self.core.set_mode(mode)

    @property
    def detector(self) -> Detector | None:
        return self.core.detector

    @property
    def detector_timeout_s(self) -> float:
        return self.core.detector_timeout_s

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if self.core.mode == "off":
            return super().query(query, runtime, env, messages, extra_args)
        if (
            not messages
            or messages[-1]["role"] != "assistant"
            or not messages[-1]["tool_calls"]
        ):
            # ToolsExecutionLoop calls the executor once more after the model
            # produces its terminal assistant response. Release run-local
            # prompts and lineage values at that point.
            if messages and messages[-1]["role"] == "assistant" and not messages[-1]["tool_calls"]:
                run_id = extra_args.get(_RUN_ID_KEY)
                if isinstance(run_id, str):
                    self.end_run(run_id)
            return query, runtime, env, messages, extra_args

        updated_extra_args = dict(extra_args)
        run_id = updated_extra_args.get(_RUN_ID_KEY)
        if not isinstance(run_id, str) or not run_id:
            run_id = str(uuid4())
            updated_extra_args[_RUN_ID_KEY] = run_id
        previous_batch = updated_extra_args.get(_BATCH_ID_KEY, 0)
        if isinstance(previous_batch, bool) or not isinstance(previous_batch, int) or previous_batch < 0:
            raise ValueError(f"{_BATCH_ID_KEY} must be a non-negative integer")
        batch_id = previous_batch + 1
        updated_extra_args[_BATCH_ID_KEY] = batch_id
        if previous_batch == 0:
            # First tool batch of a run: AgentDojo runs tasks one after another, so any
            # other run this executor started has finished. End it (bug: run state was
            # never cleared, and the shared store filled up across runs).
            for finished in [r for r in self._active_runs if r != run_id]:
                self.end_run(finished)
        self._active_runs.add(run_id)
        run_metadata = updated_extra_args.get("_clone_tvm_run_meta")
        if run_metadata is not None:
            if not isinstance(run_metadata, Mapping):
                raise TypeError("_clone_tvm_run_meta must be a mapping.")
            self.ledger.set_run_metadata(run_id, run_metadata)
        tool_results: list[ChatToolResultMessage] = []

        # Process the whole assistant tool-call batch in framework order.
        for tool_call in messages[-1]["tool_calls"]:
            # Same order as AgentDojo's ToolsExecutor: an empty or unknown tool name
            # is answered by the framework and never reaches the detector or ledger,
            # so a hallucinated tool behaves exactly as in a baseline run.
            invalid = _invalid_tool_error(tool_call.function, runtime)
            if invalid is not None:
                tool_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=invalid,
                    )
                )
                continue

            args = _framework_args(tool_call.args)
            # AgentDojo writes converted list arguments back into the call, so the
            # message history matches a baseline run. ``args`` stays a separate copy.
            for key, value in args.items():
                if isinstance(value, list) and isinstance(tool_call.args.get(key), str):
                    tool_call.args[key] = deepcopy(value)
            definition = runtime.functions.get(tool_call.function)
            expected_keys = (
                set(definition.parameters.model_fields)
                if definition is not None
                else set(args)
            )
            call_verdict = self.core.check_call(
                run_id,
                tool_call.id,
                tool_call.function,
                args,
                expected_keys,
                schema=definition.parameters if definition is not None else None,
                user_prompt=query,
                batch_id=batch_id,
            )
            if not call_verdict.allowed:
                denial = call_verdict.denial_text or "Blocked"
                tool_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(denial)],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=denial,
                    )
                )
                continue

            pre_record = call_verdict.record
            if pre_record is None:
                raise RuntimeError("Allowed tool call did not produce an interception record.")
            tool_result = None
            if tool_call.function not in runtime.functions:   # registered under another key
                result, error = "", f"Invalid tool {tool_call.function} provided."
                executed = False
            else:
                try:
                    tool_result, error = runtime.run_function(env, tool_call.function, args)
                    result = self.output_formatter(tool_result)
                except Exception as failure:
                    # Close the record before the exception leaves (a baseline run
                    # raises the same exception), so the ledger is not left half-open.
                    self.core.mark_executed(pre_record, True)
                    self.core.mark_failed(
                        pre_record, f"{type(failure).__name__} while running or formatting the tool result."
                    )
                    raise
                executed = True
            self.core.mark_executed(pre_record, executed)
            result_verdict = self.core.check_result(
                run_id,
                tool_call.id,
                pre_record.interception_id,
                tool_call.function,
                result,
                tool_error=error,
                schema=definition.return_type if definition is not None else None,
                raw_result=tool_result,
                result_format=(
                    "json"
                    if isinstance(tool_result, (Mapping, list, tuple))
                    or (hasattr(tool_result, "model_dump") and not isinstance(tool_result, type))
                    else "text"
                ),
                user_prompt=query,
                batch_id=batch_id,
            )
            observation = result if result_verdict.allowed else (
                result_verdict.denial_text or "Blocked"
            )
            if not result_verdict.allowed:
                # The model sees only the fixed denial text; the reason stays in the ledger.
                error = observation

            tool_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(observation)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )

        return query, runtime, env, [*messages, *tool_results], updated_extra_args


def _invalid_tool_error(function: str, runtime: FunctionsRuntime) -> str | None:
    """AgentDojo's own answers for an empty or unknown tool name (None if the tool exists)."""
    if function == EMPTY_FUNCTION_NAME:
        return "Empty function name provided. Provide a valid function name."
    if function not in (tool.name for tool in runtime.functions.values()):
        return f"Invalid tool {function} provided."
    return None


def _framework_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """Apply AgentDojo's list-string conversion without mutating its FunctionCall."""
    copied = deepcopy(dict(args))
    for key, value in copied.items():
        if isinstance(value, str):
            try:
                parsed = literal_eval(value)
            except (ValueError, SyntaxError):
                continue
            if isinstance(parsed, list):
                copied[key] = parsed
    return copied
