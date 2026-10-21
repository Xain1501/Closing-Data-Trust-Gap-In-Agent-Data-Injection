from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from typing import Any
from uuid import uuid4

from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from clone.core import Detector, DetectorDecision, InterceptionCore, Mode
from clone.ledger import InterceptionLedger
from clone.tvm import TrustMatrix, load_tool_matrix

_RUN_ID_KEY = "_clone_tvm_run_id"


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
        if tool_output_formatter is None:
            super().__init__()
        else:
            super().__init__(tool_output_formatter)
        self.detector = detector
        self.mode = mode
        self.detector_timeout_s = detector_timeout_s
        self.ledger = ledger
        self.tool_matrix = tool_matrix or load_tool_matrix()
        self.core = InterceptionCore(
            ledger,
            detector,
            self.tool_matrix,
            mode=mode,
            detector_timeout_s=detector_timeout_s,
        )

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
            return query, runtime, env, messages, extra_args

        updated_extra_args = dict(extra_args)
        run_id = updated_extra_args.get(_RUN_ID_KEY)
        if not isinstance(run_id, str) or not run_id:
            run_id = str(uuid4())
            updated_extra_args[_RUN_ID_KEY] = run_id
        run_metadata = updated_extra_args.get("_clone_tvm_run_meta")
        if run_metadata is not None:
            if not isinstance(run_metadata, Mapping):
                raise TypeError("_clone_tvm_run_meta must be a mapping.")
            self.ledger.set_run_metadata(run_id, run_metadata)
        tool_results: list[ChatToolResultMessage] = []

        # Process the whole assistant tool-call batch in framework order.
        for tool_call in messages[-1]["tool_calls"]:
            args = _framework_args(tool_call.args)
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

            if tool_call.function == EMPTY_FUNCTION_NAME:
                result, error = "", "Empty function name provided. Provide a valid function name."
                executed = False
            elif tool_call.function not in runtime.functions:
                result, error = "", f"Invalid tool {tool_call.function} provided."
                executed = False
            else:
                tool_result, error = runtime.run_function(env, tool_call.function, args)
                result = self.output_formatter(tool_result)
                executed = True
            pre_record = call_verdict.record
            if pre_record is None:
                raise RuntimeError("Allowed tool call did not produce an interception record.")
            self.core.mark_executed(pre_record, executed)
            result_verdict = self.core.check_result(
                run_id,
                tool_call.id,
                pre_record.interception_id,
                tool_call.function,
                result,
                tool_error=error,
            )
            observation = result if result_verdict.allowed else (
                result_verdict.denial_text or "Blocked"
            )
            if not result_verdict.allowed and result_verdict.record is not None:
                record = result_verdict.record
                error = (
                    observation
                    if record.label == "detector-error"
                    else record.error or observation
                )

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
