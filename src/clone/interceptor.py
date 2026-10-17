from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from queue import Empty, Queue
from threading import Lock, Thread
from time import time
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel

from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

Mode = Literal["off", "passthrough", "enforce"]
Phase = Literal["pre", "post"]
DetectorPayload = dict[str, Any] | str
_RUN_ID_KEY = "_clone_tvm_run_id"
_DENIAL_PREFIX = "Blocked by Trust Verification Matrix"


@dataclass(frozen=True)
class DetectorDecision:
    allowed: bool
    label: str
    score: float | None = None
    reason: str | None = None


Detector = Callable[[DetectorPayload], bool | DetectorDecision]


@dataclass
class InterceptionRecord:
    run_id: str
    interception_id: str
    seq: int
    phase: Phase
    tool_call_id: str | None
    sha256: str
    pre_interception_id: str | None
    state: str = "captured"
    detector_decision: bool | None = None
    released: bool | None = None
    label: str | None = None
    score: float | None = None
    error: str | None = None


@dataclass(frozen=True)
class LedgerEntry:
    event_seq: int
    run_id: str
    interception_id: str
    interception_seq: int
    phase: Phase
    tool_call_id: str | None
    sha256: str
    pre_interception_id: str | None
    state: str
    detector_decision: bool | None
    released: bool | None
    label: str | None
    score: float | None
    error: str | None
    timestamp: float


@dataclass(frozen=True)
class RawPayload:
    run_id: str
    interception_id: str
    phase: Phase
    label: str | None
    payload: DetectorPayload


class TrustVerificationMatrix:
    """Thread-safe, process-global trace of intercepted tool inputs and observations."""

    def __init__(self) -> None:
        self.records: list[InterceptionRecord] = []
        self.ledger: list[LedgerEntry] = []
        self.raw_payloads: list[RawPayload] = []
        self._lock = Lock()
        self._seq_by_run: dict[str, int] = {}
        self._event_seq = 0

    def capture(
        self,
        run_id: str,
        phase: Phase,
        tool_call_id: str | None,
        payload: DetectorPayload,
        pre_interception_id: str | None = None,
    ) -> InterceptionRecord:
        payload_hash = _payload_hash(phase, payload)
        with self._lock:
            seq = self._seq_by_run.get(run_id, 0) + 1
            self._seq_by_run[run_id] = seq
            record = InterceptionRecord(
                run_id=run_id,
                interception_id=str(uuid4()),
                seq=seq,
                phase=phase,
                tool_call_id=tool_call_id,
                sha256=payload_hash,
                pre_interception_id=pre_interception_id,
            )
            self.records.append(record)
            self.raw_payloads.append(
                RawPayload(run_id, record.interception_id, phase, None, deepcopy(payload))
            )
            self._append_ledger_locked(record, "captured")
            return record

    def transition(
        self,
        record: InterceptionRecord,
        state: str,
        *,
        detector_decision: bool | None = None,
        released: bool | None = None,
        label: str | None = None,
        score: float | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            record.state = state
            if detector_decision is not None:
                record.detector_decision = detector_decision
            if released is not None:
                record.released = released
            if label is not None:
                record.label = label
            if score is not None:
                record.score = score
            if error is not None:
                record.error = error
            for index in range(len(self.raw_payloads) - 1, -1, -1):
                payload = self.raw_payloads[index]
                if payload.interception_id == record.interception_id:
                    self.raw_payloads[index] = RawPayload(
                        payload.run_id,
                        payload.interception_id,
                        payload.phase,
                        record.label,
                        payload.payload,
                    )
                    break
            self._append_ledger_locked(record, state)

    def update_hash(self, record: InterceptionRecord, payload: DetectorPayload) -> None:
        with self._lock:
            record.sha256 = _payload_hash(record.phase, payload)

    def _append_ledger_locked(self, record: InterceptionRecord, state: str) -> None:
        self._event_seq += 1
        self.ledger.append(
            LedgerEntry(
                event_seq=self._event_seq,
                run_id=record.run_id,
                interception_id=record.interception_id,
                interception_seq=record.seq,
                phase=record.phase,
                tool_call_id=record.tool_call_id,
                sha256=record.sha256,
                pre_interception_id=record.pre_interception_id,
                state=state,
                detector_decision=record.detector_decision,
                released=record.released,
                label=record.label,
                score=record.score,
                error=record.error,
                timestamp=time(),
            )
        )

    def export_ledger(self, path: str | Path) -> None:
        with self._lock:
            rows = [asdict(entry) for entry in self.ledger]
        _write_jsonl(path, rows)

    def export_raw_payloads(self, path: str | Path) -> None:
        """Export raw detector inputs separately from the state-change ledger."""
        with self._lock:
            rows = [asdict(payload) for payload in self.raw_payloads]
        _write_jsonl(path, rows)

    def clear(self) -> None:
        with self._lock:
            self.records.clear()
            self.ledger.clear()
            self.raw_payloads.clear()
            self._seq_by_run.clear()
            self._event_seq = 0


TVM = TrustVerificationMatrix()


class TrustVerificationToolsExecutor(ToolsExecutor):
    """AgentDojo tool executor with pre-hop and post-hop detector interception."""

    def __init__(
        self,
        detector: Detector | None = None,
        *,
        mode: Mode = "enforce",
        detector_timeout_s: float = 2.0,
        tool_output_formatter: Callable[[FunctionReturnType], str] | None = None,
        matrix: TrustVerificationMatrix = TVM,
    ) -> None:
        if mode not in ("off", "passthrough", "enforce"):
            raise ValueError(f"Unsupported interception mode: {mode}")
        if detector_timeout_s <= 0:
            raise ValueError("detector_timeout_s must be greater than zero")
        if tool_output_formatter is None:
            super().__init__()
        else:
            super().__init__(tool_output_formatter)
        self.detector = detector
        self.mode = mode
        self.detector_timeout_s = detector_timeout_s
        self.matrix = matrix

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if self.mode == "off":
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
        tool_results: list[ChatToolResultMessage] = []

        # Process the whole assistant tool-call batch in framework order.
        for tool_call in messages[-1]["tool_calls"]:
            args = _framework_args(tool_call.args)
            pre_payload = {"tool": tool_call.function, "args": args}
            pre = self.matrix.capture(run_id, "pre", tool_call.id, pre_payload)
            pre_allowed, pre_decision, pre_error = self._inspect(pre, pre_payload)

            if not pre_allowed:
                denial = self._denial(pre_decision, pre_error)
                self.matrix.transition(
                    pre,
                    "blocked",
                    detector_decision=False,
                    released=False,
                    label=pre_decision.label if pre_decision else "detector-error",
                    score=pre_decision.score if pre_decision else None,
                    error=pre_error or (pre_decision.reason if pre_decision else None),
                )
                tool_results.append(
                    self._denial_result(tool_call, denial, pre.interception_id, run_id)
                )
                continue

            self.matrix.transition(
                pre,
                "passthrough_release"
                if pre_decision is not None and not pre_decision.allowed
                else "allowed",
                detector_decision=pre_decision.allowed if pre_decision else None,
                label=pre_decision.label if pre_decision else "passthrough",
                score=pre_decision.score if pre_decision else None,
                error=pre_error,
            )
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
            self.matrix.transition(
                pre, "executed" if executed else "completed", released=True
            )

            post_record = self.matrix.capture(
                run_id, "post", tool_call.id, result, pre.interception_id
            )
            post_allowed, post_decision, post_error = self._inspect(post_record, result)
            if post_allowed:
                observation = result
                self.matrix.transition(
                    post_record,
                    "passthrough_release"
                    if post_decision is not None and not post_decision.allowed
                    else "released",
                    detector_decision=post_decision.allowed if post_decision else None,
                    released=True,
                    label=post_decision.label if post_decision else "passthrough",
                    score=post_decision.score if post_decision else None,
                    error=post_error,
                )
            else:
                observation = self._denial(post_decision, post_error)
                self.matrix.update_hash(post_record, observation)
                self.matrix.transition(
                    post_record,
                    "blocked",
                    detector_decision=False,
                    released=False,
                    label=post_decision.label if post_decision else "detector-error",
                    score=post_decision.score if post_decision else None,
                    error=post_error or (post_decision.reason if post_decision else None),
                )
                error = post_error or (post_decision.reason if post_decision else "Blocked by detector.")

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

    def _inspect(
        self, record: InterceptionRecord, payload: DetectorPayload
    ) -> tuple[bool, DetectorDecision | None, str | None]:
        self.matrix.transition(record, "decision_pending")
        decision, error = _run_detector(
            self.detector, deepcopy(payload), self.detector_timeout_s
        )
        if error is not None:
            self.matrix.transition(record, "detector_error", error=error)
            return self.mode == "passthrough", None, error
        if decision is None:
            error = "Detector returned no decision."
            self.matrix.transition(record, "detector_error", error=error)
            return self.mode == "passthrough", None, error
        return decision.allowed or self.mode == "passthrough", decision, None

    def _denial_result(
        self,
        tool_call: Any,
        denial: str,
        pre_interception_id: str,
        run_id: str,
    ) -> ChatToolResultMessage:
        post = self.matrix.capture(
            run_id, "post", tool_call.id, denial, pre_interception_id
        )
        self.matrix.transition(
            post,
            "blocked",
            detector_decision=False,
            released=False,
            label="policy-denial",
            error=denial,
        )
        self.matrix.transition(post, "released", released=True)
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(denial)],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=denial,
        )

    @staticmethod
    def _denial(decision: DetectorDecision | None, error: str | None) -> str:
        reason = error or (decision.reason if decision else None) or (
            decision.label if decision else "detector unavailable"
        )
        return f"{_DENIAL_PREFIX}: {reason}"


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


def _run_detector(
    detector: Detector | None,
    payload: DetectorPayload,
    timeout_s: float,
) -> tuple[DetectorDecision | None, str | None]:
    if detector is None:
        return None, "No detector configured."

    response: Queue[tuple[bool | DetectorDecision | None, Exception | None]] = Queue(maxsize=1)

    def invoke() -> None:
        try:
            response.put((detector(payload), None))
        except Exception as error:
            response.put((None, error))

    Thread(target=invoke, name="tvm-detector", daemon=True).start()
    try:
        result, error = response.get(timeout=timeout_s)
    except Empty:
        return None, f"Detector timed out after {timeout_s:g} seconds."
    if error is not None:
        return None, f"Detector error: {type(error).__name__}: {error}"
    if isinstance(result, DetectorDecision):
        if not isinstance(result.allowed, bool) or not isinstance(result.label, str):
            return None, "Detector returned an invalid decision."
        return result, None
    if isinstance(result, bool):
        return DetectorDecision(result, "allow" if result else "block"), None
    return None, f"Detector returned unsupported decision type: {type(result).__name__}."


def _payload_hash(phase: Phase, payload: DetectorPayload) -> str:
    if phase == "pre":
        canonical = json.dumps(
            _jsonable(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    elif isinstance(payload, str):
        canonical = payload.encode("utf-8")
    else:
        raise TypeError("Post-hop payloads must be strings.")
    return sha256(canonical).hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            output.write("\n")
