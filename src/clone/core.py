from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from inspect import Signature, signature
from queue import Empty, Queue
from threading import Thread
from time import perf_counter_ns
from typing import Any, Literal

from clone.ledger import DetectorPayload, InterceptionLedger, InterceptionRecord
from clone.tvm import ToolMatrixEntry, TrustMatrix

Mode = Literal["off", "passthrough", "enforce"]
_DENIAL_PREFIX = "Blocked by Trust Verification Matrix"


@dataclass(frozen=True)
class DetectorContext:
    direction: Literal["pre", "post"]
    tool_name: str
    tool_call_id: str | None
    matrix_entry: ToolMatrixEntry


@dataclass(frozen=True)
class DetectorDecision:
    allowed: bool
    label: str
    score: float | None = None
    reason: str | None = None
    contains_adi: bool | None = None


Detector = Callable[..., bool | DetectorDecision]


@dataclass(frozen=True)
class InterceptionVerdict:
    allowed: bool
    denial_text: str | None
    record: InterceptionRecord | None


class InterceptionCore:
    """Framework-independent interception, policy, and ledger lifecycle."""

    def __init__(
        self,
        ledger: InterceptionLedger,
        detector: Detector | None,
        tool_matrix: TrustMatrix,
        mode: Mode = "enforce",
        detector_timeout_s: float = 2.0,
        detector_name: str | None = None,
        detector_version: str | None = None,
    ) -> None:
        if mode not in ("off", "passthrough", "enforce"):
            raise ValueError(f"Unsupported interception mode: {mode}")
        if detector_timeout_s <= 0:
            raise ValueError("detector_timeout_s must be greater than zero")
        self.ledger = ledger
        self.detector = detector
        self.tool_matrix = tool_matrix
        self.mode = mode
        self.detector_timeout_s = detector_timeout_s
        self.detector_name = (
            detector_name
            if detector_name is not None
            else getattr(detector, "__name__", None)
        )
        self.detector_version = (
            detector_version
            if detector_version is not None
            else getattr(detector, "__version__", None)
        )
        self._detector_uses_context = (
            _detector_accepts_context(detector) if mode != "off" else False
        )

    def check_call(
        self,
        run_id: str,
        call_id: str | None,
        tool: str,
        args: dict[str, Any],
        expected_keys: set[str] | frozenset[str],
    ) -> InterceptionVerdict:
        """Capture and decide whether a tool call may execute."""
        if self.mode == "off":
            return InterceptionVerdict(True, None, None)

        entry = self.tool_matrix.lookup(tool, expected_keys)
        payload = {"tool": tool, "args": deepcopy(args)}
        record = self.ledger.capture(
            run_id,
            "pre",
            call_id,
            payload,
            internal_tool_id=entry.internal_tool_id,
            impact_tier=entry.impact_tier,
            impact_tier_source=entry.impact_tier_source,
            matrix_classified=not entry.is_fallback,
            detector_name=self.detector_name,
            detector_version=self.detector_version,
            matrix_schema_version=self.tool_matrix.schema_version,
            matrix_sha256=self.tool_matrix.source_sha256,
        )
        if entry.is_fallback:
            self.ledger.transition(
                record,
                "unclassified_tool",
                label="unclassified",
                error=f"Tool {tool!r} is missing from the trust matrix.",
            )

        context = DetectorContext("pre", tool, call_id, entry)
        decision, error = self._inspect(record, payload, context)
        if error is None and decision is not None and decision.allowed:
            if entry.is_fallback and self.mode == "enforce":
                denial = "Blocked: unclassified tool"
                label = "unclassified"
                detail = f"Tool {tool!r} is missing from the trust matrix."
            else:
                self.ledger.transition(
                    record,
                    "allowed",
                    detector_decision=True,
                    label=decision.label,
                    score=decision.score,
                    contains_adi=decision.contains_adi,
                )
                return InterceptionVerdict(True, None, record)
        elif self.mode == "passthrough":
            self.ledger.transition(
                record,
                "passthrough_release",
                detector_decision=decision.allowed if decision is not None else None,
                label=decision.label if decision is not None else "detector-error",
                score=decision.score if decision is not None else None,
                contains_adi=decision.contains_adi if decision is not None else None,
                error=error,
            )
            return InterceptionVerdict(True, None, record)
        else:
            denial = self._denial(decision, error)
            label = decision.label if decision is not None else "detector-error"
            detail = error or (decision.reason if decision is not None else None)

        self.ledger.transition(
            record,
            "blocked",
            detector_decision=False,
            released=False,
            label=label,
            score=decision.score if decision is not None else None,
            contains_adi=decision.contains_adi if decision is not None else None,
            error=detail,
        )
        self._deliver_denial(run_id, call_id, record, entry, denial)
        return InterceptionVerdict(False, denial, record)

    def mark_executed(self, record: InterceptionRecord, executed: bool) -> None:
        """Record that an allowed call has completed its execution attempt."""
        self.ledger.transition(
            record, "executed" if executed else "completed", released=True
        )

    def check_result(
        self,
        run_id: str,
        call_id: str | None,
        pre_interception_id: str,
        tool: str,
        text: str,
        *,
        tool_error: str | None = None,
    ) -> InterceptionVerdict:
        """Capture and decide whether the original tool observation may be released."""
        if not isinstance(text, str):
            raise TypeError("Post-hop result text must be a string.")
        if self.mode == "off":
            return InterceptionVerdict(True, None, None)

        pre_record = self.ledger.get_record(pre_interception_id)
        entry = (
            self._entry_for_record(pre_record)
            if pre_record is not None
            else self.tool_matrix.lookup(tool, ())
        )
        record = self.ledger.capture(
            run_id,
            "post",
            call_id,
            text,
            pre_interception_id,
            internal_tool_id=entry.internal_tool_id,
            impact_tier=entry.impact_tier,
            impact_tier_source=entry.impact_tier_source,
            matrix_classified=not entry.is_fallback,
            tool_error=tool_error,
            detector_name=self.detector_name,
            detector_version=self.detector_version,
            matrix_schema_version=self.tool_matrix.schema_version,
            matrix_sha256=self.tool_matrix.source_sha256,
        )
        context = DetectorContext("post", tool, call_id, entry)
        decision, error = self._inspect(record, text, context)
        if error is None and decision is not None and decision.allowed:
            self.ledger.transition(
                record,
                "released",
                detector_decision=True,
                released=True,
                label=decision.label,
                score=decision.score,
                contains_adi=decision.contains_adi,
                delivered_payload=text,
            )
            return InterceptionVerdict(True, None, record)
        if self.mode == "passthrough":
            self.ledger.transition(
                record,
                "passthrough_release",
                detector_decision=decision.allowed if decision is not None else None,
                released=True,
                label=decision.label if decision is not None else "detector-error",
                score=decision.score if decision is not None else None,
                contains_adi=decision.contains_adi if decision is not None else None,
                error=error,
                delivered_payload=text,
            )
            return InterceptionVerdict(True, None, record)

        denial = self._denial(decision, error)
        self.ledger.transition(
            record,
            "blocked",
            detector_decision=False,
            released=False,
            label=decision.label if decision is not None else "detector-error",
            score=decision.score if decision is not None else None,
            contains_adi=decision.contains_adi if decision is not None else None,
            error=error or (decision.reason if decision is not None else None),
        )
        self.ledger.transition(
            record,
            "denial_delivered",
            released=False,
            delivered_payload=denial,
        )
        return InterceptionVerdict(False, denial, record)

    def _entry_for_record(self, record: InterceptionRecord) -> ToolMatrixEntry:
        for entry in self.tool_matrix.entries:
            if entry.internal_tool_id == record.internal_tool_id:
                return entry
        return ToolMatrixEntry(
            tool_name=record.internal_tool_id or "",
            internal_tool_id=record.internal_tool_id or "",
            impact_tier=record.impact_tier,
            impact_tier_source=record.impact_tier_source or "unclassified",
            authority_arguments=(),
            field_trust_classes={},
            expected_keys=(),
            is_fallback=not record.matrix_classified,
        )

    def _deliver_denial(
        self,
        run_id: str,
        call_id: str | None,
        pre_record: InterceptionRecord,
        entry: ToolMatrixEntry,
        denial: str,
    ) -> None:
        post = self.ledger.capture(
            run_id,
            "post",
            call_id,
            denial,
            pre_record.interception_id,
            internal_tool_id=entry.internal_tool_id,
            impact_tier=entry.impact_tier,
            impact_tier_source=entry.impact_tier_source,
            matrix_classified=not entry.is_fallback,
            detector_name=self.detector_name,
            detector_version=self.detector_version,
            matrix_schema_version=self.tool_matrix.schema_version,
            matrix_sha256=self.tool_matrix.source_sha256,
        )
        self.ledger.transition(
            post,
            "denial_delivered",
            detector_decision=False,
            released=False,
            label="policy-denial",
            delivered_payload=denial,
        )

    def _inspect(
        self,
        record: InterceptionRecord,
        payload: DetectorPayload,
        context: DetectorContext,
    ) -> tuple[DetectorDecision | None, str | None]:
        self.ledger.transition(record, "decision_pending")
        started_ns = perf_counter_ns()
        decision, error = _run_detector(
            self.detector,
            deepcopy(payload),
            context,
            self.detector_timeout_s,
            self._detector_uses_context,
        )
        latency_ms = (perf_counter_ns() - started_ns) / 1_000_000
        if error is not None:
            self.ledger.transition(
                record,
                "detector_error",
                error=error,
                detector_latency_ms=latency_ms,
            )
            return None, error
        if decision is None:
            error = "Detector returned no decision."
            self.ledger.transition(
                record,
                "detector_error",
                error=error,
                detector_latency_ms=latency_ms,
            )
            return None, error
        self.ledger.transition(
            record, "decision_received", detector_latency_ms=latency_ms
        )
        return decision, None

    @staticmethod
    def _denial(
        decision: DetectorDecision | None, error: str | None
    ) -> str:
        if error is not None:
            return "Blocked: detector unavailable"
        reason = (decision.reason if decision else None) or (
            decision.label if decision else "detector unavailable"
        )
        return f"{_DENIAL_PREFIX}: {reason}"


def _run_detector(
    detector: Detector | None,
    payload: DetectorPayload,
    context: DetectorContext,
    timeout_s: float,
    detector_uses_context: bool,
) -> tuple[DetectorDecision | None, str | None]:
    if detector is None:
        return None, "No detector configured."

    response: Queue[tuple[bool | DetectorDecision | None, Exception | None]] = Queue(maxsize=1)

    def invoke() -> None:
        try:
            result = detector(payload, context) if detector_uses_context else detector(payload)
            response.put((result, None))
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


def _detector_accepts_context(detector: Detector | None) -> bool:
    if detector is None:
        return False
    try:
        detector_signature: Signature = signature(detector)
    except (TypeError, ValueError) as error:
        raise TypeError(
            "Detector must have an inspectable signature accepting payload "
            "or payload and context."
        ) from error
    try:
        detector_signature.bind(None, None)
    except TypeError:
        try:
            detector_signature.bind(None)
        except TypeError as error:
            raise TypeError(
                "Detector must accept payload or payload and context."
            ) from error
        return False
    return True
