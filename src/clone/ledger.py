from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from hashlib import sha256  # noqa: F401  (entry hashing below)
import json
import math
from pathlib import Path
from threading import Lock
from time import time
from typing import Any, Literal
from uuid import uuid4

from clone.canonical import canonical_json, text_sha256

Phase = Literal["pre", "post"]
DetectorPayload = dict[str, Any] | str
_GENESIS_ENTRY_SHA256 = "0" * 64
_ENTRY_SCHEMA_VERSION = 2   # v2: forgery_found, schema_ok, parse_health, decided_by


@dataclass
class InterceptionRecord:
    run_id: str
    interception_id: str
    seq: int
    phase: Phase
    tool_call_id: str | None
    sha256: str
    pre_interception_id: str | None
    internal_tool_id: str | None = None
    impact_tier: int | None = None
    impact_tier_source: str | None = None
    matrix_classified: bool = True
    state: str = "captured"
    detector_decision: bool | None = None
    released: bool | None = None
    label: str | None = None
    score: float | None = None
    contains_adi: bool | None = None
    error: str | None = None
    detector_latency_ms: float | None = None
    delivered_sha256: str | None = None
    tool_error: str | None = None
    detector_name: str | None = None
    detector_version: str | None = None
    matrix_schema_version: int | None = None
    matrix_sha256: str | None = None
    prev_entry_sha256: str | None = None
    entry_sha256: str | None = None
    entry_schema_version: int | None = None
    # Evidence, logged separately so statistics are not mixed (scope section 8):
    forgery_found: bool | None = None     # counted structural findings (same meaning as contains_adi)
    schema_ok: bool | None = None         # None = no schema was checked
    parse_health: str | None = None       # clean | salvaged_repr | salvaged_repaired | uninspectable
    decided_by: str | None = None         # who produced the outcome: detector name/stage, "matrix", "detector-error", "policy"


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
    internal_tool_id: str | None
    impact_tier: int | None
    impact_tier_source: str | None
    matrix_classified: bool
    state: str
    detector_decision: bool | None
    released: bool | None
    label: str | None
    score: float | None
    contains_adi: bool | None
    error: str | None
    detector_latency_ms: float | None
    timestamp: float
    delivered_sha256: str | None = None
    tool_error: str | None = None
    detector_name: str | None = None
    detector_version: str | None = None
    matrix_schema_version: int | None = None
    matrix_sha256: str | None = None
    prev_entry_sha256: str | None = None
    entry_sha256: str | None = None
    entry_schema_version: int | None = None
    # Evidence, logged separately so statistics are not mixed (scope section 8):
    forgery_found: bool | None = None     # counted structural findings (same meaning as contains_adi)
    schema_ok: bool | None = None         # None = no schema was checked
    parse_health: str | None = None       # clean | salvaged_repr | salvaged_repaired | uninspectable
    decided_by: str | None = None         # who produced the outcome: detector name/stage, "matrix", "detector-error", "policy"


@dataclass(frozen=True)
class RawPayload:
    run_id: str
    interception_id: str
    phase: Phase
    label: str | None
    payload: DetectorPayload


class InterceptionLedger:
    """Thread-safe trace of intercepted tool inputs, observations, and state changes."""

    def __init__(self, storage_dir: str | Path | None = None) -> None:
        """Create an in-memory ledger, optionally persisting it to JSONL.

        With ``storage_dir`` set, ``ledger.jsonl`` and ``raw-payloads.jsonl`` are
        APPENDED to (one line per event / per captured payload), so the cost of a
        run grows linearly. Raw payloads are written whenever ``storage_dir`` is
        set; captured tool data may be private. A payload's final label is in
        ``ledger.jsonl`` (and in ``export_raw_payloads``); the appended raw row
        is written at capture time, before any label exists.
        """
        self.records: list[InterceptionRecord] = []
        self.ledger: list[LedgerEntry] = []
        self.raw_payloads: list[RawPayload] = []
        self._lock = Lock()
        self._seq_by_run: dict[str, int] = {}
        self._records_by_id: dict[str, InterceptionRecord] = {}
        self._raw_payload_index: dict[str, int] = {}
        self._run_metadata: dict[str, dict[str, Any]] = {}
        self._event_seq = 0
        self.storage_dir = Path(storage_dir) if storage_dir is not None else None
        self._persisted_entries = 0
        self._persisted_payloads = 0
        self._files_started = False

    def set_run_metadata(self, run_id: str, mapping: Mapping[str, Any]) -> None:
        if not isinstance(mapping, Mapping):
            raise TypeError("Run metadata must be a mapping.")
        with self._lock:
            self._run_metadata[run_id] = deepcopy(dict(mapping))
            self._persist_metadata_locked()

    def capture(
        self,
        run_id: str,
        phase: Phase,
        tool_call_id: str | None,
        payload: DetectorPayload,
        pre_interception_id: str | None = None,
        *,
        internal_tool_id: str | None = None,
        impact_tier: int | None = None,
        impact_tier_source: str | None = None,
        matrix_classified: bool = True,
        tool_error: str | None = None,
        detector_name: str | None = None,
        detector_version: str | None = None,
        matrix_schema_version: int | None = None,
        matrix_sha256: str | None = None,
    ) -> InterceptionRecord:
        # Pre-hop payloads are frozen into their canonical JSON text here, once.
        # That text is what is hashed, stored and (decoded) inspected.
        if not isinstance(payload, str):
            if phase == "post":
                raise TypeError("Post-hop payloads must be strings.")
            payload = canonical_json(payload)
        payload_hash = text_sha256(payload)
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
                internal_tool_id=internal_tool_id,
                impact_tier=impact_tier,
                impact_tier_source=impact_tier_source,
                matrix_classified=matrix_classified,
                tool_error=tool_error,
                detector_name=detector_name,
                detector_version=detector_version,
                matrix_schema_version=matrix_schema_version,
                matrix_sha256=matrix_sha256,
            )
            self.records.append(record)
            self._records_by_id[record.interception_id] = record
            self._raw_payload_index[record.interception_id] = len(self.raw_payloads)
            self.raw_payloads.append(
                RawPayload(run_id, record.interception_id, phase, None, payload)
            )
            self._append_ledger_locked(record, "captured")
            self._persist_locked()
            return record

    def get_record(self, interception_id: str) -> InterceptionRecord | None:
        with self._lock:
            return self._records_by_id.get(interception_id)

    def get_payload(self, interception_id: str) -> str | None:
        """The frozen payload text captured for an interception."""
        with self._lock:
            index = self._raw_payload_index.get(interception_id)
            return None if index is None else self.raw_payloads[index].payload  # type: ignore[return-value]

    def transition(
        self,
        record: InterceptionRecord,
        state: str,
        *,
        detector_decision: bool | None = None,
        released: bool | None = None,
        label: str | None = None,
        score: float | None = None,
        contains_adi: bool | None = None,
        error: str | None = None,
        detector_latency_ms: float | None = None,
        delivered_payload: DetectorPayload | None = None,
        forgery_found: bool | None = None,
        schema_ok: bool | None = None,
        parse_health: str | None = None,
        decided_by: str | None = None,
    ) -> None:
        if score is not None and not (isinstance(score, (int, float)) and math.isfinite(score)):
            score = None                      # NaN / infinity is not valid JSON
        with self._lock:
            record.state = state
            if forgery_found is not None:
                record.forgery_found = forgery_found
            if schema_ok is not None:
                record.schema_ok = schema_ok
            if parse_health is not None:
                record.parse_health = parse_health
            if decided_by is not None:
                record.decided_by = decided_by
            if detector_decision is not None:
                record.detector_decision = detector_decision
            if released is not None:
                record.released = released
            if label is not None:
                record.label = label
            if score is not None:
                record.score = score
            if contains_adi is not None:
                record.contains_adi = contains_adi
            if error is not None:
                record.error = error
            if detector_latency_ms is not None:
                record.detector_latency_ms = detector_latency_ms
            if delivered_payload is not None:
                record.delivered_sha256 = _payload_hash(delivered_payload)
            raw_index = self._raw_payload_index.get(record.interception_id)
            if raw_index is None:
                raise KeyError(
                    f"No captured raw payload for interception {record.interception_id}."
                )
            payload = self.raw_payloads[raw_index]
            self.raw_payloads[raw_index] = RawPayload(
                payload.run_id,
                payload.interception_id,
                payload.phase,
                record.label,
                payload.payload,
            )
            self._append_ledger_locked(record, state)
            self._persist_locked()

    def _append_ledger_locked(self, record: InterceptionRecord, state: str) -> None:
        event_seq = self._event_seq + 1
        previous_hash = (
            self.ledger[-1].entry_sha256
            if self.ledger
            else _GENESIS_ENTRY_SHA256
        )
        if previous_hash is None:
            raise ValueError("Cannot append to a ledger with an unchained last entry.")
        entry = LedgerEntry(
            event_seq=event_seq,
            run_id=record.run_id,
            interception_id=record.interception_id,
            interception_seq=record.seq,
            phase=record.phase,
            tool_call_id=record.tool_call_id,
            sha256=record.sha256,
            pre_interception_id=record.pre_interception_id,
            internal_tool_id=record.internal_tool_id,
            impact_tier=record.impact_tier,
            impact_tier_source=record.impact_tier_source,
            matrix_classified=record.matrix_classified,
            state=state,
            detector_decision=record.detector_decision,
            released=record.released,
            label=record.label,
            score=record.score,
            contains_adi=record.contains_adi,
            error=record.error,
            detector_latency_ms=record.detector_latency_ms,
            timestamp=time(),
            delivered_sha256=record.delivered_sha256,
            tool_error=record.tool_error,
            detector_name=record.detector_name,
            detector_version=record.detector_version,
            matrix_schema_version=record.matrix_schema_version,
            matrix_sha256=record.matrix_sha256,
            prev_entry_sha256=previous_hash,
            entry_schema_version=_ENTRY_SCHEMA_VERSION,
            forgery_found=record.forgery_found,
            schema_ok=record.schema_ok,
            parse_health=record.parse_health,
            decided_by=record.decided_by,
        )
        self.ledger.append(replace(entry, entry_sha256=_ledger_entry_hash(entry)))
        self._event_seq = event_seq

    def export_ledger(self, path: str | Path) -> None:
        with self._lock:
            rows = [asdict(entry) for entry in self.ledger]
        _write_jsonl(path, rows)

    def export_raw_payloads(self, path: str | Path) -> None:
        """Export raw detector inputs separately from the state-change ledger."""
        with self._lock:
            rows = [asdict(payload) for payload in self.raw_payloads]
        _write_jsonl(path, rows)

    def export_run_metadata(self, path: str | Path) -> None:
        """Export run-level metadata separately from interception events."""
        with self._lock:
            rows = [
                {"run_id": run_id, "metadata": deepcopy(metadata)}
                for run_id, metadata in sorted(self._run_metadata.items())
            ]
        _write_jsonl(path, [_jsonable(row) for row in rows])

    @classmethod
    def import_ledger(cls, path: str | Path) -> InterceptionLedger:
        imported = cls()
        with Path(path).open(encoding="utf-8") as source:
            entries = [
                LedgerEntry(**json.loads(line))
                for line in source
                if line.strip()
            ]
        with imported._lock:
            imported.ledger.extend(entries)
            imported._event_seq = len(entries)
            for entry in entries:
                imported._seq_by_run[entry.run_id] = max(
                    imported._seq_by_run.get(entry.run_id, 0),
                    entry.interception_seq,
                )
        return imported

    def verify_chain(self) -> bool:
        with self._lock:
            if len(self.ledger) != self._event_seq:
                return False
            expected_previous = _GENESIS_ENTRY_SHA256
            for expected_seq, entry in enumerate(self.ledger, start=1):
                if entry.event_seq != expected_seq:
                    return False
                if entry.entry_schema_version != _ENTRY_SCHEMA_VERSION:
                    return False
                if entry.prev_entry_sha256 != expected_previous:
                    return False
                if entry.entry_sha256 != _ledger_entry_hash(entry):
                    return False
                expected_previous = entry.entry_sha256
            return True

    def clear(self) -> None:
        with self._lock:
            self.records.clear()
            self.ledger.clear()
            self.raw_payloads.clear()
            self._seq_by_run.clear()
            self._records_by_id.clear()
            self._raw_payload_index.clear()
            self._run_metadata.clear()
            self._event_seq = 0
            self._persisted_entries = 0
            self._persisted_payloads = 0
            self._files_started = False       # next persist truncates the files
            self._persist_locked()
            self._persist_metadata_locked()

    def _persist_locked(self) -> None:
        """Append only what is new since the last call (linear cost per run)."""
        if self.storage_dir is None:
            return
        mode = "a" if self._files_started else "w"
        _write_jsonl(self.storage_dir / "ledger.jsonl",
                     [asdict(entry) for entry in self.ledger[self._persisted_entries:]], mode)
        _write_jsonl(self.storage_dir / "raw-payloads.jsonl",
                     [asdict(payload) for payload in self.raw_payloads[self._persisted_payloads:]], mode)
        self._persisted_entries = len(self.ledger)
        self._persisted_payloads = len(self.raw_payloads)
        if not self._files_started:
            self._files_started = True
            self._persist_metadata_locked()

    def _persist_metadata_locked(self) -> None:
        if self.storage_dir is None:
            return
        target = self.storage_dir / "run-metadata.jsonl"
        temporary = target.with_suffix(target.suffix + ".tmp")
        _write_jsonl(temporary, [
            _jsonable({"run_id": run_id, "metadata": deepcopy(metadata)})
            for run_id, metadata in sorted(self._run_metadata.items())
        ])
        temporary.replace(target)


def _payload_hash(payload: DetectorPayload) -> str:
    return text_sha256(payload if isinstance(payload, str) else canonical_json(payload))


def _ledger_entry_hash(entry: LedgerEntry) -> str:
    data = asdict(entry)
    data.pop("entry_sha256", None)
    canonical = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def _jsonable(value: Any) -> Any:
    """Plain JSON data for any value (sets, bytes, NaN, models... never raise)."""
    return json.loads(canonical_json(value))


def _write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]], mode: str = "w") -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # backslashreplace: a lone surrogate inside a payload must not abort the write
    with destination.open(mode, encoding="utf-8", errors="backslashreplace", newline="\n") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            output.write("\n")
