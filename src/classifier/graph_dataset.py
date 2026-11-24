"""Build deterministic, run-level graph JSONL from labeled AgentDojo traces."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from clone.core import DetectorContext
from clone.tvm import TrustMatrix, load_tool_matrix
from pipeline.tagging_stage import analyze_and_tag
from provenance.run_state import RunStateStore
from trust_graph import build_trace_graph

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BENIGN = (ROOT / "tests/fixtures/traces/benign",)
DEFAULT_ATTACKS = (
    ROOT / "runs/baseline_openai_gpt-oss-120b",
    ROOT / "runs/baseline_llama-3.3-70b-versatile",
)
DEFAULT_SUITES = ("travel", "workspace", "slack", "banking")


@dataclass(frozen=True)
class _TraceEvent:
    direction: Literal["pre", "post"]
    tool_name: str
    tool_call_id: str
    interception_id: str
    batch_id: int
    args: dict[str, Any] | None = None
    raw_result: Any = None
    result_text: str | None = None
    result_format: str = "json"
    text_derived: bool = False


def _json_paths(paths: tuple[Path, ...]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"trace input does not exist: {path}")
        candidates = [path] if path.is_file() else sorted(path.rglob("*.json"))
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                found.append(candidate)
                seen.add(resolved)
    if not found:
        raise ValueError("no trace JSON files found")
    return found


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            item.get("text", "")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text", ""), str)
        ]
        if parts:
            return "".join(parts)
    return json.dumps(content, ensure_ascii=False, sort_keys=True)


def _decode_result(text: str) -> tuple[Any, str]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text, "text"
    if isinstance(value, (dict, list)):
        return value, "json"
    return text, "text"


def _recorded_events(trace: dict[str, Any]) -> list[_TraceEvent]:
    events = trace.get("events")
    if not isinstance(events, list):
        raise ValueError("recorded trace must contain an events list")
    batches: dict[str, int] = {}
    output: list[_TraceEvent] = []
    next_batch = 0
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("trace event must be an object")
        direction = event.get("direction")
        tool = event.get("tool_name")
        call_id = event.get("tool_call_id")
        interception_id = event.get("interception_id")
        if direction not in ("pre", "post") or not all(
            isinstance(value, str) and value for value in (tool, call_id, interception_id)
        ):
            raise ValueError("trace event has invalid direction or identifiers")
        if direction == "pre":
            args = event.get("args")
            if not isinstance(args, dict):
                raise ValueError(f"{interception_id}: pre event args must be an object")
            next_batch += 1
            batches[call_id] = next_batch
            output.append(_TraceEvent(
                "pre", tool, call_id, interception_id, next_batch, args=args,
            ))
        else:
            batch_id = batches.get(call_id)
            if batch_id is None:
                raise ValueError(f"{interception_id}: post event has no earlier call")
            if "raw_result" not in event or not isinstance(event.get("result_text"), str):
                raise ValueError(f"{interception_id}: post event is missing its result")
            output.append(_TraceEvent(
                "post", tool, call_id, interception_id, batch_id,
                raw_result=event["raw_result"],
                result_text=event["result_text"],
                result_format=str(event.get("result_format", "json")),
                text_derived=bool(event.get("text_derived", False)),
            ))
    return output


def _benchmark_events(trace: dict[str, Any]) -> list[_TraceEvent]:
    messages = trace.get("messages")
    if not isinstance(messages, list):
        raise ValueError("benchmark trace must contain a messages list")
    output: list[_TraceEvent] = []
    calls: dict[str, tuple[str, int]] = {}
    batch_id = 0
    sequence = 0
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "assistant" and message.get("tool_calls"):
            batch_id += 1
            for call in message["tool_calls"]:
                if not isinstance(call, dict):
                    raise ValueError("assistant tool call must be an object")
                function = call.get("function")
                tool = call.get("name")
                if not tool and isinstance(function, dict):
                    tool = function.get("name")
                call_id = call.get("id")
                args = call.get("args")
                if args is None and isinstance(function, dict):
                    args = function.get("arguments")
                if isinstance(args, str):
                    args = json.loads(args)
                if not isinstance(tool, str) or not tool or not isinstance(call_id, str) or not call_id:
                    raise ValueError("assistant tool call has invalid name or id")
                if not isinstance(args, dict):
                    raise ValueError(f"{call_id}: tool arguments must be an object")
                sequence += 1
                interception_id = f"call-{sequence}"
                calls[call_id] = (tool, batch_id)
                output.append(_TraceEvent(
                    "pre", tool, call_id, interception_id, batch_id, args=args,
                ))
        elif message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or call_id not in calls:
                raise ValueError("tool result has no matching assistant call")
            tool, source_batch = calls[call_id]
            text = _result_text(message.get("content", ""))
            raw_result, result_format = _decode_result(text)
            sequence += 1
            output.append(_TraceEvent(
                "post", tool, call_id, f"result-{sequence}", source_batch,
                raw_result=raw_result, result_text=text, result_format=result_format,
                text_derived=True,
            ))
    return output


def _events(trace: dict[str, Any]) -> list[_TraceEvent]:
    if "events" in trace:
        result = _recorded_events(trace)
    else:
        result = _benchmark_events(trace)
    return result


def _matrix_entry(matrix: TrustMatrix, tool: str, argument_keys: set[str]):
    # Trust profiles are keyed by the complete argument-key set.  Do not
    # reimplement lookup with a subset fallback: two profiles may share names
    # while having different authority and impact semantics.
    return matrix.lookup(tool, argument_keys)


def _trace_graph(
    trace: dict[str, Any], events: list[_TraceEvent], matrix: TrustMatrix, run_id: str
) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
    prompt = trace.get("user_prompt")
    if not isinstance(prompt, str):
        prompt = next((
            message.get("content")
            for message in trace.get("messages", [])
            if isinstance(message, dict) and message.get("role") in ("human", "user")
            and isinstance(message.get("content"), str)
        ), "")

    states = RunStateStore()
    groups = []
    finding_groups = []
    decision_graphs: list[dict[str, Any]] = []
    entries_by_call: dict[str, Any] = {}
    try:
        for event in events:
            if event.direction == "pre":
                assert event.args is not None
                entry = _matrix_entry(matrix, event.tool_name, set(event.args))
                entries_by_call[event.tool_call_id] = entry
                payload: Any = {"tool": event.tool_name, "args": event.args}
                raw_result = None
            else:
                entry = entries_by_call.get(event.tool_call_id)
                if entry is None:
                    raise ValueError(f"{event.interception_id}: result has no call context")
                if event.result_text is None:
                    raise ValueError(f"{event.interception_id}: result text is missing")
                payload = event.result_text
                raw_result = event.raw_result

            context = DetectorContext(
                direction=event.direction,
                tool_name=event.tool_name,
                tool_call_id=event.tool_call_id,
                matrix_entry=entry,
                run_id=run_id,
                raw_result=raw_result,
                result_format=event.result_format,
                interception_id=event.interception_id,
                user_prompt=prompt,
                batch_id=event.batch_id,
            )
            tagged = analyze_and_tag(payload, context, states)
            groups.append(tagged.tags)
            finding_groups.append(tagged.analysis.structural.findings)
            point = build_trace_graph(
                groups, finding_groups,
                mentions=tuple(states.get(run_id).mentions) if states.get(run_id) is not None else (),
            )
            decision_graphs.append({
                "interception_id": event.interception_id,
                "direction": event.direction,
                "node_labels": point.node_labels,
                "edges": [list(edge) for edge in point.edges],
            })
        state = states.get(run_id)
        graph = build_trace_graph(groups, finding_groups,
                                  mentions=tuple(state.mentions) if state is not None else ())
    finally:
        states.end_run(run_id)

    pre_calls = sum(event.direction == "pre" for event in events)
    return {
        "node_labels": graph.node_labels,
        "edges": [list(edge) for edge in graph.edges],
    }, pre_calls, decision_graphs


def _read_trace(
    path: Path, label: Literal["benign", "attack"], matrix: TrustMatrix
) -> dict[str, Any] | None:
    try:
        trace = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(trace, dict):
            raise ValueError("trace root must be an object")
        suite = trace.get("suite") or trace.get("suite_name")
        task_id = trace.get("task_id") or trace.get("user_task_id")
        if not isinstance(suite, str) or not isinstance(task_id, str):
            raise ValueError("trace must identify its suite and user task")
        if label == "attack" and not (
            trace.get("injection_task_id") or trace.get("attack_type")
        ):
            raise ValueError("attack trace has no injection-task or attack-type metadata")
        events = _events(trace)
        if not any(event.direction == "pre" for event in events):
            return None
        case_id = path.resolve().relative_to(ROOT).as_posix()
        group_id = f"agentdojo:{suite}:{task_id}"
        run_id = str(trace.get("run_id") or case_id)
        graph, call_count, decision_graphs = _trace_graph(trace, events, matrix, run_id)
        return {
            "case_id": case_id,
            "trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "label": label,
            "source": trace.get("pipeline_name") or trace.get("source"),
            "suite": suite,
            "task_id": task_id,
            "attack_type": trace.get("attack_type"),
            "attack_success": trace.get("security") if isinstance(trace.get("security"), bool) else None,
            "group_id": group_id,
            "graph": graph,
            "tool_calls": call_count,
            "decision_graphs": decision_graphs,
            "text_derived": any(event.text_derived for event in events if event.direction == "post"),
        }
    except Exception as exc:
        raise ValueError(f"invalid trace at {path}: {exc}") from exc


def _split_groups(rows: list[dict[str, Any]]) -> dict[str, str]:
    group_labels: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        group_labels[row["group_id"]].add(row["label"])
    return {
        group: (
            "test"
            if int.from_bytes(hashlib.sha256(group.encode()).digest()[:4], "big") % 5 == 0
            else "train"
        )
        for group in group_labels
    }


def build_dataset(
    benign_paths: tuple[Path, ...] = DEFAULT_BENIGN,
    attack_paths: tuple[Path, ...] = DEFAULT_ATTACKS,
    suites: tuple[str, ...] = DEFAULT_SUITES,
    *,
    allow_text_derived_mix: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    matrix = load_tool_matrix()
    benign_files = _json_paths(benign_paths)
    attack_files = _json_paths(attack_paths)
    rows = []
    skipped_no_tool_calls = 0
    for paths, label in ((benign_files, "benign"), (attack_files, "attack")):
        for path in paths:
            row = _read_trace(path, label, matrix)
            if row is None:
                skipped_no_tool_calls += 1
            else:
                rows.append(row)
    rows = [row for row in rows if row["suite"] in suites]
    if not rows or not any(row["label"] == "attack" for row in rows):
        raise ValueError(f"no labeled traces found for requested suites: {suites}")
    origins = {bool(row["text_derived"]) for row in rows}
    if len(origins) > 1 and not allow_text_derived_mix:
        raise ValueError(
            "dataset mixes real-object and text-derived traces; record attack runs "
            "through the clone executor or pass allow_text_derived_mix=True for an "
            "explicit exploratory run"
        )

    assignments = _split_groups(rows)
    for row in rows:
        row["split"] = assignments[row["group_id"]]

    counts = Counter(f"{row['split']}:{row['label']}" for row in rows)
    if any(counts[f"train:{label}"] < 2 for label in ("benign", "attack")):
        raise ValueError(f"training split needs at least two traces per class: {dict(counts)}")
    if any(counts[f"test:{label}"] < 1 for label in ("benign", "attack")):
        raise ValueError(f"test split needs both classes: {dict(counts)}")
    if any(
        len({row["split"] for row in rows if row["group_id"] == group}) != 1
        for group in assignments
    ):
        raise ValueError("a trace group appears in more than one split")
    if skipped_no_tool_calls:
        counts["skipped:no_tool_calls"] = skipped_no_tool_calls
    counts["text_derived"] = sum(bool(row["text_derived"]) for row in rows)
    counts["real_object"] = len(rows) - counts["text_derived"]
    return rows, dict(counts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-traces", nargs="+", type=Path, default=list(DEFAULT_BENIGN))
    parser.add_argument("--attack-runs", nargs="+", type=Path, default=list(DEFAULT_ATTACKS))
    parser.add_argument("--suites", nargs="+", default=list(DEFAULT_SUITES))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "runs/wl_svm")
    parser.add_argument(
        "--allow-text-derived-mix", action="store_true",
        help="allow exploratory datasets that mix real raw objects and text-derived results",
    )
    args = parser.parse_args()
    rows, counts = build_dataset(
        tuple(args.benign_traces),
        tuple(args.attack_runs),
        tuple(args.suites),
        allow_text_derived_mix=args.allow_text_derived_mix,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for split in ("train", "test"):
        path = args.output_dir / f"graphs_{split}.jsonl"
        selected = [row for row in rows if row["split"] == split]
        path.write_text(
            "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in selected),
            encoding="utf-8",
        )
        print(f"{split}: {len(selected)} traces -> {path}")
    manifest = {
        "schema_version": 1,
        "suites": list(args.suites),
        "counts": counts,
        "traces": [
            {
                "case_id": row["case_id"],
                "label": row["label"],
                "trace_sha256": row["trace_sha256"],
            }
            for row in sorted(rows, key=lambda item: item["case_id"])
        ],
    }
    (args.output_dir / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({"counts": counts, "total": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
