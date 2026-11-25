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
DEFAULT_ATTACKS = (ROOT / "out/attack_traces_raw",)
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


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        found_text = False
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if not isinstance(text, str):
                text = item.get("content")
            if isinstance(text, str):
                found_text = True
                parts.append(text)
        if found_text:
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
    batches: dict[str, tuple[str, int]] = {}
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
            batch_id = event.get("batch_id")
            if batch_id is None:
                next_batch += 1
                batch_id = next_batch
            elif isinstance(batch_id, bool) or not isinstance(batch_id, int) or batch_id < 1:
                raise ValueError(f"{interception_id}: batch_id must be a positive integer")
            else:
                next_batch = max(next_batch, batch_id)
            if call_id in batches:
                raise ValueError(f"{interception_id}: duplicate tool call id")
            batches[call_id] = (tool, batch_id)
            output.append(_TraceEvent(
                "pre", tool, call_id, interception_id, batch_id, args=args,
            ))
        else:
            call_context = batches.get(call_id)
            if call_context is None:
                raise ValueError(f"{interception_id}: post event has no earlier call")
            source_tool, batch_id = call_context
            if tool != source_tool:
                raise ValueError(f"{interception_id}: post event tool does not match its call")
            event_batch = event.get("batch_id")
            if event_batch is not None:
                if isinstance(event_batch, bool) or not isinstance(event_batch, int):
                    raise ValueError(f"{interception_id}: batch_id must be an integer")
                if event_batch != batch_id:
                    raise ValueError(f"{interception_id}: pre/post batch_id mismatch")
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
                tool = call.get("name")
                function = call.get("function")
                if not tool and isinstance(function, str):
                    tool = function
                elif not tool and isinstance(function, dict):
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
            text = _content_text(message.get("content", ""))
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
) -> tuple[dict[str, Any], int]:
    prompt = trace.get("user_prompt")
    if not isinstance(prompt, str):
        prompt = next((
            _content_text(message.get("content", ""))
            for message in trace.get("messages", [])
            if isinstance(message, dict) and message.get("role") in ("human", "user")
        ), "")

    states = RunStateStore()
    groups = []
    finding_groups = []
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
        state = states.get(run_id)
        graph = build_trace_graph(groups, finding_groups,
                                  mentions=tuple(state.mentions) if state is not None else ())
    finally:
        states.end_run(run_id)

    pre_calls = sum(event.direction == "pre" for event in events)
    return {"node_labels": graph.node_labels, "edges": [list(edge) for edge in graph.edges]}, pre_calls


def _read_trace(
    path: Path, label: Literal["benign", "attack"], matrix: TrustMatrix
) -> dict[str, Any] | None:
    try:
        trace = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(trace, dict):
            raise ValueError("trace root must be an object")
        suite = trace.get("suite") or trace.get("suite_name")
        task_id = trace.get("task_id") or trace.get("user_task_id")
        benchmark_family = trace.get("benchmark_family")
        if benchmark_family is None and isinstance(suite, str):
            benchmark_family = "agentdojo"
        if not isinstance(benchmark_family, str) or not benchmark_family:
            raise ValueError("trace must identify its benchmark_family")
        task_group_id = trace.get("task_group_id") or trace.get("group_id")
        if task_group_id is None:
            if not isinstance(task_id, str) or not task_id:
                raise ValueError("trace must identify task_id or task_group_id")
            task_group_id = ":".join(
                (benchmark_family, str(suite or "default"), task_id)
            )
        if not isinstance(task_group_id, str) or not task_group_id:
            raise ValueError("task_group_id must be a non-empty string")
        if not task_group_id.startswith(f"{benchmark_family}:"):
            task_group_id = f"{benchmark_family}:{task_group_id}"
        if suite is not None and (not isinstance(suite, str) or not suite):
            raise ValueError("suite must be a non-empty string when present")
        if task_id is not None and (not isinstance(task_id, str) or not task_id):
            raise ValueError("task_id must be a non-empty string when present")
        declared_label = trace.get("label")
        if declared_label is not None and declared_label != label:
            raise ValueError(
                f"trace declares label {declared_label!r} but was supplied as {label!r}"
            )
        if label == "attack" and not (
            trace.get("injection_task_id") or trace.get("attack_type")
            or trace.get("attack_family")
        ):
            raise ValueError("attack trace has no injection-task or attack-type metadata")
        events = _events(trace)
        if not any(event.direction == "pre" for event in events):
            return None
        resolved_path = path.resolve()
        try:
            case_id = resolved_path.relative_to(ROOT).as_posix()
        except ValueError:
            path_id = hashlib.sha256(str(resolved_path).encode("utf-8")).hexdigest()[:16]
            case_id = f"external/{path_id}/{path.name}"
        group_id = task_group_id
        run_id = str(trace.get("run_id") or case_id)
        graph, call_count = _trace_graph(trace, events, matrix, run_id)
        attack_family = trace.get("attack_family")
        if attack_family is None and label == "attack":
            attack_family = trace.get("attack_type")
        if attack_family is not None and (
            not isinstance(attack_family, str) or not attack_family
        ):
            raise ValueError("attack_family must be a non-empty string when present")
        benchmark_version = trace.get("benchmark_version")
        if benchmark_version is not None and (
            not isinstance(benchmark_version, str) or not benchmark_version
        ):
            raise ValueError("benchmark_version must be a non-empty string when present")
        attack_success = (
            trace.get("attack_success")
            if isinstance(trace.get("attack_success"), bool)
            else trace.get("security")
            if isinstance(trace.get("security"), bool)
            else None
        )
        return {
            "case_id": case_id,
            "trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "label": label,
            "classification_unit": "run",
            "source": trace.get("pipeline_name") or trace.get("source"),
            "benchmark_family": benchmark_family,
            "attack_family": attack_family,
            "benchmark_version": benchmark_version,
            "collection_mode": trace.get("collection_mode") or trace.get("source"),
            "matched_pair_id": trace.get("matched_pair_id"),
            "call_sequence_sha256": trace.get("call_sequence_sha256"),
            "injection_condition": trace.get("injection_condition"),
            "label_basis": trace.get("label_basis") or (
                "injection_present"
                if label == "attack" and (
                    trace.get("injection_task_id") or trace.get("injections")
                )
                else "attack_trace_membership" if label == "attack"
                else "clean_trace_membership"
            ),
            "suite": suite,
            "task_id": task_id,
            "attack_type": trace.get("attack_type"),
            "attack_success": attack_success,
            "attack_success_source": (
                trace.get("attack_success_source")
                or ("source_agentdojo_trace" if isinstance(trace.get("security"), bool) else None)
            ),
            "group_id": group_id,
            "graph": graph,
            "tool_calls": call_count,
            "text_derived": any(event.text_derived for event in events if event.direction == "post"),
        }
    except Exception as exc:
        raise ValueError(f"invalid trace at {path}: {exc}") from exc


def _split_groups(
    rows: list[dict[str, Any]],
    *,
    holdout_benchmark_families: tuple[str, ...] = (),
    holdout_attack_families: tuple[str, ...] = (),
    holdout_sources: tuple[str, ...] = (),
) -> dict[str, str]:
    group_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        group_rows[row["group_id"]].append(row)
    assignments = {}
    for group, members in group_rows.items():
        is_held_out_benchmark = any(
            row["benchmark_family"] in holdout_benchmark_families
            for row in members
        )
        is_held_out_attack = any(
            row["label"] == "attack" and row.get("attack_family") in holdout_attack_families
            for row in members
        )
        is_held_out_source = any(
            row.get("source") in holdout_sources for row in members
        )
        assignments[group] = (
            "test"
            if is_held_out_benchmark or is_held_out_attack or is_held_out_source
            or int.from_bytes(hashlib.sha256(group.encode()).digest()[:4], "big") % 5 == 0
            else "train"
        )
    return assignments


def _validate_matched_pairs(
    rows: list[dict[str, Any]], *, require_matched_pairs: bool
) -> None:
    matched_pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        pair_id = row.get("matched_pair_id")
        if pair_id:
            matched_pairs[pair_id].append(row)
    for pair_id, pair_rows in matched_pairs.items():
        if len({row["group_id"] for row in pair_rows}) != 1:
            raise ValueError(f"matched pair {pair_id} crosses task groups")
        call_sequence_hashes = {
            row.get("call_sequence_sha256")
            for row in pair_rows
            if row.get("call_sequence_sha256")
        }
        if len(call_sequence_hashes) > 1:
            raise ValueError(f"matched pair {pair_id} has different tool-call sequences")
        if require_matched_pairs and (
            len(pair_rows) != 2
            or {row["label"] for row in pair_rows} != {"benign", "attack"}
            or len(call_sequence_hashes) != 1
        ):
            raise ValueError(
                f"matched pair {pair_id} must have one benign and one attack trace "
                "with the same recorded tool-call sequence"
            )
    if require_matched_pairs and not matched_pairs:
        raise ValueError("no matched benign/attack counterfactual pairs were found")


def build_dataset(
    benign_paths: tuple[Path, ...] = DEFAULT_BENIGN,
    attack_paths: tuple[Path, ...] = DEFAULT_ATTACKS,
    suites: tuple[str, ...] = DEFAULT_SUITES,
    *,
    allow_text_derived_mix: bool = False,
    required_benchmark_families: tuple[str, ...] = (),
    required_attack_families: tuple[str, ...] = (),
    holdout_benchmark_families: tuple[str, ...] = (),
    holdout_attack_families: tuple[str, ...] = (),
    holdout_sources: tuple[str, ...] = (),
    require_matched_pairs: bool = False,
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
    if suites:
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
    benchmark_families_in_data = {row["benchmark_family"] for row in rows}
    attack_families_in_data = {
        row["attack_family"] for row in rows if row.get("attack_family")
    }
    sources_in_data = {row.get("source") for row in rows if row.get("source")}
    missing_holdouts = (
        set(holdout_benchmark_families) - benchmark_families_in_data
    ) | (set(holdout_attack_families) - attack_families_in_data) | (
        set(holdout_sources) - sources_in_data
    )
    if missing_holdouts:
        raise ValueError(
            "requested holdout values are absent from filtered data: "
            + ", ".join(sorted(missing_holdouts))
        )
    _validate_matched_pairs(rows, require_matched_pairs=require_matched_pairs)

    assignments = _split_groups(
        rows,
        holdout_benchmark_families=holdout_benchmark_families,
        holdout_attack_families=holdout_attack_families,
        holdout_sources=holdout_sources,
    )
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
    family_counts = Counter(str(row["benchmark_family"]) for row in rows)
    attack_family_counts = Counter(
        str(row["attack_family"]) for row in rows if row.get("attack_family")
    )
    missing_families = sorted(set(required_benchmark_families) - set(family_counts))
    if missing_families:
        raise ValueError(
            "required benchmark families are missing: " + ", ".join(missing_families)
        )
    missing_attack_families = sorted(set(required_attack_families) - set(attack_family_counts))
    if missing_attack_families:
        raise ValueError(
            "required attack families are missing: " + ", ".join(missing_attack_families)
        )
    for family, count in sorted(family_counts.items()):
        counts[f"family:{family}"] = count
    for family, count in sorted(attack_family_counts.items()):
        counts[f"attack_family:{family}"] = count
    for row in rows:
        for dimension, value in (
            ("benchmark_label", f"{row['benchmark_family']}:{row['split']}:{row['label']}"),
            ("source_label", f"{row.get('source') or 'unknown'}:{row['split']}:{row['label']}"),
            ("collection_label", f"{row.get('collection_mode') or 'unknown'}:{row['label']}"),
            ("label_basis", f"{row['label_basis']}:{row['label']}"),
        ):
            counts[f"{dimension}:{value}"] += 1
    return rows, dict(counts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-traces", nargs="+", type=Path, default=list(DEFAULT_BENIGN))
    parser.add_argument("--attack-runs", nargs="+", type=Path, default=list(DEFAULT_ATTACKS))
    parser.add_argument("--suites", nargs="+", default=list(DEFAULT_SUITES))
    parser.add_argument(
        "--all-suites", action="store_true",
        help="include traces from any suite (requires benchmark/task metadata)",
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "runs/wl_svm")
    parser.add_argument(
        "--allow-text-derived-mix", action="store_true",
        help="allow exploratory datasets that mix real raw objects and text-derived results",
    )
    parser.add_argument(
        "--require-benchmark-family", action="append", default=[],
        help="require a family such as agentdojo or adi to be present (repeatable)",
    )
    parser.add_argument(
        "--require-attack-family", action="append", default=[],
        help="require an attack family such as data_only_syntactic to be present",
    )
    parser.add_argument(
        "--holdout-benchmark-family", action="append", default=[],
        help="force all groups from this benchmark family into test (repeatable)",
    )
    parser.add_argument(
        "--holdout-attack-family", action="append", default=[],
        help="force all groups containing this attack family into test (repeatable)",
    )
    parser.add_argument(
        "--holdout-source", action="append", default=[],
        help="force all groups from this collection source into test (repeatable)",
    )
    parser.add_argument(
        "--require-matched-pairs", action="store_true",
        help="require exactly one clean and one injected trace per matched_pair_id",
    )
    args = parser.parse_args()
    rows, counts = build_dataset(
        tuple(args.benign_traces),
        tuple(args.attack_runs),
        () if args.all_suites else tuple(args.suites),
        allow_text_derived_mix=args.allow_text_derived_mix,
        required_benchmark_families=tuple(args.require_benchmark_family),
        required_attack_families=tuple(args.require_attack_family),
        holdout_benchmark_families=tuple(args.holdout_benchmark_family),
        holdout_attack_families=tuple(args.holdout_attack_family),
        holdout_sources=tuple(args.holdout_source),
        require_matched_pairs=args.require_matched_pairs,
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
        "schema_version": 2,
        "classification_unit": "run",
        "suites": list(args.suites),
        "all_suites": args.all_suites,
        "holdout_benchmark_families": args.holdout_benchmark_family,
        "holdout_attack_families": args.holdout_attack_family,
        "holdout_sources": args.holdout_source,
        "requires_matched_pairs": args.require_matched_pairs,
        "label_semantics": (
            "attack indicates an injected/attack trace, not that the attack succeeded"
        ),
        "counts": counts,
        "traces": [
            {
                "case_id": row["case_id"],
                "label": row["label"],
                "benchmark_family": row.get("benchmark_family"),
                "attack_family": row.get("attack_family"),
                "benchmark_version": row.get("benchmark_version"),
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
