"""Run parser analysis, provenance tagging, and per-run value lineage."""
from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from uuid import uuid4

from clone.core import DetectorContext
from clone.ledger import DetectorPayload
from parser.models import ParsedField
from pipeline.parser_analysis import ParserAnalysis, analyze_clone_payload
from provenance.run_state import RunState, RunStateStore
from trust_graph.tagging import FieldTag, ProfileEntry, tag_fields


@dataclass(frozen=True)
class TaggingResult:
    analysis: ParserAnalysis
    tags: tuple[FieldTag, ...]
    run_state: RunState


def analyze_and_tag(
    payload: DetectorPayload,
    context: DetectorContext,
    run_states: RunStateStore,
    *,
    profile_entry: ProfileEntry | None = None,
) -> TaggingResult:
    """Tag true result-object fields when available, otherwise parser fields.

    Tool-matrix authority arguments affect roles only. String leaves default to
    EXTERNAL; containers, numbers, booleans and nulls to SYSTEM. A matrix entry
    whose profile is approved is applied automatically (a draft one never is).
    """
    analysis = analyze_clone_payload(payload, context)
    run_id = context.run_id or f"ephemeral:{context.interception_id or context.tool_call_id or uuid4()}"
    if context.run_id:
        state = run_states.get_or_create(run_id, context.user_prompt)
    else:
        # Direct detector calls without clone run metadata cannot establish
        # cross-call lineage and must not leave one-off state in a global store.
        state = RunState(run_id=run_id, user_prompt=context.user_prompt, blind=True)
    if not analysis.inspectable or (
        analysis.skeleton is not None and analysis.skeleton.status == "too_large"
    ):
        state.blind = True
    entry = context.matrix_entry
    authority_arguments = entry.authority_arguments if entry is not None else ()
    if profile_entry is None and entry is not None and getattr(entry, "review_status", None) == "approved":
        profile_entry = entry.profile()
    fields: tuple[ParsedField, ...] = analysis.true_fields
    if context.direction == "post" and context.result_format == "text":
        # A scalar/string tool response has no trusted object boundaries. The
        # text parser may interpret JSON-looking text as a tree, so keep the
        # original result as one opaque leaf for both tagging and lineage.
        value = context.raw_result
        if isinstance(value, bool):
            value_type = "boolean"
        elif isinstance(value, (int, float)):
            value_type = "number"
        elif value is None:
            value_type = "null"
        else:
            value = str(value)
            value_type = "string"
        inner = analysis.skeleton.inner_fields if analysis.skeleton is not None else ()
        fields = (ParsedField(
            path="$", key=None, parent_path=None, depth=0,
            value_type=value_type, value=value,
        ), *inner)
    # Core stops waiting at the deadline and decides without this detector. A late
    # detector must not index values or tags afterwards; the run is marked blind instead,
    # because a result the run state never saw leaves lineage incomplete.
    deadline = getattr(context, "deadline", None)
    late = deadline is not None and monotonic() > deadline
    if late:
        state.blind = True
    tags = tag_fields(
        direction=context.direction,
        tool_name=context.tool_name,
        fields=fields,
        profile_entry=profile_entry,
        # A throwaway state keeps tag ids and run id without touching the shared one.
        run_state=RunState(run_id=state.run_id, user_prompt=state.user_prompt, blind=True) if late else state,
        interception_id=context.interception_id,
        authority_arguments=authority_arguments,
        batch_id=context.batch_id,
        result_format=context.result_format,
        findings=[*analysis.structural.findings, *analysis.anomalies],
    )
    if not late and context.interception_id:
        with state._lock:
            state.findings_by_interception[context.interception_id] = tuple(analysis.structural.findings)
    return TaggingResult(analysis, tuple(tags), state)
