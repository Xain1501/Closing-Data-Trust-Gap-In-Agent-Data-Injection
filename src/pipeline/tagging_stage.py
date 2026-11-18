"""Run parser analysis, provenance tagging, and per-run value lineage."""
from __future__ import annotations

from dataclasses import dataclass
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

    Tool-matrix authority arguments affect roles only. Result leaves default to
    EXTERNAL and containers to SYSTEM; callers may supply an approved path
    profile explicitly. Automatic profile loading is not wired yet.
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
        fields = (ParsedField(
            path="$", key=None, parent_path=None, depth=0,
            value_type=value_type, value=value,
        ),)
    tags = tag_fields(
        direction=context.direction,
        tool_name=context.tool_name,
        fields=fields,
        profile_entry=profile_entry,
        run_state=state,
        interception_id=context.interception_id,
        authority_arguments=authority_arguments,
        batch_id=context.batch_id,
        result_format=context.result_format,
        findings=analysis.structural.findings,
    )
    return TaggingResult(analysis, tuple(tags), state)
