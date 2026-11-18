"""Index result values and link proposed arguments to earlier run sources."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Sequence
import unicodedata
from urllib.parse import unquote

from parser.models import ParsedField, Trust
from trust_graph.tagging import (
    Evidence,
    FieldTag,
    LineageStatus,
    Provenance,
    trust_for,
)

_IDENTIFIER_FLANK = frozenset("._+-")


def normalise(value: str) -> str:
    """Decode percent encoding once, apply Unicode NFKC and casefold, then strip."""
    return unicodedata.normalize("NFKC", unquote(value)).casefold().strip()


def index_values(
    tags: Sequence[FieldTag],
    fields: Sequence[ParsedField],
    run_state: Any,
    *,
    batch_id: int | None = None,
) -> None:
    """Index result tags and their SYSTEM/EXTERNAL string leaves in RunState."""
    run_state.add_result_tags(list(tags), list(fields), batch_id)


def link_arguments(
    tags: Sequence[FieldTag],
    fields: Sequence[ParsedField],
    run_state: Any,
    *,
    batch_id: int | None = None,
) -> list[FieldTag]:
    """Return argument tags with prompt/external lineage attached per string leaf.

    Prompt and source matches are evidence only. A USER_MATCH does not itself
    establish that the requested action is authorized.
    """
    field_by_path = {field.path: field for field in fields}
    prompt = normalise(run_state.user_prompt or "")
    earlier_values = tuple(
        value for value in run_state.values
        if batch_id is None or (value.batch_id is not None and value.batch_id < batch_id)
    )
    output: list[FieldTag] = []
    for tag in tags:
        source = field_by_path.get(tag.path)
        if source is None or source.value_type != "string" or not isinstance(source.value, str):
            output.append(replace(tag, lineage_status=LineageStatus.UNLINKED,
                                  provenance=Provenance.DERIVED, trust=Trust.UT))
            continue
        candidate = normalise(source.value)
        if len(candidate) < run_state.min_length:
            output.append(replace(tag, lineage_status=LineageStatus.BELOW_MIN,
                                  provenance=Provenance.DERIVED, trust=Trust.UT))
            continue
        if prompt and _contains(prompt, candidate):
            output.append(replace(tag, lineage_status=LineageStatus.USER_MATCH,
                                  provenance=Provenance.USER,
                                  trust=trust_for(Provenance.USER)))
            continue
        system_match = next((
            value for value in reversed(earlier_values)
            if value.provenance == Provenance.SYSTEM.value
            and candidate == value.normalized_value
        ), None)
        if system_match is not None:
            output.append(replace(
                tag, lineage_status=LineageStatus.SYSTEM_LINK,
                provenance=Provenance.DERIVED, trust=Trust.T,
                derived_from=(Evidence(
                    source_tag_id=system_match.source_tag_id,
                    match_type="equal", matched_length=len(candidate),
                    source_provenance=Provenance.SYSTEM,
                ),),
            ))
            continue
        external_match = next((
            (value, match_type)
            for value in reversed(earlier_values)
            if value.provenance == Provenance.EXTERNAL.value
            for match_type in (
                ("equal",) if candidate == value.normalized_value
                else ("substring",)
            )
            if _contains(value.normalized_value, candidate)
        ), None)
        if external_match is not None:
            value, match_type = external_match
            output.append(replace(tag, lineage_status=LineageStatus.EXTERNAL_LINK,
                                  provenance=Provenance.DERIVED, trust=Trust.UT,
                                  derived_from=(Evidence(
                                      source_tag_id=value.source_tag_id,
                                      match_type=match_type,
                                      matched_length=len(candidate),
                                      source_provenance=Provenance.EXTERNAL,
                                  ),)))
        else:
            output.append(replace(tag, lineage_status=LineageStatus.UNLINKED,
                                  provenance=Provenance.DERIVED, trust=Trust.UT))
    run_state.record_argument_tags(list(output))
    return output


def _contains(haystack: str, needle: str) -> bool:
    if not needle:
        return False
    start = 0
    while (index := haystack.find(needle, start)) >= 0:
        end = index + len(needle)
        left = haystack[index - 1] if index else ""
        right = haystack[end] if end < len(haystack) else ""
        left_ok = not left or not (left.isalnum() or left in _IDENTIFIER_FLANK)
        right_ok = not right or not (right.isalnum() or right in _IDENTIFIER_FLANK)
        if left_ok and right_ok:
            return True
        start = index + 1
    return False
