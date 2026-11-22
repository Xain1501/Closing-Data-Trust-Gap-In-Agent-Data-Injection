"""Index result values and link proposed arguments to earlier run sources."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Sequence
import re
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
    snapshot = (run_state.snapshot_values() if hasattr(run_state, "snapshot_values")
                else tuple(run_state.values))
    # A value indexed without a batch number (a direct check_result) is treated as
    # earlier; only a value known to be from the same or a later batch is excluded.
    earlier_values = tuple(
        value for value in snapshot
        if batch_id is None or value.batch_id is None or value.batch_id < batch_id
    )
    output: list[FieldTag] = []
    for tag in tags:
        source = field_by_path.get(tag.path)
        if (source is not None and source.value_type == "number"
                and isinstance(source.value, (int, float)) and not isinstance(source.value, bool)):
            output.append(_link_number(tag, source.value, prompt, earlier_values))
            continue
        if source is None or source.value_type != "string" or not isinstance(source.value, str):
            output.append(replace(tag, lineage_status=LineageStatus.UNLINKED,
                                  provenance=Provenance.DERIVED, trust=Trust.UT))
            continue
        candidate = normalise(source.value)
        if len(candidate) < run_state.min_length:
            output.append(replace(tag, lineage_status=LineageStatus.BELOW_MIN,
                                  provenance=Provenance.DERIVED, trust=Trust.UT))
            continue
        if prompt and _grounds(candidate) and _contains(prompt, candidate):
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
                    source_has_forgery=system_match.has_forgery,
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
                                      source_has_forgery=value.has_forgery,
                                  ),)))
        else:
            output.append(replace(tag, lineage_status=LineageStatus.UNLINKED,
                                  provenance=Provenance.DERIVED, trust=Trust.UT))
    run_state.record_argument_tags(list(output))
    return output


_NUMBER_IN_TEXT = re.compile(r"(?<![\w.])-?\d+(?:[.,]\d+)?(?!\w)")
_MIN_NUMBER_DIGITS = 3


def _grounds(candidate: str) -> bool:
    """Whether a prompt match can ground this value. A single plain word shorter than
    8 letters ("send", "today") appears in many prompts and proves nothing; names,
    ids, addresses, numbers and multi-word values can."""
    return len(candidate) >= 8 or not candidate.isalpha()


def _link_number(tag: FieldTag, value: float | int, prompt: str, earlier: tuple) -> FieldTag:
    """Number arguments: same evidence as strings, compared by numeric value."""
    from provenance.run_state import number_key

    key = number_key(value)
    if len(key.replace("-", "").replace(".", "")) < _MIN_NUMBER_DIGITS:
        return replace(tag, lineage_status=LineageStatus.BELOW_MIN,
                       provenance=Provenance.DERIVED, trust=Trust.UT)
    prompt_numbers = {number_key(float(m.replace(",", "."))) for m in _NUMBER_IN_TEXT.findall(prompt)}
    if key in prompt_numbers:
        return replace(tag, lineage_status=LineageStatus.USER_MATCH,
                       provenance=Provenance.USER, trust=trust_for(Provenance.USER))
    for wanted, status, trust in ((Provenance.SYSTEM, LineageStatus.SYSTEM_LINK, Trust.T),
                                  (Provenance.EXTERNAL, LineageStatus.EXTERNAL_LINK, Trust.UT)):
        match = next((v for v in reversed(earlier)
                      if v.provenance == wanted.value and v.normalized_value == key), None)
        if match is not None:
            return replace(tag, lineage_status=status, provenance=Provenance.DERIVED, trust=trust,
                           derived_from=(Evidence(source_tag_id=match.source_tag_id,
                                                  match_type="equal", matched_length=len(key),
                                                  source_provenance=wanted,
                                                  source_has_forgery=match.has_forgery),))
    return replace(tag, lineage_status=LineageStatus.UNLINKED,
                   provenance=Provenance.DERIVED, trust=Trust.UT)


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
