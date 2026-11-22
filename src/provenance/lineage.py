"""Index result values and link proposed arguments to earlier run sources."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Sequence
import html
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
# Look-alike letters (Cyrillic, Greek) mapped to Latin after NFKC.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
    "τ": "t", "ι": "i", "κ": "k",
})
_STRIP = re.compile(r"[\s\-_.,:;/\\()\[\]'\"]+")
_MAX_EVIDENCE = 20


def normalise(value: str) -> str:
    """Percent / HTML decoding (repeated, at most 3 rounds), Unicode NFKC, look-alike
    letters mapped to Latin, casefold, strip."""
    text = value
    for _ in range(3):
        decoded = html.unescape(unquote(text))
        if decoded == text:
            break
        text = decoded
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES).casefold().strip()


def stripped(normalised: str) -> str:
    """A normalised value without spaces, dashes or punctuation (IBAN groups, phone formats)."""
    return _STRIP.sub("", normalised)


def _identifier_like(value: str) -> bool:
    """Values that almost never occur by chance: IBAN, email, URL, long tokens with digits."""
    return ("@" in value or value.startswith(("http://", "https://", "www."))
            or (len(value) >= 8 and any(ch.isdigit() for ch in value)))


def index_values(
    tags: Sequence[FieldTag],
    fields: Sequence[ParsedField],
    run_state: Any,
    *,
    batch_id: int | None = None,
) -> None:
    """Index result tags, their SYSTEM/EXTERNAL leaves and the result's mentions in RunState."""
    run_state.add_result_tags(list(tags), list(fields), batch_id)
    if hasattr(run_state, "add_mentions"):
        run_state.add_mentions(list(tags), list(fields))


def link_arguments(
    tags: Sequence[FieldTag],
    fields: Sequence[ParsedField],
    run_state: Any,
    *,
    batch_id: int | None = None,
) -> list[FieldTag]:
    """Attach lineage to argument tags. Every matching source is recorded, with its
    match strength and its forgery / mimicry flags; the status names the strongest
    trusted source (user > SYSTEM > EXTERNAL) and ``untrusted_also`` says an untrusted
    or flagged source holds the value too. Evidence only: a USER_MATCH does not by
    itself establish that the action is authorised."""
    field_by_path = {field.path: field for field in fields}
    prompts = getattr(run_state, "prompts", None) or [run_state.user_prompt or ""]
    prompt = normalise("\n".join(p for p in prompts if p))
    snapshot = (run_state.snapshot_values() if hasattr(run_state, "snapshot_values")
                else tuple(run_state.values))
    # A value indexed without a batch number (a direct check_result) is treated as
    # earlier; only a value known to be from the same or a later batch is excluded.
    earlier = tuple(
        value for value in snapshot
        if batch_id is None or value.batch_id is None or value.batch_id < batch_id
    )
    min_length = getattr(run_state, "min_length", 4)
    output: list[FieldTag] = []
    for tag in tags:
        source = field_by_path.get(tag.path)
        if source is not None and source.value_type in ("object", "array"):
            output.append(tag)               # containers: NOT_APPLICABLE, their leaves are linked
            continue
        if (source is not None and source.value_type == "number"
                and isinstance(source.value, (int, float)) and not isinstance(source.value, bool)):
            evidence = _number_evidence(source.value, prompt, earlier)
        elif source is not None and source.value_type == "string" and isinstance(source.value, str):
            evidence = _string_evidence(normalise(source.value), prompt, earlier, min_length)
        else:
            evidence = []
        output.append(_with_lineage(tag, evidence))
    run_state.record_argument_tags(list(output))
    return output


_STRENGTH_RANK = {"whole_field": 0, "token": 1, "fragment": 2}


def _strength(stored: Any, whole: bool) -> str:
    if not whole:
        return "fragment"
    return "token" if (".@tok[" in stored.source_path or ".@col[" in stored.source_path) else "whole_field"


def _evidence(stored: Any, match_type: str, strength: str, form: str, length: int) -> Evidence:
    return Evidence(
        source_tag_id=stored.source_tag_id, match_type=match_type, matched_length=length,
        source_provenance=Provenance(stored.provenance), source_has_forgery=stored.has_forgery,
        source_has_mimicry=getattr(stored, "has_mimicry", False),
        source_leaf_forged=getattr(stored, "leaf_forged", False),
        match_strength=strength, match_form=form,
    )


def _user_evidence(length: int, strength: str = "whole_field", form: str = "equal") -> Evidence:
    return Evidence(source_tag_id=None, match_type="equal", matched_length=length,
                    source_provenance=Provenance.USER, match_strength=strength, match_form=form)


def _string_evidence(candidate: str, prompt: str, earlier: tuple, min_length: int) -> list[Evidence]:
    if not candidate:
        return []
    cand_stripped = stripped(candidate)
    short = len(candidate) < min_length
    ident = _identifier_like(candidate)
    # Grouped identifiers (IBAN, phone, account numbers) may be written with spaces or
    # dashes; emails and URLs are not, and stripping them would merge distinct addresses.
    groups = ident and "@" not in candidate and "/" not in candidate
    out: list[Evidence] = []
    # The user's prompt. A single plain word shorter than 8 letters proves nothing.
    if prompt and _grounds(candidate):
        if _contains(prompt, candidate, glued_ok=ident):
            out.append(_user_evidence(len(candidate)))
        elif groups and len(cand_stripped) >= 8 and cand_stripped in stripped(prompt):
            out.append(_user_evidence(len(candidate), form="stripped"))
    for stored in reversed(earlier):
        if len(out) >= _MAX_EVIDENCE:
            break
        value = stored.normalized_value
        if candidate == value:
            out.append(_evidence(stored, "equal", _strength(stored, True), "equal", len(candidate)))
        elif (len(cand_stripped) >= min_length and stored.stripped_value
              and cand_stripped == stored.stripped_value):
            out.append(_evidence(stored, "equal", _strength(stored, True), "stripped", len(candidate)))
        elif short:
            continue                       # short values: whole field, cell or token only
        elif ident and _contains(value, candidate, glued_ok=True):
            out.append(_evidence(stored, "substring", "fragment", "equal", len(candidate)))
        elif ident and groups and len(cand_stripped) >= 8 and cand_stripped in stored.stripped_value:
            out.append(_evidence(stored, "substring", "fragment", "stripped", len(candidate)))
        elif not ident and _contains(value, candidate):
            out.append(_evidence(stored, "substring", "fragment", "equal", len(candidate)))
    return out


def _number_evidence(value: float | int, prompt: str, earlier: tuple) -> list[Evidence]:
    from provenance.run_state import number_key

    key = number_key(value)
    out: list[Evidence] = []
    prompt_numbers = {number_key(float(m.replace(",", ""))) for m in _NUMBER_IN_TEXT.findall(prompt)
                      if m.replace(",", "").replace(".", "").lstrip("-").isdigit()}
    if key in prompt_numbers:
        out.append(_user_evidence(len(key), form="number"))
    for stored in reversed(earlier):
        if len(out) >= _MAX_EVIDENCE:
            break
        if stored.normalized_value == key or _as_number_key(stored.normalized_value) == key:
            out.append(_evidence(stored, "equal", _strength(stored, True), "number", len(key)))
    return out


_PLAIN_NUMBER = re.compile(r"^[$€£]?\s?-?\d{1,3}(?:,\d{3})*(?:\.\d+)?$|^-?\d+(?:\.\d+)?$")


def _as_number_key(text: str) -> str | None:
    """A stored text that is only a number ("98.70", "1,250.00", "$5") in canonical form."""
    from provenance.run_state import number_key

    if not text or not _PLAIN_NUMBER.match(text):
        return None
    try:
        return number_key(float(re.sub(r"[^\d.-]", "", text)))
    except ValueError:
        return None


def _with_lineage(tag: FieldTag, evidence: list[Evidence]) -> FieldTag:
    if not evidence:
        return replace(tag, lineage_status=LineageStatus.UNLINKED,
                       provenance=Provenance.DERIVED, trust=Trust.UT, derived_from=())
    evidence.sort(key=lambda e: _STRENGTH_RANK[e.match_strength])
    has = {e.source_provenance for e in evidence}
    flagged = any(e.source_has_forgery or e.source_has_mimicry or e.source_leaf_forged
                  for e in evidence)
    if Provenance.USER in has:
        status, provenance, trust = LineageStatus.USER_MATCH, Provenance.USER, trust_for(Provenance.USER)
    elif Provenance.SYSTEM in has:
        status, provenance, trust = LineageStatus.SYSTEM_LINK, Provenance.DERIVED, Trust.T
    else:
        status, provenance, trust = LineageStatus.EXTERNAL_LINK, Provenance.DERIVED, Trust.UT
    untrusted_also = status is not LineageStatus.EXTERNAL_LINK and (
        Provenance.EXTERNAL in has or flagged)
    # USER first in derived_from would hide graph sources; keep source evidence first.
    ordered = tuple(e for e in evidence if e.source_tag_id is not None) + tuple(
        e for e in evidence if e.source_tag_id is None)
    return replace(tag, lineage_status=status, provenance=provenance, trust=trust,
                   derived_from=ordered, untrusted_also=untrusted_also)


_NUMBER_IN_TEXT = re.compile(r"(?<![\w.])-?\d+(?:[.,]\d+)?(?!\w)")
_MIN_NUMBER_DIGITS = 3


def _grounds(candidate: str) -> bool:
    """Whether a prompt match can ground this value. A single plain word shorter than
    8 letters ("send", "today") appears in many prompts and proves nothing; names,
    ids, addresses, numbers and multi-word values can."""
    return len(candidate) >= 8 or not candidate.isalpha()


def _contains(haystack: str, needle: str, *, glued_ok: bool = False) -> bool:
    """Whole-value occurrence. ``glued_ok`` (identifiers that are not emails, such as
    IBANs and long tokens): letters or digits right next to the value are allowed, so
    "...1212Thank you" still matches; identifier punctuation ("._+-@") never is, so
    bob@x.com does not match evil.bob@x.com."""
    if not needle:
        return False
    if glued_ok and "@" not in needle:
        start = 0
        while (index := haystack.find(needle, start)) >= 0:
            end = index + len(needle)
            left = haystack[index - 1] if index else ""
            right = haystack[end] if end < len(haystack) else ""
            if left not in _IDENTIFIER_FLANK | {"@"} and right not in _IDENTIFIER_FLANK | {"@"}:
                return True
            start = index + 1
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
