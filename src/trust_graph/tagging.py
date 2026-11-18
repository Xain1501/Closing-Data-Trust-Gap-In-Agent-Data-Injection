"""Field-level tagging (docs/tagging-design.md).

Each field of one intercepted message gets a ``FieldTag`` in a side record keyed by
its JSON path: where the value came from (provenance), whether it may be trusted
(trust, computed from provenance) and the part it plays (role). Tags never hold the
raw value and the payload is never modified.

Result tags are built from the true result fields; argument tags link values to the
prompt or earlier SYSTEM/EXTERNAL result leaves through the per-run state.

The old two-argument call ``tag_fields(parse_result, field_trust_classes)`` used by
``src/pipeline`` still works unchanged; it is deprecated and goes away when tagging is
wired in as a detector stage.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal

from parser.models import ParsedField, ParseResult, TaggedField, Trust

Direction = Literal["pre", "post"]


class Provenance(str, Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    EXTERNAL = "EXTERNAL"
    DERIVED = "DERIVED"
    UNKNOWN = "UNKNOWN"


class Role(str, Enum):
    AUTHORITY_ARG = "AUTHORITY_ARG"
    CONTENT = "CONTENT"
    IDENTIFIER = "IDENTIFIER"
    OTHER = "OTHER"


class LineageStatus(str, Enum):
    USER_MATCH = "USER_MATCH"
    SYSTEM_LINK = "SYSTEM_LINK"
    EXTERNAL_LINK = "EXTERNAL_LINK"
    UNLINKED = "UNLINKED"
    BELOW_MIN = "BELOW_MIN"


@dataclass(frozen=True)
class Evidence:
    """One real link from a DERIVED tag to the tag of its source value."""
    source_tag_id: str | None
    match_type: Literal["equal", "substring"]
    matched_length: int
    source_provenance: Provenance = Provenance.EXTERNAL
    source_has_forgery: bool = False


@dataclass(frozen=True)
class FieldTag:
    run_id: str
    interception_id: str | None
    direction: Direction
    path: str
    tag_id: str
    created_at: float
    provenance: Provenance
    trust: Trust
    role: Role
    parent_path: str | None
    depth: int
    value_type: str
    length: int | None
    lineage_status: LineageStatus
    derived_from: tuple[Evidence, ...] = ()
    has_forgery: bool = False


_RESULT_PROVENANCE = (Provenance.SYSTEM, Provenance.EXTERNAL)


@dataclass(frozen=True)
class ProfileEntry:
    """Phase-1 tool trust profile entry (design doc, Section 5). No file loading yet."""
    tool_name: str
    args: Mapping[str, Role] = field(default_factory=dict)
    result_format: Literal["json", "text"] = "json"
    result_fields: Mapping[str, Provenance] = field(default_factory=dict)
    result_default: Provenance = Provenance.EXTERNAL
    review_status: Literal["draft", "approved"] = "draft"

    def __post_init__(self) -> None:
        if self.result_format not in ("json", "text"):
            raise ValueError(f"{self.tool_name}: result_format must be 'json' or 'text'")
        if self.review_status not in ("draft", "approved"):
            raise ValueError(f"{self.tool_name}: review_status must be 'draft' or 'approved'")
        args = {name: Role(role) for name, role in self.args.items()}
        result_fields = {pattern: Provenance(p) for pattern, p in self.result_fields.items()}
        default = Provenance(self.result_default)
        for p in (*result_fields.values(), default):
            if p not in _RESULT_PROVENANCE:
                raise ValueError(f"{self.tool_name}: result provenance must be SYSTEM or EXTERNAL, got {p.value}")
        object.__setattr__(self, "args", MappingProxyType(args))
        object.__setattr__(self, "result_fields", MappingProxyType(result_fields))
        object.__setattr__(self, "result_default", default)

    @property
    def usable(self) -> bool:
        return self.review_status == "approved"


def normalise(value: str) -> str:
    """Compatibility export; canonical value normalization lives with lineage."""
    from provenance.lineage import normalise as normalize_value

    return normalize_value(value)


def trust_for(provenance: Provenance, source_trusts: Sequence[Trust] = ()) -> Trust:
    """Trust is computed from provenance, never set directly (design doc 2.2)."""
    if provenance in (Provenance.SYSTEM, Provenance.USER):
        return Trust.T
    if provenance is Provenance.DERIVED:
        return Trust.T if source_trusts and all(t is Trust.T for t in source_trusts) else Trust.UT
    return Trust.UT


def tag_fields(
    direction: Direction | ParseResult,
    tool_name: str | Mapping[str, str] | None = None,
    fields: Sequence[ParsedField] | None = None,
    profile_entry: ProfileEntry | None = None,
    run_state: Any = None,
    *,
    interception_id: str | None = None,
    authority_arguments: Sequence[str] = (),
    batch_id: int | None = None,
    result_format: Literal["json", "text"] = "json",
    findings: Sequence[Any] = (),
    clock: Callable[[], float] = time.time,
) -> list[FieldTag] | list[TaggedField]:
    """Tag every parsed field of one message.

    ``direction`` is ``"pre"`` (``fields`` are the parsed *arguments* object) or
    ``"post"`` (``fields`` are the parsed formatted result). ``profile_entry`` is the
    tool's profile, or ``None`` when the tool has none. ``run_state`` is the caller's
    RunState; post-hop values are indexed there and pre-hop arguments are linked
    against its prompt and earlier result values.

    Expected cases (no profile, draft entry, plain text) return tags; misuse raises.
    """
    if isinstance(direction, ParseResult):          # deprecated two-argument call
        return _legacy_tag_fields(direction, dict(tool_name or {}))  # type: ignore[arg-type]

    if direction not in ("pre", "post"):
        raise ValueError(f"direction must be 'pre' or 'post', got {direction!r}")
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a non-empty string")
    if profile_entry is not None and profile_entry.tool_name != tool_name:
        raise ValueError(f"profile entry is for {profile_entry.tool_name!r}, not {tool_name!r}")
    run_id = getattr(run_state, "run_id", None)
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_state must provide a non-empty run_id")

    fields = list(fields or ())
    make = _TagFactory(run_id, interception_id, direction, clock)
    if direction == "post":
        forged_paths = _forged_field_paths(fields, findings)
        tags = _tag_result(fields, profile_entry, make, result_format, forged_paths)
        if run_state is not None:
            from provenance.lineage import index_values

            index_values(tags, fields, run_state, batch_id=batch_id)
        return tags
    forged_paths = _forged_field_paths(fields, findings)
    tags = _tag_arguments(fields, profile_entry, make, authority_arguments, forged_paths)
    if run_state is not None:
        from provenance.lineage import link_arguments

        return link_arguments(tags, fields, run_state, batch_id=batch_id)
    return tags


# ------------------------------------------------------------------ results ----
def _tag_result(
    fields: list[ParsedField], entry: ProfileEntry | None, make: "_TagFactory",
    result_format: Literal["json", "text"], forged_paths: set[str],
) -> list[FieldTag]:
    effective_format = entry.result_format if entry is not None and entry.usable else result_format
    if entry is None or not entry.usable:
        if effective_format == "text":
            root = next((f for f in fields if f.path == "$"), None)
            return [make(root, Provenance.EXTERNAL, _result_role(Provenance.EXTERNAL, root.value_type), root.path in forged_paths)] if root is not None else []
        # The real object supplies trusted boundaries; its string/scalar leaves
        # can still contain externally supplied data. Structure and values get
        # separate provenance by default.
        return [
            make(
                f,
                Provenance.SYSTEM if f.value_type in ("object", "array") else Provenance.EXTERNAL,
                _result_role(
                    Provenance.SYSTEM if f.value_type in ("object", "array") else Provenance.EXTERNAL,
                    f.value_type,
                ),
                f.path in forged_paths,
            )
            for f in fields
        ]

    if effective_format == "text":                  # whole result is one field "$"
        root = next((f for f in fields if f.path == "$"), None)
        if root is None:
            return []
        default = entry.result_default if entry is not None and entry.usable else Provenance.EXTERNAL
        return [make(root, default, _result_role(default, root.value_type), root.path in forged_paths)]

    patterns = [(_compile_pattern(p), prov) for p, prov in entry.result_fields.items()]
    by_path = {f.path: f for f in fields}
    explicit: dict[str, Provenance | None] = {}      # provenance set by a pattern (or containment)
    tags = []
    for f in fields:
        prov = _explicit_provenance(f, by_path, patterns, explicit)
        final = prov if prov is not None else (
            Provenance.SYSTEM if f.value_type in ("object", "array") else entry.result_default
        )
        tags.append(make(f, final, _result_role(final, f.value_type), f.path in forged_paths))
    return tags


def _explicit_provenance(f, by_path, patterns, memo) -> Provenance | None:
    """Pattern match, with containment: inside an explicitly EXTERNAL field -> EXTERNAL.

    Only explicitly matched (or contained) EXTERNAL fields propagate. Containers that
    merely fall back to ``result_default`` do not, otherwise an EXTERNAL default on the
    root would override every SYSTEM pattern below it.
    """
    if f.path in memo:
        return memo[f.path]
    parent = by_path.get(f.parent_path) if f.parent_path else None
    if parent is not None and _explicit_provenance(parent, by_path, patterns, memo) is Provenance.EXTERNAL:
        memo[f.path] = Provenance.EXTERNAL
        return Provenance.EXTERNAL
    key = _strip_duplicate_suffix(f.path)
    result = next((prov for rx, prov in patterns if rx.fullmatch(key)), None)
    memo[f.path] = result
    return result


def _result_role(provenance: Provenance, value_type: str) -> Role:
    """Design doc 3.1, rule 6."""
    if provenance is Provenance.EXTERNAL:
        return Role.CONTENT if value_type == "string" else Role.OTHER
    if provenance is Provenance.SYSTEM:
        return Role.IDENTIFIER if value_type == "string" else Role.OTHER
    return Role.OTHER


def _compile_pattern(pattern: str) -> re.Pattern[str]:
    """``$[*].body`` -> regex on the parser's path form; ``[*]`` matches any list index."""
    return re.compile(re.escape(pattern).replace(r"\[\*\]", r"\[\d+\]"))


_DUPLICATE_SUFFIX = re.compile(r"#\d+(?=$|[.\[])")


def _strip_duplicate_suffix(path: str) -> str:
    """The parser marks repeated keys as ``$.to#2``; patterns match the plain key."""
    return _DUPLICATE_SUFFIX.sub("", path)


# ---------------------------------------------------------------- arguments ----
def _tag_arguments(
    fields: list[ParsedField], entry: ProfileEntry | None, make: "_TagFactory",
    authority_arguments: Sequence[str] = (), forged_paths: set[str] | None = None,
) -> list[FieldTag]:
    """Assign argument roles before lineage attaches prompt/source provenance."""
    roles = dict(entry.args) if entry is not None and entry.usable else {}
    authority = set(authority_arguments)
    return [
        make(
            f,
            Provenance.DERIVED,
            roles.get(
                _argument_name(f.path),
                Role.AUTHORITY_ARG if _argument_name(f.path) in authority else Role.OTHER,
            ),
            f.path in (forged_paths or set()),
        )
        for f in fields
    ]


_IDENT_ROOT = re.compile(r"^\$\.([A-Za-z_]\w*)")
_QUOTED_ROOT = re.compile(r'^\$\[("(?:[^"\\]|\\.)*")\]')


def _argument_name(path: str) -> str | None:
    """Top-level argument a path belongs to: ``$.recipients[0]`` -> ``recipients``."""
    m = _IDENT_ROOT.match(path)
    if m:
        return m.group(1)
    m = _QUOTED_ROOT.match(path)
    return json.loads(m.group(1)) if m else None


# ------------------------------------------------------------------ helpers ----
class _TagFactory:
    def __init__(self, run_id: str, interception_id: str | None, direction: Direction,
                 clock: Callable[[], float]) -> None:
        self.run_id, self.interception_id, self.direction, self.clock = run_id, interception_id, direction, clock

    def __call__(self, f: ParsedField, provenance: Provenance, role: Role,
                 has_forgery: bool = False) -> FieldTag:
        length = len(normalise(f.value)) if isinstance(f.value, str) else None
        return FieldTag(
            run_id=self.run_id, interception_id=self.interception_id, direction=self.direction,
            path=f.path, tag_id=str(uuid.uuid4()), created_at=self.clock(),
            provenance=provenance, trust=trust_for(provenance), role=role,
            parent_path=f.parent_path, depth=f.depth, value_type=f.value_type, length=length,
            lineage_status=LineageStatus.UNLINKED, derived_from=(), has_forgery=has_forgery,
        )


def _forged_field_paths(fields: Sequence[ParsedField], findings: Sequence[Any]) -> set[str]:
    """Attach each counted parser finding to its most specific true field owner."""
    owners: set[str] = set()
    for finding in findings:
        path = str(getattr(finding, "path", "")).split("#", 1)[0]
        candidates = [
            field.path for field in fields
            if path == field.path
            or path.startswith(field.path + ".")
            or path.startswith(field.path + "[")
        ]
        if candidates:
            owners.add(max(candidates, key=len))
    return owners


# -------------------------------------------------------- deprecated legacy ----
def _legacy_tag_fields(result: ParseResult, field_trust_classes: dict[str, str]) -> list[TaggedField]:
    """Previous behaviour, unchanged: matrix class of the top-level argument; default UT."""
    tagged: list[TaggedField] = []
    for f in result.fields:
        root_key = _root_key(f.path)
        raw_class = field_trust_classes.get(root_key, "unclassified").strip().lower()
        trust = Trust.T if raw_class in {"t", "trusted", "provenance_trusted"} else Trust.UT
        tagged.append(TaggedField(**f.model_dump(), trust=trust))
    return tagged


def _root_key(path: str) -> str:
    if not path.startswith("$."):
        return ""
    remainder = path[2:]
    key = remainder.split(".", 1)[0].split("[", 1)[0]
    return key.replace("~1", "/").replace("~0", "~")
