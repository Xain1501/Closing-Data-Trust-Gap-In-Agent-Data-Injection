"""Skeleton: the TRUE field list of a tool result, taken from the result object.

The parser reads the formatted *text* of a result. ADI works by making text
inside one field look like extra fields, so field boundaries read back from
text can be forged. The skeleton is built from the tool's real result object
(before formatting), so its boundaries cannot be forged by anything written
inside a field. Later stages (tagging, lineage, the run graph) use it as the
provenance source: "this value is the whole of field X of result Y".

    to_plain(raw_result)       -> plain dicts / lists / scalars, as the formatter would emit them
    build_skeleton(raw_result) -> Skeleton (fields use the parser's own ParsedField and paths)

A Skeleton is immutable and exportable (``to_dict`` is JSON-serialisable), so it
can be handed to tagging, stored in run state, or written to an audit trail.

Limit: on JSON output the skeleton adds a guarantee, not new detection (the
JSON parser already recovers the same fields). Its value shows when the output
format is not JSON, or when the two disagree.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

try:
    from .inner import leaf_inner_fields
    from .models import ParsedField
    from .parser import _Ctx, _Pairs, _TooDeep, _TooManyFields, _walk
except ImportError:  # flat-folder layout
    from inner import leaf_inner_fields
    from models import ParsedField
    from parser import _Ctx, _Pairs, _TooDeep, _TooManyFields, _walk

ResultKind = Literal["model", "list", "dict", "str", "none", "scalar", "other"]
SkeletonStatus = Literal[
    "ok",            # structured object walked; ``fields`` is the true field list
    "unstructured",  # str / scalar result: one opaque value, no inner fields to list
    "absent",        # no result object was available (None result or not supplied)
    "too_large",     # object exceeded the parser's depth / field limits
]


def to_plain(raw_result: Any) -> Any:
    """Convert a tool result object to plain data, matching AgentDojo's formatter.

    * pydantic model        -> ``model_dump(mode="json")`` (datetimes -> ISO strings, enums -> values)
    * top-level list        -> models dumped; ``str`` / ``int`` items become ``str`` (the formatter does this)
    * dict                  -> kept, with nested models / tuples / sets made plain and keys made ``str``
    * str / None / scalars  -> returned unchanged

    Unlike the formatter this never raises on unusual item types: they are made
    plain recursively, so a skeleton can still be built for them.
    """
    if _is_model(raw_result):
        return _deep_plain(raw_result.model_dump(mode="json"))
    if isinstance(raw_result, list):
        items = []
        for item in raw_result:
            if type(item) in (str, int):          # same test as the formatter: bool is not included
                items.append(str(item))
            else:
                items.append(_deep_plain(item))
        return items
    if isinstance(raw_result, Mapping):
        return _deep_plain(raw_result)
    return raw_result


def _is_model(value: Any) -> bool:
    return hasattr(value, "model_dump") and not isinstance(value, type)


def _deep_plain(value: Any, depth: int = 0) -> Any:
    if depth > 200:
        raise _TooDeep("result object")
    if _is_model(value):
        return _deep_plain(value.model_dump(mode="json"), depth + 1)
    if isinstance(value, Mapping):
        return {str(key): _deep_plain(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_deep_plain(item, depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_deep_plain(item, depth + 1) for item in value), key=repr)
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)                              # dates, enums, bytes...: what default=str would emit


def _as_pairs(value: Any) -> Any:
    """Plain data -> the parser's internal tree form, so ``_walk`` yields identical paths."""
    if isinstance(value, dict):
        return _Pairs((key, _as_pairs(item)) for key, item in value.items())
    if isinstance(value, list):
        return [_as_pairs(item) for item in value]
    return value


def _kind(raw_result: Any) -> ResultKind:
    if raw_result is None:
        return "none"
    if _is_model(raw_result):
        return "model"
    if isinstance(raw_result, list):
        return "list"
    if isinstance(raw_result, Mapping):
        return "dict"
    if isinstance(raw_result, str):
        return "str"
    if isinstance(raw_result, (bool, int, float)):
        return "scalar"
    return "other"


@dataclass(frozen=True)
class Skeleton:
    """The true fields of one tool result. Immutable; safe to pass between stages."""

    status: SkeletonStatus
    result_kind: ResultKind
    fields: tuple[ParsedField, ...] = ()
    source: str = "raw_result"                    # where the boundaries came from (never the text)
    tool_name: str | None = None
    interception_id: str | None = None            # joins this skeleton to the ledger / tags / audit trail
    text: str | None = field(default=None, repr=False, compare=False)   # str results: the text itself
    _by_path: dict[str, ParsedField] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_by_path", {f.path: f for f in self.fields})

    @property
    def structured(self) -> bool:
        """True when ``fields`` is a real field list (status ``ok``)."""
        return self.status == "ok"

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(f.path for f in self.fields)

    @property
    def leaves(self) -> tuple[ParsedField, ...]:
        """Value-carrying fields (strings, numbers, booleans, nulls)."""
        return tuple(f for f in self.fields if f.value_type not in ("object", "array"))

    @property
    def string_leaves(self) -> tuple[ParsedField, ...]:
        """String values: the only places an outsider can write free text."""
        return tuple(f for f in self.fields if f.value_type == "string")

    @property
    def inner_fields(self) -> tuple[ParsedField, ...]:
        """Rows, cells and tokens written inside string leaves (``parser.inner``), e.g.
        ``$[0].content.@row[12].@col[1]`` or ``$.body.@tok[0]``. Kept apart from
        ``fields``, which stay the object's own boundaries. For a text result they sit
        under ``$``."""
        cached = self.__dict__.get("_inner")
        if cached is None:
            out: list[ParsedField] = []
            if self.structured:
                for leaf in self.string_leaves:
                    if isinstance(leaf.value, str):
                        out.extend(leaf_inner_fields(leaf.value, leaf.path, leaf.depth))
            elif self.result_kind == "str" and isinstance(self.text, str):
                # A text result (read_file) is one EXTERNAL leaf "$"; its rows, cells and
                # tokens are inferred from the content. No authorship is claimed.
                out.extend(leaf_inner_fields(self.text, "$", 0))
            cached = tuple(out)
            object.__setattr__(self, "_inner", cached)
        return cached

    def get(self, path: str) -> ParsedField | None:
        return self._by_path.get(path)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable export (audit trail, run state, files)."""
        return {
            "status": self.status,
            "result_kind": self.result_kind,
            "source": self.source,
            "tool_name": self.tool_name,
            "interception_id": self.interception_id,
            "field_count": len(self.fields),
            "fields": [f.model_dump(mode="json") for f in self.fields],
            "inner_fields": [f.model_dump(mode="json") for f in self.inner_fields],
        }


def build_skeleton(
    raw_result: Any,
    *,
    tool_name: str | None = None,
    interception_id: str | None = None,
) -> Skeleton:
    """Build the true field list from a tool's result object.

    Uses the parser's own walker, so paths, keys, depths and value types are
    exactly what the parser produces for the same data as JSON. A ``str``,
    scalar or missing result has no inner fields: ``fields`` is empty and
    callers fall back to the parser's fields.
    """
    kind = _kind(raw_result)
    common = {"result_kind": kind, "tool_name": tool_name, "interception_id": interception_id}
    if kind == "none":
        return Skeleton(status="absent", **common)
    if kind == "str":
        return Skeleton(status="unstructured", text=raw_result, **common)
    if kind in ("scalar", "other"):
        return Skeleton(status="unstructured", **common)
    ctx = _Ctx()
    try:
        _walk(_as_pairs(to_plain(raw_result)), "$", None, None, 0, ctx)
    except (_TooDeep, _TooManyFields, RecursionError):
        return Skeleton(status="too_large", **common)
    return Skeleton(status="ok", fields=tuple(ctx.fields), **common)
