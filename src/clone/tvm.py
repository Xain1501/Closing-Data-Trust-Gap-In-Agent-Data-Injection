"""Trust Verification Matrix: per-tool policy facts (impact tier, tool profile).

Schema version 2. Each entry describes one tool, matched by ``tool_name`` (and,
when two tools share a name, by their exact argument names):

    impact_tier / impact_tier_source   how costly the tool is (1, 5, 10)
    args            {argument name: role}   role in ROLES; empty = no roles assigned yet
    result_format   "json" | "text"         "text" = the whole result is one field "$"
    result_fields   {path pattern: provenance}   optional overrides, e.g. "$[*].id_": "SYSTEM"
    result_default  provenance for every other result field (normally EXTERNAL)
    review_status   "draft" | "approved"    tagging uses a profile only when approved

Field boundaries are NOT listed here: they come from the result object
(``parser.skeleton``). Trust comes from lineage, not from this file. The matrix
only supplies policy facts and optional overrides.

This module must stay free of framework and pydantic imports.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Literal

ImpactTier = Literal[1, 5, 10]
DEFAULT_MATRIX_PATH = Path(__file__).with_name("tool_matrix.json")
MATRIX_SCHEMA_VERSION = 2

# Vocabularies (kept as strings here; trust_graph.tagging owns the enums).
ROLES = frozenset({"AUTHORITY_ARG", "CONTENT", "IDENTIFIER", "OTHER"})
RESULT_PROVENANCE = frozenset({"SYSTEM", "EXTERNAL"})
RESULT_FORMATS = frozenset({"json", "text"})
REVIEW_STATUSES = frozenset({"draft", "approved"})

_REQUIRED = ("tool_name", "internal_tool_id", "impact_tier", "impact_tier_source", "expected_keys")


def _pairs(mapping: Mapping[str, str] | tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    items = mapping.items() if isinstance(mapping, Mapping) else mapping
    return tuple(sorted((str(k), str(v)) for k, v in items))


@dataclass(frozen=True)
class ToolMatrixEntry:
    """One tool's policy facts. Immutable and hashable (mappings are stored as sorted pairs)."""

    tool_name: str
    internal_tool_id: str
    impact_tier: ImpactTier | None
    impact_tier_source: str
    expected_keys: tuple[str, ...]
    args: tuple[tuple[str, str], ...] = ()
    result_format: str = "json"
    result_fields: tuple[tuple[str, str], ...] = ()
    result_default: str = "EXTERNAL"
    review_status: str = "draft"
    source_suites: tuple[str, ...] = ()
    is_fallback: bool = False
    keys_match: bool = True            # False: matched by name, but the live argument names differ

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_keys", tuple(self.expected_keys))
        object.__setattr__(self, "args", _pairs(self.args))
        object.__setattr__(self, "result_fields", _pairs(self.result_fields))
        object.__setattr__(self, "source_suites", tuple(self.source_suites))

    @property
    def arg_roles(self) -> dict[str, str]:
        return dict(self.args)

    @property
    def authority_arguments(self) -> tuple[str, ...]:
        """Arguments whose value decides where an action goes (role AUTHORITY_ARG)."""
        return tuple(name for name, role in self.args if role == "AUTHORITY_ARG")

    @property
    def result_field_overrides(self) -> dict[str, str]:
        return dict(self.result_fields)

    def profile(self) -> Any:
        """This entry as the tagging stage's ``ProfileEntry`` (imported lazily)."""
        from trust_graph.tagging import ProfileEntry   # keeps tvm import-light

        return ProfileEntry(
            tool_name=self.tool_name,
            args=self.arg_roles,
            result_format=self.result_format,  # type: ignore[arg-type]
            result_fields=self.result_field_overrides,
            result_default=self.result_default,  # type: ignore[arg-type]
            review_status=self.review_status,  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class TrustMatrix:
    entries: tuple[ToolMatrixEntry, ...]
    schema_version: int = MATRIX_SCHEMA_VERSION
    source_sha256: str | None = None
    _by_name: dict[str, tuple[ToolMatrixEntry, ...]] = field(
        default_factory=dict, init=False, repr=False, compare=False, hash=False)
    _by_id: dict[str, ToolMatrixEntry] = field(
        default_factory=dict, init=False, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))
        by_name: dict[str, list[ToolMatrixEntry]] = {}
        for entry in self.entries:
            by_name.setdefault(entry.tool_name, []).append(entry)
        object.__setattr__(self, "_by_name", {k: tuple(v) for k, v in by_name.items()})
        object.__setattr__(self, "_by_id", {e.internal_tool_id: e for e in self.entries})

    def lookup(
        self, tool_name: str, expected_keys: set[str] | frozenset[str] | None = None
    ) -> ToolMatrixEntry:
        """Find a tool's entry.

        * One entry with this name: it is used even if the live argument names
          differ (schema drift); the returned copy has ``keys_match=False``.
        * Several entries share the name: the argument names pick one; if none
          match exactly (or no names were given), the tool is unclassified.
        * Unknown name: unclassified fallback.
        """
        candidates = self._by_name.get(tool_name, ())
        keys = None if expected_keys is None else frozenset(expected_keys)
        if keys is not None:
            for entry in candidates:
                if frozenset(entry.expected_keys) == keys:
                    return entry
        if len(candidates) == 1:
            entry = candidates[0]
            return entry if keys is None else replace(entry, keys_match=False)
        return self.fallback(tool_name, keys or ())

    def by_id(self, internal_tool_id: str | None) -> ToolMatrixEntry | None:
        return self._by_id.get(internal_tool_id) if internal_tool_id else None

    @staticmethod
    def fallback(tool_name: str, expected_keys: Any = ()) -> ToolMatrixEntry:
        return ToolMatrixEntry(
            tool_name=tool_name,
            internal_tool_id=f"unclassified:{tool_name}",
            impact_tier=None,
            impact_tier_source="unclassified",
            expected_keys=tuple(sorted(expected_keys)),
            is_fallback=True,
        )


def _entry_from_raw(raw: Any, index: int) -> ToolMatrixEntry:
    where = f"matrix tool #{index}"
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where}: each tool must be an object")
    name = raw.get("tool_name")
    if isinstance(name, str):
        where = f"matrix tool {name!r}"
    missing = [key for key in _REQUIRED if key not in raw]
    if missing:
        raise ValueError(f"{where}: missing required field(s) {missing}")
    if "field_trust_classes" in raw or "authority_arguments" in raw:
        raise ValueError(f"{where}: 'field_trust_classes' / 'authority_arguments' are schema v1; "
                         "use 'args' (argument roles) instead")

    tier = raw["impact_tier"]
    if tier not in (None, 1, 5, 10):
        raise ValueError(f"{where}: invalid impact tier {tier!r}")
    tier_source = raw["impact_tier_source"]
    if tier is not None and tier_source != "policy default":
        raise ValueError(f"{where}: impact tier must be marked 'policy default'")

    keys = raw["expected_keys"]
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        raise ValueError(f"{where}: expected_keys must be a list of strings")
    if len(set(keys)) != len(keys):
        raise ValueError(f"{where}: expected_keys contains duplicates")

    args = raw.get("args", {})
    if not isinstance(args, Mapping):
        raise ValueError(f"{where}: args must be an object of argument -> role")
    unknown_args = sorted(set(args) - set(keys))
    if unknown_args:
        raise ValueError(f"{where}: args {unknown_args} are not in expected_keys")
    bad_roles = sorted({str(r) for r in args.values()} - ROLES)
    if bad_roles:
        raise ValueError(f"{where}: unknown role(s) {bad_roles}; allowed {sorted(ROLES)}")

    result_fields = raw.get("result_fields", {})
    if not isinstance(result_fields, Mapping):
        raise ValueError(f"{where}: result_fields must be an object of path -> provenance")
    bad_paths = sorted(p for p in result_fields if not str(p).startswith("$"))
    if bad_paths:
        raise ValueError(f"{where}: result_fields paths must start with '$': {bad_paths}")
    result_default = raw.get("result_default", "EXTERNAL")
    bad_prov = sorted({str(p) for p in (*result_fields.values(), result_default)} - RESULT_PROVENANCE)
    if bad_prov:
        raise ValueError(f"{where}: result provenance must be SYSTEM or EXTERNAL, got {bad_prov}")
    result_format = raw.get("result_format", "json")
    if result_format not in RESULT_FORMATS:
        raise ValueError(f"{where}: result_format must be 'json' or 'text'")
    review_status = raw.get("review_status", "draft")
    if review_status not in REVIEW_STATUSES:
        raise ValueError(f"{where}: review_status must be 'draft' or 'approved'")

    return ToolMatrixEntry(
        tool_name=name,
        internal_tool_id=raw["internal_tool_id"],
        impact_tier=tier,
        impact_tier_source=tier_source or "unassigned",
        expected_keys=tuple(keys),
        args=dict(args),
        result_format=result_format,
        result_fields=dict(result_fields),
        result_default=result_default,
        review_status=review_status,
        source_suites=tuple(raw.get("source_suites", ())),
    )


def load_tool_matrix(path: str | Path = DEFAULT_MATRIX_PATH) -> TrustMatrix:
    """Load and validate the checked-in TVM JSON into immutable records."""
    source_bytes = Path(path).read_bytes()
    document = json.loads(source_bytes.decode("utf-8"))
    if not isinstance(document, Mapping) or not isinstance(document.get("tools"), list):
        raise ValueError("Trust matrix must be an object with a 'tools' list.")
    if document.get("schema_version") != MATRIX_SCHEMA_VERSION:
        raise ValueError(f"Trust matrix must use schema_version {MATRIX_SCHEMA_VERSION}, "
                         f"got {document.get('schema_version')!r}.")

    entries = []
    seen: set[tuple[str, frozenset[str]]] = set()
    ids: set[str] = set()
    for index, raw in enumerate(document["tools"]):
        entry = _entry_from_raw(raw, index)
        key = (entry.tool_name, frozenset(entry.expected_keys))
        if key in seen:
            raise ValueError(f"Duplicate matrix entry for {entry.tool_name} with keys {entry.expected_keys}.")
        if entry.internal_tool_id in ids:
            raise ValueError(f"Duplicate internal_tool_id {entry.internal_tool_id!r}.")
        seen.add(key)
        ids.add(entry.internal_tool_id)
        entries.append(entry)
    return TrustMatrix(tuple(entries), source_sha256=sha256(source_bytes).hexdigest())
