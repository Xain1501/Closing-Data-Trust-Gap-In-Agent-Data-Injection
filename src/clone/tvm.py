from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

ImpactTier = Literal[1, 5, 10]
DEFAULT_MATRIX_PATH = Path(__file__).with_name("tool_matrix.json")


@dataclass(frozen=True)
class ToolMatrixEntry:
    tool_name: str
    internal_tool_id: str
    impact_tier: ImpactTier | None
    impact_tier_source: str
    authority_arguments: tuple[str, ...]
    field_trust_classes: Mapping[str, str]
    expected_keys: tuple[str, ...]
    source_suites: tuple[str, ...] = ()
    is_fallback: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "field_trust_classes", MappingProxyType(dict(self.field_trust_classes))
        )


@dataclass(frozen=True)
class TrustMatrix:
    entries: tuple[ToolMatrixEntry, ...]
    schema_version: int = 1
    source_sha256: str | None = None

    def lookup(
        self, tool_name: str, expected_keys: set[str] | frozenset[str]
    ) -> ToolMatrixEntry:
        for entry in self.entries:
            if entry.tool_name == tool_name and set(entry.expected_keys) == set(expected_keys):
                return entry
        keys = tuple(sorted(expected_keys))
        return ToolMatrixEntry(
            tool_name=tool_name,
            internal_tool_id=f"unclassified:{tool_name}",
            impact_tier=None,
            impact_tier_source="unclassified",
            authority_arguments=(),
            field_trust_classes={key: "unclassified" for key in keys},
            expected_keys=keys,
            is_fallback=True,
        )


def load_tool_matrix(path: str | Path = DEFAULT_MATRIX_PATH) -> TrustMatrix:
    """Load the checked-in TVM JSON into immutable records."""
    source_bytes = Path(path).read_bytes()
    document = json.loads(source_bytes.decode("utf-8"))
    if document.get("schema_version") != 1 or not isinstance(document.get("tools"), list):
        raise ValueError("Trust matrix must use schema_version 1 and contain a tools list.")

    entries = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for raw in document["tools"]:
        tier = raw.get("impact_tier")
        if tier not in (None, 1, 5, 10):
            raise ValueError(f"Invalid impact tier for {raw.get('tool_name')}: {tier}")
        tier_source = raw.get("impact_tier_source")
        if tier is not None and tier_source != "policy default":
            raise ValueError(f"Impact tier for {raw.get('tool_name')} must be marked policy default.")
        name = raw["tool_name"]
        keys = tuple(raw["expected_keys"])
        key = (name, keys)
        if key in seen:
            raise ValueError(f"Duplicate matrix entry for {name} with keys {keys}.")
        seen.add(key)
        field_classes = raw["field_trust_classes"]
        if set(field_classes) != set(keys):
            raise ValueError(f"Field trust classes do not match expected keys for {name}.")
        entries.append(
            ToolMatrixEntry(
                tool_name=name,
                internal_tool_id=raw["internal_tool_id"],
                impact_tier=tier,
                impact_tier_source=tier_source or "unassigned",
                authority_arguments=tuple(raw["authority_arguments"]),
                field_trust_classes=field_classes,
                expected_keys=keys,
                source_suites=tuple(raw.get("source_suites", ())),
            )
        )
    return TrustMatrix(tuple(entries), source_sha256=sha256(source_bytes).hexdigest())
