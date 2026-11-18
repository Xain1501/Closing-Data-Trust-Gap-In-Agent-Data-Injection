"""Trust tagging and graph construction stages.

Tagging is usable without the optional classifier dependency. Graph construction
loads the classifier's ``GraphSnapshot`` type only when that API is called.
"""
from .tagging import (
    Evidence,
    FieldTag,
    LineageStatus,
    ProfileEntry,
    Provenance,
    Role,
    normalise,
    tag_fields,
    trust_for,
)

__all__ = [
    "Evidence",
    "FieldTag",
    "LineageStatus",
    "ProfileEntry",
    "Provenance",
    "Role",
    "build_trust_graph",
    "normalise",
    "tag_fields",
    "trust_for",
]


def build_trust_graph(*args, **kwargs):
    from .graph import build_trust_graph as _build_trust_graph

    return _build_trust_graph(*args, **kwargs)
