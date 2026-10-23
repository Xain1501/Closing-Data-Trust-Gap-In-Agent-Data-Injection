"""Field-level trust tagging from explicit tool-matrix provenance metadata."""
from __future__ import annotations

from parser.models import ParseResult, TaggedField, Trust


def tag_fields(result: ParseResult, field_trust_classes: dict[str, str]) -> list[TaggedField]:
    """Tag fields using the matrix class for their top-level argument.

    Unknown or unsupported classes default to UT. Content itself is never used
    to infer trust; matrix owners must explicitly mark a field as trusted.
    """
    tagged: list[TaggedField] = []
    for field in result.fields:
        root_key = _root_key(field.path)
        raw_class = field_trust_classes.get(root_key, "unclassified").strip().lower()
        trust = Trust.T if raw_class in {"t", "trusted", "provenance_trusted"} else Trust.UT
        tagged.append(TaggedField(**field.model_dump(), trust=trust))
    return tagged


def _root_key(path: str) -> str:
    if not path.startswith("$."):
        return ""
    remainder = path[2:]
    key = remainder.split(".", 1)[0].split("[", 1)[0]
    return key.replace("~1", "/").replace("~0", "~")
