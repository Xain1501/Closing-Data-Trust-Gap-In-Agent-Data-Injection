"""One canonical, immutable serialisation of a cloned payload.

``canonical_json(value)`` returns the exact text that is hashed, stored in the
ledger and decoded for the detector, so "what was hashed", "what was stored"
and "what was inspected" are provably the same bytes. A string cannot be
mutated, so no defensive copies are needed after this point.

Rules: sorted keys, compact separators, real UTF-8 (``ensure_ascii=False``).
Values JSON cannot express are converted here, once, instead of crashing later:

    set / frozenset   -> {"$type": "set", "items": [...sorted...]}
    bytes / bytearray -> {"$type": "bytes", "hex": "..."}
    NaN / +-Infinity  -> {"$type": "float", "value": "nan" | "inf" | "-inf"}
    lone surrogates   -> the six characters \\udXXX (text stays valid UTF-8)
    pydantic models   -> model_dump(mode="json")
    anything else     -> {"$type": "<class name>", "repr": "..."}

This module must stay free of framework imports.
"""
from __future__ import annotations

import json
import math
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

_MAX_DEPTH = 200


def clean_text(text: str) -> str:
    """Return ``text`` unchanged unless it holds lone surrogates, which UTF-8 cannot encode."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _plain(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("payload is nested too deeply to serialise")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return {"$type": "float", "value": "nan" if math.isnan(value) else ("inf" if value > 0 else "-inf")}
    if hasattr(value, "model_dump"):
        return _plain(value.model_dump(mode="json"), depth + 1)
    if isinstance(value, Mapping):
        return {clean_text(str(key)): _plain(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item, depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_plain(item, depth + 1) for item in value]
        return {"$type": "set", "items": sorted(items, key=_dumps)}
    if isinstance(value, (bytes, bytearray)):
        return {"$type": "bytes", "hex": bytes(value).hex()}
    return {"$type": type(value).__name__, "repr": clean_text(repr(value))}


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_json(value: Any) -> str:
    """Serialise ``value`` to its canonical JSON text. Never raises on odd value types."""
    return _dumps(_plain(value))


def text_sha256(text: str) -> str:
    """SHA-256 of a text payload; lone surrogates are hashed, not fatal."""
    return sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
