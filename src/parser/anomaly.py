"""Anomaly check: structure in a string field that its benign baseline never has.

The forgery rules recognise known formats (JSON delimiters, tables, key-value lines,
markdown claims). A forgery in a format they do not know, or one that adds only new
keys, contradicts nothing they can see. This check does not try to identify it: it
measures the *shape* of each string field and compares it with what that same field
looked like in benign runs. A field that suddenly carries much more structure is
marked ``anomaly``: suspicious, never counted, never a block on its own.

    shape(text)                                -> Shape (line, key-value, tag, section, blob counts)
    anomaly_findings(fields, tool_name, base)  -> list[Finding] (kind "anomaly", on the field)

The baseline (``shape_baseline.json``) is built from the benign traces by
``scripts/build_shape_baseline.py``: per tool and field pattern ("$[*].body"), the
most of each feature seen. A field the baseline has never seen is judged only on
strongly foreign structure (markup tags, INI sections, encoded blobs).
"""
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    from .models import Finding
except ImportError:  # flat-folder layout
    from models import Finding

BASELINE_PATH = Path(__file__).with_name("shape_baseline.json")
MAX_TEXT_CHARS = 200_000

_KV = re.compile(r"^\s*[\"']?[A-Za-z][\w .-]{0,40}[\"']?\s*[:=]\s*\S")
_TAG = re.compile(r"</?[A-Za-z][\w:-]{0,30}(?:\s[^<>\n]{0,200})?/?>")
_SECTION = re.compile(r"^\s*\[[A-Za-z][\w .-]{0,40}\]\s*$")
_YAML_ITEM = re.compile(r"^\s*-\s+[A-Za-z][\w ]{0,30}:\s+\S")
_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
_INDEX = re.compile(r"\[\d+\]")


@dataclass(frozen=True)
class Shape:
    lines: int = 0
    kv_lines: int = 0
    tags: int = 0
    sections: int = 0
    yaml_items: int = 0
    blobs: int = 0


def _markup_tags(text: str) -> int:
    """Real markup only: closing tags, tags with attributes, self-closing tags.
    A lone "<module>" or "<lambda>" (Python tracebacks) is not markup."""
    count = 0
    for m in _TAG.finditer(text):
        tag = m.group(0)
        if tag.startswith("</") or tag.endswith("/>") or " " in tag.strip("<>/"):
            count += 1
    return count


def _looks_encoded(text: str, m: re.Match[str]) -> bool:
    """Base64-like: mixes upper case, lower case and digits, and is not a URL path."""
    blob = m.group(0)
    start = m.start()
    if "://" in text[max(0, start - 60):start] and " " not in text[max(0, start - 60):start].split("://")[-1]:
        return False
    if blob.count("/") > 2:
        return False                                   # paths: a/b/c/d
    if not re.search(r"\s", text.strip()):
        # The whole field is one token (an attachment id, a hash): indistinguishable from
        # an id, so not counted. A blob embedded in other text is.
        return False
    return any(c.isupper() for c in blob) and any(c.islower() for c in blob) and any(c.isdigit() for c in blob)


def shape(text: str) -> Shape:
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        return Shape()
    lines = [line for line in text.splitlines() if line.strip()]
    return Shape(
        lines=len(lines),
        kv_lines=sum(bool(_KV.match(line)) for line in lines),
        tags=_markup_tags(text),
        sections=sum(bool(_SECTION.match(line)) for line in lines),
        yaml_items=sum(bool(_YAML_ITEM.match(line)) for line in lines),
        blobs=sum(1 for m in _BLOB.finditer(text) if _looks_encoded(text, m)),
    )


def field_key(tool_name: str | None, path: str) -> str:
    """'search_emails' + '$[3].body' -> 'search_emails|$[*].body'."""
    return f"{tool_name or '?'}|{_INDEX.sub('[*]', path)}"


@lru_cache(maxsize=1)
def load_baseline(path: str | None = None) -> dict[str, dict[str, int]]:
    p = Path(path) if path else BASELINE_PATH
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def update_baseline(baseline: dict[str, dict[str, int]], key: str, s: Shape) -> None:
    entry = baseline.setdefault(key, {name: 0 for name in asdict(Shape())} | {"seen": 0})
    entry["seen"] += 1
    for name, value in asdict(s).items():
        entry[name] = max(entry[name], value)


def _reasons(s: Shape, entry: dict[str, int] | None) -> list[str]:
    reasons: list[str] = []
    if entry is None:
        # Never seen in benign runs: only structure that is foreign to ordinary text.
        if s.tags >= 2:
            reasons.append(f"markup tags ({s.tags})")
        if s.sections >= 1:
            reasons.append("config sections")
        if s.blobs >= 1:
            reasons.append("encoded blob")
        return reasons
    if s.kv_lines >= 2 and s.kv_lines > entry["kv_lines"] + 1:
        reasons.append(f"key-value lines {s.kv_lines} (benign max {entry['kv_lines']})")
    if s.tags >= 2 and s.tags > entry["tags"]:
        reasons.append(f"markup tags {s.tags} (benign max {entry['tags']})")
    if s.sections >= 1 and s.sections > entry["sections"]:
        reasons.append("config sections")
    if s.yaml_items >= 2 and s.yaml_items > entry["yaml_items"] + 1:
        reasons.append(f"list-of-keys lines {s.yaml_items} (benign max {entry['yaml_items']})")
    if s.blobs >= 1 and s.blobs > entry["blobs"]:
        reasons.append("encoded blob")
    if s.lines > max(entry["lines"] * 2, entry["lines"] + 5) and (s.kv_lines or s.tags or s.yaml_items):
        reasons.append(f"lines {s.lines} (benign max {entry['lines']}) with structure")
    return reasons


def anomaly_findings(
    fields: Sequence[Any], tool_name: str | None, baseline: dict[str, dict[str, int]] | None = None,
) -> list[Finding]:
    """One ``anomaly`` finding per string field whose shape leaves its benign range."""
    base = load_baseline() if baseline is None else baseline
    out: list[Finding] = []
    for f in fields:
        if getattr(f, "value_type", None) != "string" or not isinstance(getattr(f, "value", None), str):
            continue
        if ".@" in f.path:
            continue                                   # inner nodes: their leaf is checked
        reasons = _reasons(shape(f.value), base.get(field_key(tool_name, f.path)))
        if reasons:
            out.append(Finding(kind="anomaly", path=f.path, detail="anomaly: " + "; ".join(reasons)))
    return out
