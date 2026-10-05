"""Stage 1 - Deterministic JSON parser (proposal sections 6.2 / 8.4.1).

parse() is PURE PARSING: it turns a payload into addressable fields and a
status. It computes no score and makes no trust judgment. Structural flags
live in structural.py and only receive the already-parsed result.

stdlib `json` does the tokenising (so duplicate keys stay visible; Pydantic
would silently collapse them). Pydantic validates the outputs.
"""
from __future__ import annotations

import json
import re
from typing import Any

try:
    from .models import Finding, ParsedField, ParseResult, ParseStatus, ToolTraffic
except ImportError:  # flat-folder layout
    from models import Finding, ParsedField, ParseResult, ParseStatus, ToolTraffic

MAX_BYTES = 1_000_000
MAX_DEPTH = 32


class _Pairs(list):
    """object_pairs_hook result: keeps duplicate keys and key order."""


class _TooDeep(Exception):
    pass


def _reject_constant(name: str) -> Any:  # NaN / Infinity are not valid JSON
    raise ValueError(f"non-standard JSON constant: {name}")


def _child_path(parent: str, key: str) -> str:
    return f"{parent}.{key}" if re.fullmatch(r"[A-Za-z_]\w*", key) else f"{parent}[{json.dumps(key)}]"


def payload_text(traffic: ToolTraffic) -> str:
    p = traffic.payload
    return p if isinstance(p, str) else json.dumps(p, default=str)


class _Ctx:
    def __init__(self) -> None:
        self.fields: list[ParsedField] = []
        self.findings: list[Finding] = []
        self.boundaries = 0    # containers + keys


def _walk(node: Any, path: str, parent: str | None, key: str | None, depth: int, ctx: _Ctx) -> None:
    if depth > MAX_DEPTH:
        raise _TooDeep(path)

    if isinstance(node, _Pairs):
        ctx.boundaries += 1
        ctx.fields.append(ParsedField(path=path, key=key, parent_path=parent, depth=depth, value_type="object"))
        counts: dict[str, int] = {}
        for k, v in node:
            n = counts[k] = counts.get(k, 0) + 1
            base = _child_path(path, k)
            if n > 1:
                ctx.findings.append(Finding(kind="duplicate_key", path=base, detail=f"key {k!r} appears {n} times"))
                base = f"{base}#{n}"
            ctx.boundaries += 1
            _walk(v, base, path, k, depth + 1, ctx)
    elif isinstance(node, list):
        ctx.boundaries += 1
        ctx.fields.append(ParsedField(path=path, key=key, parent_path=parent, depth=depth, value_type="array"))
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", path, None, depth + 1, ctx)
    else:
        vt = ("null" if node is None else "boolean" if isinstance(node, bool)
              else "string" if isinstance(node, str) else "number")
        ctx.fields.append(ParsedField(path=path, key=key, parent_path=parent, depth=depth,
                                      value_type=vt, value=node))  # type: ignore[arg-type]


def parse(traffic: ToolTraffic) -> ParseResult:
    raw = payload_text(traffic).lstrip("\ufeff")   # a leading BOM is not an attack
    ctx = _Ctx()
    status = ParseStatus.OK

    if len(raw.encode("utf-8", "ignore")) > MAX_BYTES:
        status = ParseStatus.TOO_LARGE
        ctx.findings.append(Finding(kind="payload_too_large", path="$", detail=f"> {MAX_BYTES} bytes"))
        raw = raw[:MAX_BYTES]
    else:
        try:
            tree = json.loads(raw, object_pairs_hook=_Pairs, parse_constant=_reject_constant)
            _walk(tree, "$", None, None, 0, ctx)
        except (_TooDeep, RecursionError):
            status = ParseStatus.TOO_DEEP
            ctx.findings.append(Finding(kind="depth_exceeded", path="$", detail=f"nesting deeper than {MAX_DEPTH}"))
        except ValueError as e:   # JSONDecodeError is a ValueError
            status = ParseStatus.INVALID_JSON
            ctx.findings.append(Finding(kind="parse_failure", path="$", detail=f"{type(e).__name__}: {e}"))

    if status is not ParseStatus.OK:  # default-untrusted: one opaque string node
        ctx.fields = [ParsedField(path="$", key=None, parent_path=None, depth=0,
                                  value_type="string", value=raw)]
        ctx.boundaries = 1

    return ParseResult(
        internal_id=traffic.internal_id, direction=traffic.direction,
        tool_name=traffic.tool_name, tool_call_id=traffic.tool_call_id,
        status=status, fields=ctx.fields, findings=ctx.findings,
        boundary_count=max(1, ctx.boundaries),
    )