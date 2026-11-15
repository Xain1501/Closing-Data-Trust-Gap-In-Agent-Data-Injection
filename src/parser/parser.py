"""Stage 1 - Deterministic JSON parser (proposal sections 6.2 / 8.4.1).

parse() is PURE PARSING: it turns a payload into addressable fields and a
status. It computes no score and makes no trust judgment. Structural flags
live in structural.py and only receive the already-parsed result.

stdlib `json` does the tokenising (so duplicate keys stay visible; Pydantic
would silently collapse them). Pydantic validates the outputs.
"""
from __future__ import annotations

import ast
import json
import math
import re
from typing import Any

try:
    from .models import Finding, ParsedField, ParseResult, ParseStatus, ToolTraffic
except ImportError:  # flat-folder layout
    from models import Finding, ParsedField, ParseResult, ParseStatus, ToolTraffic

MAX_BYTES = 1_000_000
MAX_DEPTH = 32
MAX_FIELDS = 100_000


class _Pairs(list):
    """object_pairs_hook result: keeps duplicate keys and key order."""


class _TooDeep(Exception):
    pass


class _TooManyFields(Exception):
    pass


def _reject_constant(name: str) -> Any:  # NaN / Infinity are not valid JSON
    raise ValueError(f"non-standard JSON constant: {name}")


def _finite_float(token: str) -> float:
    """Decode JSON numbers without silently turning exponent overflow into infinity."""
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"JSON number is outside the supported finite range: {token}")
    return value


def _parse_failure_status(raw: str) -> ParseStatus:
    """INVALID_JSON = the payload tried to be JSON (object/array opener or a JSON
    constant) and failed. Anything else - prose, "Key: value" text, YAML, CSV,
    markdown, HTML, text starting with a quote - is NOT_JSON (another format)."""
    stripped = raw.strip()
    if (
        not stripped                      # empty result: handled separately later (C1)
        or stripped.startswith(("{", "["))
        or stripped in {"NaN", "Infinity", "-Infinity"}
    ):
        return ParseStatus.INVALID_JSON
    return ParseStatus.NOT_JSON


def _repair(raw: str) -> str:
    """Best-effort close of truncated JSON: drop trailing commas, close an open
    string and any open brackets. Purely textual; never evaluates anything."""
    out: list[str] = []
    stack: list[str] = []
    in_str = esc = False
    for ch in raw:
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]":
            while out and out[-1] in " \t\r\n,":
                out.pop()
            if stack:
                stack.pop()
        out.append(ch)
    if in_str:
        if esc:
            out.pop()
        out.append('"')
    while out and out[-1] in " \t\r\n,":
        out.pop()
    if out and out[-1] == ":":
        out.append("null")
    return "".join(out) + "".join(reversed(stack))


def _salvage(raw: str) -> Any | None:
    """Recover a JSON tree from broken JSON so its fields can be scored.
    Tries: Python literal (repr of a dict/list) -> repaired JSON. None if neither works."""
    stripped = raw.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:   # Python repr such as {'a': 1, 'b': None}; literal_eval is safe (no code execution)
        obj = ast.literal_eval(stripped)
        if isinstance(obj, (dict, list)):
            return json.loads(json.dumps(obj, default=str), object_pairs_hook=_Pairs)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        pass
    try:
        return json.loads(_repair(stripped), object_pairs_hook=_Pairs,
                          parse_constant=lambda _: None, parse_float=float)
    except (ValueError, RecursionError):
        return None


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

    def add_field(self, field: ParsedField) -> None:
        if len(self.fields) >= MAX_FIELDS:
            raise _TooManyFields
        self.fields.append(field)


def _walk(node: Any, path: str, parent: str | None, key: str | None, depth: int, ctx: _Ctx) -> None:
    if depth > MAX_DEPTH:
        raise _TooDeep(path)

    if isinstance(node, _Pairs):
        ctx.boundaries += 1
        ctx.add_field(ParsedField(path=path, key=key, parent_path=parent, depth=depth, value_type="object"))
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
        ctx.add_field(ParsedField(path=path, key=key, parent_path=parent, depth=depth, value_type="array"))
        for i, v in enumerate(node):
            _walk(v, f"{path}[{i}]", path, None, depth + 1, ctx)
    else:
        vt = ("null" if node is None else "boolean" if isinstance(node, bool)
              else "string" if isinstance(node, str) else "number")
        ctx.add_field(ParsedField(path=path, key=key, parent_path=parent, depth=depth,
                                  value_type=vt, value=node))  # type: ignore[arg-type]


def parse(traffic: ToolTraffic) -> ParseResult:
    raw = payload_text(traffic).lstrip("\ufeff")   # a leading BOM is not an attack
    ctx = _Ctx()
    status = ParseStatus.OK
    salvaged = False

    if len(raw.encode("utf-8", "ignore")) > MAX_BYTES:
        status = ParseStatus.TOO_LARGE
        ctx.findings.append(Finding(kind="payload_too_large", path="$", detail=f"> {MAX_BYTES} bytes"))
        raw = raw[:MAX_BYTES]
    else:
        try:
            tree = json.loads(
                raw,
                object_pairs_hook=_Pairs,
                parse_constant=_reject_constant,
                parse_float=_finite_float,
            )
            _walk(tree, "$", None, None, 0, ctx)
        except (_TooDeep, RecursionError):
            status = ParseStatus.TOO_DEEP
            ctx.findings.append(Finding(kind="depth_exceeded", path="$", detail=f"nesting deeper than {MAX_DEPTH}"))
        except _TooManyFields:
            status = ParseStatus.TOO_MANY_FIELDS
            ctx.findings.append(Finding(kind="field_limit_exceeded", path="$",
                                        detail=f"more than {MAX_FIELDS} parsed fields"))
        except ValueError as e:   # JSONDecodeError is a ValueError
            status = _parse_failure_status(raw)
            if status is ParseStatus.INVALID_JSON:
                tree = _salvage(raw)
                if tree is not None:
                    try:
                        _walk(tree, "$", None, None, 0, ctx)
                        salvaged = True
                    except (_TooDeep, _TooManyFields, RecursionError):
                        ctx.fields, ctx.boundaries = [], 0
                        ctx.findings = [f for f in ctx.findings if f.kind != "duplicate_key"]
                note = " (fields salvaged for scoring)" if salvaged else ""
                ctx.findings.append(Finding(kind="parse_failure", path="$",
                                            detail=f"{type(e).__name__}: {e}{note}"))

    if status is not ParseStatus.OK and not salvaged:  # default-untrusted: one opaque string node
        ctx.fields = [ParsedField(path="$", key=None, parent_path=None, depth=0,
                                  value_type="string", value=raw)]
        ctx.boundaries = 1

    return ParseResult(
        internal_id=traffic.internal_id, direction=traffic.direction,
        tool_name=traffic.tool_name, tool_call_id=traffic.tool_call_id,
        status=status, fields=ctx.fields, findings=ctx.findings,
        boundary_count=max(1, ctx.boundaries),
    )
