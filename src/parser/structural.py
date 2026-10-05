"""Stage 1b - Structural flags and S (proposal 6.2 / 8.4.3 "structural flag").

Takes an ALREADY-PARSED ParseResult and looks for STRUCTURE hiding inside string
values AND key names. Instruction words ("ignore", "system:") are never used.

The patterns come from the paper's table of "inexact delimiters": an attacker
forges  {"k":"v"}  using look-alike characters, e.g.
    {\\"k\\":\\"v\\"}   {'k':'v'}   {"k":"v"} (curly)   {$k$:$v$}   (\\"k\\":\\"v\\")
so the main signal is a forged  <quote>key<quote> : value  pair, whatever the
quote/brace characters are. Text is also normalised before scanning (HTML
entities, %-encoding, fullwidth forms, zero-width characters).

HEURISTIC. Known limits are written as tests in test_structural.py.
"""
from __future__ import annotations

import html
import json
import re
import unicodedata
from collections.abc import Sequence
from typing import Any
from urllib.parse import unquote

from pydantic import TypeAdapter, ValidationError

try:
    from .models import Finding, ParseResult, ParseStatus, StructuralReport, ToolTraffic
    from .parser import _child_path, payload_text
except ImportError:  # flat-folder layout
    from models import Finding, ParseResult, ParseStatus, StructuralReport, ToolTraffic
    from parser import _child_path, payload_text

_Q = "\"'\u201c\u201d\u2018\u2019`"      # quote look-alikes
_QK = _Q + "$"                            # '$' is used as a quote in the paper ({$k$:$v$}) - key/value shape only

# COUNTED toward S (one finding per pattern per field)
_COUNTED: dict[str, re.Pattern[str]] = {
    # quote then } , or quote then ] followed by , } ]   (bare  "]  is too common in prose)
    "quote_close_structure": re.compile(rf"[{_Q}]\s*(?:[}}\uff5d]|[\]\uff3d]\s*[,}}\]\uff5d\uff3d])"),
    # a value ending and a new key starting:   ", "role":
    "key_injection": re.compile(rf"[{_Q}]\s*[,\uff0c]\s*[{_Q}][^{_Q}\n]{{1,64}}[{_Q}]\s*[:\uff1a=]"),
    "object_reopen": re.compile(r"[}\uff5d]\s*[,\uff0c]\s*[{\uff5b]"),                # }, {
    "array_close_object": re.compile(r"[\]\uff3d]\s*[}\uff5d]"),                       # ]}
    # forged key:value pair with ANY quote look-alike, optionally backslash-escaped
    "kv_forgery": re.compile(
        rf"\\?[{_QK}]\s*[\w\-. ]{{1,40}}?\s*\\?[{_QK}]\s*[:\uff1a]\s*(?:\\?[{_QK}]|[{{\[\d-]|true|false|null)"),
}
# NOT counted: plausible in benign content
_WEAK: dict[str, re.Pattern[str]] = {
    "code_fence": re.compile(r"```"),
    "chat_template_token": re.compile(r"<\|[a-z_]+\|>|\[/?INST\]|</?(?:system|tool_response|function_results)>", re.I),
}

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")


def _variants(s: str) -> list[str]:
    """The text as written + a normalised copy (entities, %-encoding, fullwidth, zero-width)."""
    t = s
    for _ in range(2):                       # twice, to catch double encoding
        t = html.unescape(t)
        if "%" in t:
            t = unquote(t)
    t = _INVISIBLE.sub("", unicodedata.normalize("NFKC", t))
    return [s] if t == s else [s, t]


def _scan_string(s: str, path: str, counted: list[Finding], weak: list[Finding]) -> None:
    variants = _variants(s)
    for table, out, kind in ((_COUNTED, counted, "illegal_delimiter"), (_WEAK, weak, "weak_signal")):
        for name, pat in table.items():
            for v in variants:
                if m := pat.search(v):        # one finding per pattern per field
                    out.append(Finding(kind=kind, path=path, detail=f"{name}: {m.group(0)!r}"))  # type: ignore[arg-type]
                    break
    t = s.strip()
    if t[:1] in ("{", "["):
        try:
            if isinstance(json.loads(t), (dict, list)):
                counted.append(Finding(kind="embedded_json", path=path,
                                       detail="string value is itself a JSON object/array"))
        except ValueError:
            pass


def _loc_to_path(loc: tuple[Any, ...]) -> str:
    p = "$"
    for part in loc:
        p = f"{p}[{part}]" if isinstance(part, int) else _child_path(p, str(part))
    return p


def check_schema(traffic: ToolTraffic, expected: Any) -> list[Finding]:
    """Optional: validate against a Pydantic model/type for this tool's response.
    Register models with ConfigDict(extra='forbid') so unknown keys are errors."""
    out: list[Finding] = []
    try:
        TypeAdapter(expected).validate_python(json.loads(payload_text(traffic).lstrip("\ufeff")))
    except ValidationError as e:
        for err in e.errors():
            kind = "unexpected_key" if err["type"] == "extra_forbidden" else "schema_violation"
            detail = "key not in the tool's expected schema" if kind == "unexpected_key" else err["msg"]
            out.append(Finding(kind=kind, path=_loc_to_path(err["loc"]), detail=detail))   # type: ignore[arg-type]
    except ValueError:
        pass   # not JSON: parse() already reported it via status
    return out


def structural_flags(result: ParseResult, schema_findings: Sequence[Finding] = ()) -> StructuralReport:
    """S = min(1, counted hits / boundaries). Only meaningful when status is OK;
    otherwise S = 0 and the status itself carries the (default-untrusted) signal."""
    if result.status is not ParseStatus.OK:
        return StructuralReport(findings=[], uncounted_findings=[], hit_count=0,
                                boundary_count=result.boundary_count, structural_score=0.0)

    counted = [f for f in result.findings if f.kind == "duplicate_key"]
    weak: list[Finding] = []
    for f in result.fields:
        if f.value_type == "string" and isinstance(f.value, str):
            _scan_string(f.value, f.path, counted, weak)
        if f.key:                                         # attacker-controlled key names too
            _scan_string(f.key, f"{f.path}#key", counted, weak)
    for sf in schema_findings:
        (counted if sf.kind == "unexpected_key" else weak).append(sf)

    return StructuralReport(
        findings=counted, uncounted_findings=weak, hit_count=len(counted),
        boundary_count=result.boundary_count,
        structural_score=min(1.0, len(counted) / result.boundary_count),
    )