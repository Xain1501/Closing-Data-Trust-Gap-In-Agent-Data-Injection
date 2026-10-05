
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from pydantic import TypeAdapter, ValidationError

from models import Finding, ParseResult, ParseStatus, StructuralReport, ToolTraffic
from parser import _child_path, payload_text

_Q = "\"'\u201c\u201d\u2018\u2019`"          # ASCII + smart quotes + backtick
_CLOSE = r"}\]\uff5d\uff3d"                    # } ] and fullwidth look-alikes
_OPEN = r"{\[\uff5b\uff3b"

# COUNTED toward S
_COUNTED: dict[str, re.Pattern[str]] = {
    "quote_close_structure": re.compile(rf"[{_Q}]\s*[{_CLOSE}]"),                       # ..."}  ...”］
    "key_injection":         re.compile(rf"[{_Q}]\s*[,\uff0c]\s*[{_Q}][^{_Q}\n]{{1,64}}[{_Q}]\s*[:\uff1a=]"),
    "object_reopen":         re.compile(rf"[}}\uff5d]\s*[,\uff0c]\s*[{{\uff5b]"),        # }, {
    "array_close_object":    re.compile(r"[\]\uff3d]\s*[}\uff5d]"),                      # ]}
}
# NOT counted: plausible in benign content (code in emails, quoted chat logs)
_WEAK: dict[str, re.Pattern[str]] = {
    "code_fence":          re.compile(r"```"),
    "chat_template_token": re.compile(r"<\|[a-z_]+\|>|\[/?INST\]|</?(?:system|tool_response|function_results)>", re.I),
}


def _scan_string(s: str, path: str, counted: list[Finding], weak: list[Finding]) -> None:
    # one finding per pattern per field, so a single long string can't inflate S by repetition
    for name, pat in _COUNTED.items():
        if m := pat.search(s):
            counted.append(Finding(kind="illegal_delimiter", path=path, detail=f"{name}: {m.group(0)!r}"))
    for name, pat in _WEAK.items():
        if m := pat.search(s):
            weak.append(Finding(kind="weak_signal", path=path, detail=f"{name}: {m.group(0)!r}"))
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
        TypeAdapter(expected).validate_python(json.loads(payload_text(traffic)))
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
    for sf in schema_findings:
        (counted if sf.kind == "unexpected_key" else weak).append(sf)

    return StructuralReport(
        findings=counted, uncounted_findings=weak, hit_count=len(counted),
        boundary_count=result.boundary_count,
        structural_score=min(1.0, len(counted) / result.boundary_count),
    )
