"""stage1.py - the single entry point of Stage 1 (proposal 6.2, deterministic parsing).

    result = analyze(traffic, fmt="json")      # fmt: "json" | "dom" | "markdown"

Works for BOTH directions (traffic.direction = pre_hop or post_hop): the same parser runs on an
outgoing call's arguments and on an incoming tool response (proposal 6.1 / 6.2).

Verdict (a label for the next stages, NOT a block decision):
  untrusted_default : JSON that does not parse (invalid_json / too_large / too_deep).
                      Proposal 6.2: content that does not parse is untrusted by default.
  flagged           : parsed, and at least `min_hits` counted signs of forged structure.
  clean             : parsed, fewer than `min_hits` signs.

Why hit_count and not S for the rule: S = hits / boundaries shrinks as a message grows, so a
single forged sign in a long message gets a tiny S. The rule uses hit_count; S is passed on
unchanged as a feature for the classifier. min_hits=1 is a DESIGN CHOICE to confirm with the
supervisor: it gave 0 false positives on every clean benign set tested so far.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

try:
    from .models import StructuralReport, ToolTraffic
    from .parser import parse
    from .structural import structural_flags
    from .dom_flag import dom_flags
    from .md_flags import md_flags
    from .schema_registry import ToolSchemaRegistry
except ImportError:  # flat-folder layout
    from models import StructuralReport, ToolTraffic
    from parser import parse
    from structural import structural_flags
    from dom_flag import dom_flags
    from md_flags import md_flags
    from schema_registry import ToolSchemaRegistry


@dataclass
class Stage1Result:
    verdict: str                      # "clean" | "flagged" | "untrusted_default"
    status: str                       # parse status, or "text" for dom / markdown
    report: object                    # StructuralReport (hit_count, structural_score, findings)
    reasons: list = field(default_factory=list)


def _as_text(payload) -> str:
    return payload if isinstance(payload, str) else json.dumps(payload)


def _markdown_report(traffic: ToolTraffic):
    """md_flags (record consistency) + the JSON text rules run over the whole markdown text."""
    text = _as_text(traffic.payload)
    a = md_flags(text)
    wrapped = ToolTraffic(direction=traffic.direction, tool_name=traffic.tool_name,
                          payload=json.dumps({"text": text}), internal_id=traffic.internal_id)
    b = structural_flags(parse(wrapped))
    findings = list(a.findings) + list(b.findings)
    bounds = max(1, a.boundary_count + b.boundary_count)
    return StructuralReport(findings=findings, uncounted_findings=[], hit_count=len(findings),
                            boundary_count=bounds, structural_score=min(1.0, len(findings) / bounds))


def analyze(traffic: ToolTraffic, fmt: str = "json", min_hits: int = 1,
            schema_registry: ToolSchemaRegistry | None = None) -> Stage1Result:
    if fmt == "dom":
        text = _as_text(traffic.payload)
        if not text.strip():
            rep = StructuralReport(findings=[], uncounted_findings=[], hit_count=0,
                                   boundary_count=1, structural_score=0.0)
            return Stage1Result("untrusted_default", "empty", rep, ["empty DOM payload; untrusted by default"])
        rep, status = dom_flags(text), "text"
    elif fmt == "markdown":
        if not _as_text(traffic.payload).strip():
            rep = StructuralReport(findings=[], uncounted_findings=[], hit_count=0,
                                   boundary_count=1, structural_score=0.0)
            return Stage1Result("untrusted_default", "empty", rep, ["empty markdown payload; untrusted by default"])
        rep, status = _markdown_report(traffic), "text"
    elif fmt == "json":
        res = parse(traffic)
        status = getattr(res.status, "value", str(res.status))
        schema_findings = schema_registry.validate(traffic) if schema_registry and status == "ok" else ()
        rep = structural_flags(res, schema_findings=schema_findings)
        if status != "ok":
            return Stage1Result("untrusted_default", status, rep,
                                [f"payload did not parse ({status}); untrusted by default"])
    else:
        raise ValueError(f"unknown fmt {fmt!r} (use json, dom or markdown)")
    if rep.hit_count >= min_hits:
        reasons = [f"{f.kind} at {f.path}: {f.detail}" for f in rep.findings]
        return Stage1Result("flagged", status, rep, reasons)
    return Stage1Result("clean", status, rep, [])
