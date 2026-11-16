"""Decision layer over parser evidence.

The parser reports evidence (fields, findings, parse health); this module is
the single place that turns it into allow / block. Rules, in order:

1. uninspectable        -> block  (otherwise 1.1 MB or 33 nesting levels skips the detector)
2. salvaged_repaired    -> block  (the model sees the raw broken text; we scored a guessed repair)
3. schema violation     -> block
4. any counted finding  -> block  ("any strong hit" rule, policy research section 12)
5. otherwise            -> allow  (clean JSON, clean text, empty result, clean Python-literal result)

The verdict is computed identically in passthrough and enforce mode; the clone
core decides whether a block is enforced or only logged.
"""
from __future__ import annotations

from dataclasses import dataclass

from pipeline.parser_analysis import ParserAnalysis


@dataclass(frozen=True)
class ParserVerdict:
    allowed: bool
    label: str
    reason: str
    contains_adi: bool


def decide(analysis: ParserAnalysis) -> ParserVerdict:
    parsed, report = analysis.parsed, analysis.structural
    contains_adi = report.hit_count > 0
    health = analysis.parse_health

    if health == "uninspectable":
        return ParserVerdict(False, "parser-untrusted",
                             f"Parser status: {parsed.status.value}; content could not be inspected.",
                             contains_adi)
    if health == "salvaged_repaired":
        return ParserVerdict(False, "parser-untrusted",
                             f"Parser status: {parsed.status.value}; truncated JSON was repaired by "
                             "guesswork, so the scored fields may differ from what the model reads.",
                             contains_adi)
    if analysis.schema_invalid:
        details = "; ".join(
            f"{finding.kind} at {finding.path}"
            for finding in [*report.findings, *report.uncounted_findings]
            if finding.kind in ("unexpected_key", "schema_violation")
        )
        return ParserVerdict(False, "schema-violation",
                             f"Tool schema validation failed: {details}.", contains_adi)
    if contains_adi:
        details = "; ".join(f"{finding.kind} at {finding.path}" for finding in report.findings[:3])
        return ParserVerdict(False, "adi-detected", f"Structural ADI findings: {details}.", contains_adi)
    note = "" if health == "clean" else f" (parse health: {health})"
    return ParserVerdict(True, "no-adi-detected", f"No counted structural ADI findings{note}.", False)
