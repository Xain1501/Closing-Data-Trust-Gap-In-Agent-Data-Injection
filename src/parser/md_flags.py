"""Structural flags for MARKDOWN-style tool output (the 'markdown' format of the ADI benchmark).

EXPERIMENTAL: designed from ONE example (github_comments) and meant to be measured on
other markdown data (github_issue) before it is trusted.

The markdown transform renders a record as
    1. - **url**: https://...
    - **id**: 3729984323
    # user
    - **login**: eqy
Markdown has no quote characters to escape, so a forged field can look exactly like a real
line. Only CONSISTENCY signs are available (structure only, no words):

  * a numbered record ("2. - **url**:") whose number is not the next in sequence;
  * the same top-level record id used by two different records (a copied record);
  * a field marker ("- **key**:") in the MIDDLE of a line (an inline forged field).

LIMIT: a forged record with a fresh id and correct numbering on its own lines is
indistinguishable from a real one. That needs provenance (tagging / graph stages).
"""
from __future__ import annotations

import re

try:
    from .models import Finding, StructuralReport
except ImportError:  # flat-folder layout
    from models import Finding, StructuralReport

_ITEM = re.compile(r"^\s*(\d+)\.\s+-\s+\*\*")                      # "2. - **url**:" starts a record
_FIELD = re.compile(r"^\s*(?:\d+\.\s+)?-\s+\*\*([^*\n]+)\*\*:\s?(.*)$")
_HEADING = re.compile(r"^#{1,6}\s+\S")
_START = re.compile(r"(?:\d+\.\s+)?-\s+\*\*[^*\n]+\*\*:")            # marker at the start of a line
_MARK = re.compile(r"(?:^|\s)(?:\d+\.\s+)?-\s+\*\*[^*\n]+\*\*:")     # marker anywhere
_ID_KEY = re.compile(r"id(?:_[A-Za-z0-9]{4,})?")                    # 'id' or random-key 'id_ab12cd34'


def md_flags(text: str) -> StructuralReport:
    findings: list[Finding] = []
    fields = headings = 0
    items: list[dict] = []
    cur = None
    in_top = False
    for n, line in enumerate(text.splitlines(), start=1):
        if _ITEM.match(line):
            cur = {"num": int(_ITEM.match(line).group(1)), "line": n, "id": None}
            items.append(cur)
            in_top = True
        elif _HEADING.match(line):
            headings += 1
            in_top = False
        fm = _FIELD.match(line)
        if fm:
            fields += 1
            if cur is not None and in_top and cur["id"] is None and _ID_KEY.fullmatch(fm.group(1).strip()):
                cur["id"] = fm.group(2).strip()
        # an inline forged field marker in the middle of a line
        stripped = line.lstrip()
        marks = _MARK.findall(stripped)
        extra = len(marks) - (1 if _START.match(stripped) else 0)
        if extra > 0:
            findings.append(Finding(
                kind="illegal_delimiter", path=f"line:{n}",
                detail=f"field marker in the middle of a line: {marks[-1].strip()!r}"))
    seen: dict[str, int] = {}
    for i, it in enumerate(items):
        if it["num"] != i + 1:
            findings.append(Finding(
                kind="illegal_delimiter", path=f"line:{it['line']}",
                detail=f"record numbered {it['num']} where {i + 1} was expected"))
        if it["id"]:
            if it["id"] in seen:
                findings.append(Finding(
                    kind="duplicate_key", path=f"line:{it['line']}",
                    detail=f"record id {it['id']!r} already used by the record on line {seen[it['id']]}"))
            else:
                seen[it["id"]] = it["line"]
    boundaries = max(1, fields + headings)
    return StructuralReport(
        findings=findings, uncounted_findings=[], hit_count=len(findings),
        boundary_count=boundaries, structural_score=min(1.0, len(findings) / boundaries))