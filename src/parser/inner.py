"""Inner skeleton: records written inside ONE string leaf, and forgery checks on them.

ADI hides forged structure inside a single real field: a forged CSV row in a file's
``content``, a second ``IBAN:`` line in a bill, a repeated ``recipient:`` in an email
body. The result object gives no boundary inside that string, so this module adds one
level: a string that holds records (a delimited table, or ``key: value`` lines) is
split into rows and cells. It knows nothing about tools.

    split_records(text)                      -> Records | None
    inner_fields(records, leaf_path, depth)  -> ParsedField rows / cells under the leaf
    record_findings(records, leaf_path)      -> (counted, logged) Findings

Sub-field paths use ``.@row[i]`` / ``.@row[i].@col[j]``. They never use ``#`` (finding
paths with ``#`` are collapsed onto their field), and ``@`` cannot clash with a real key
(the parser writes such keys as ``["@row"]``).

Checks (counted ones are ``record_conflict`` findings; the rest are logged only):
  dup_identifier   counted  an identifier column (email / IBAN / URL / phone) repeats a value
  conflicting_key  counted  one record gives the same key two different values
  dup_entity       logged   a table's first column repeats a name
  odd_row          logged   a row's column count differs from the table's
A forgery with a NEW identity or only NEW keys contradicts nothing and is not caught.
"""
from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

try:
    from .models import Finding, ParsedField
except ImportError:  # flat-folder layout
    from models import Finding, ParsedField

MAX_TEXT_CHARS = 200_000
MAX_ROWS = 2_000
_MIN_TABLE_LINES = 3
_DOMINANT_SHARE = 0.6
_SEPARATORS = (",", "\t", "|", ";")

_IDENT = tuple(re.compile(p, re.I) for p in (
    r"^[^@\s,]+@[^@\s,]+\.[a-z]{2,}$",          # email
    r"^[A-Z]{2}\d{2}[A-Z0-9]{8,30}$",            # IBAN (spaces removed first)
    r"^(https?://|www\.)\S+$",                   # URL
    r"^\+?(?:[\d\s().-]*\d){9,}$",               # phone
))
_KV = re.compile(r"^\s*([A-Za-z][\w ./()-]{0,40}?)\s*[:=]\s*(\S.*?)\s*$")
_FILLER = frozenset({"new", "updated", "correct", "current", "the", "our", "your", "a", "an"})
_MD_RULE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


@dataclass(frozen=True)
class Cell:
    label: str          # column number (table) or normalised key (key-value)
    value: str
    line: int           # 0-based line in the leaf text


@dataclass(frozen=True)
class Row:
    cells: tuple[Cell, ...]


@dataclass(frozen=True)
class Records:
    kind: Literal["table", "kv"]
    rows: tuple[Row, ...]
    width: int = 0                      # dominant column count (tables)
    separator: str | None = None
    truncated: bool = False             # rows beyond MAX_ROWS were not split
    conflicts: tuple[tuple[int, str], ...] = field(default=())   # kv: (row, key) pairs that conflict


def is_identifier(value: str) -> bool:
    v = value.strip()
    if re.match(r"^[A-Z]{2}\d{2}", v):
        v = v.replace(" ", "")
    return any(p.match(v) for p in _IDENT)


def normalise_key(key: str) -> str:
    """Lower-cased key without filler words; "" for a key that is not a name, such as a
    log prefix with a timestamp ("W0109 09:12:...")."""
    if re.search(r"\d{3,}", key):
        return ""
    return " ".join(w for w in re.findall(r"[a-z0-9]+", key.lower()) if w not in _FILLER)


# ------------------------------------------------------------------ splitting ----
def split_records(text: str) -> Records | None:
    """Rows and cells of a table or key-value block written inside ``text``, else None."""
    if not isinstance(text, str) or "\n" not in text or len(text) > MAX_TEXT_CHARS:
        return None
    return _table(text) or _kv(text)


def _table(text: str) -> Records | None:
    numbered = [(n, line) for n, line in enumerate(text.splitlines())
                if line.strip() and not _MD_RULE.match(line)]
    if len(numbered) < _MIN_TABLE_LINES:
        return None
    best = None
    for sep in _SEPARATORS:
        counts = [line.count(sep) for _, line in numbered]
        mode = max(set(counts), key=counts.count)
        hits = counts.count(mode)
        if mode >= 1 and hits >= max(_MIN_TABLE_LINES, _DOMINANT_SHARE * len(numbered)):
            if best is None or hits > best[2]:
                best = (sep, mode, hits)
    if best is None:
        return None
    sep, mode, _ = best
    if mode == 1 and sep == "," and _looks_like_prose(numbered):
        return None
    truncated = len(numbered) > MAX_ROWS
    numbered = numbered[:MAX_ROWS]
    rows = []
    for n, line in numbered:
        if sep == ",":
            parts = next(csv.reader([line]), [])
        else:
            parts = line.split(sep)
            if sep == "|":                        # markdown: drop the empty edge cells
                if parts and not parts[0].strip():
                    parts = parts[1:]
                if parts and not parts[-1].strip():
                    parts = parts[:-1]
        rows.append(Row(tuple(Cell(str(i), p.strip(), n) for i, p in enumerate(parts))))
    width = mode + 1 if sep != "|" else Counter(len(r.cells) for r in rows).most_common(1)[0][0]
    return Records("table", tuple(rows), width=width, separator=sep, truncated=truncated)


def _looks_like_prose(numbered: list[tuple[int, str]]) -> bool:
    """Two "columns" split by one comma: prose when a line ends on the comma
    ("Dear Bob,") or a side reads as a sentence (five or more words)."""
    for _, line in numbered:
        left, _, right = line.partition(",")
        if not right.strip() or len(left.split()) >= 5 or len(right.split()) >= 5:
            return True
    return False


def _kv(text: str) -> Records | None:
    """Key-value lines. A line holding several ``Key: v, Key: v`` pairs is one record of its
    own (a list of records, e.g. flights); single-pair lines are grouped into records."""
    rows: list[Row] = []
    conflicts: list[tuple[int, str]] = []
    current: list[Cell] = []
    seen: dict[str, str] = {}

    def close() -> None:
        nonlocal current, seen
        if current:
            rows.append(Row(tuple(current)))
        current, seen = [], {}

    pairs_found = 0
    in_code = False
    for n, line in enumerate(text.splitlines()):
        if line.lstrip().startswith(("```", "~~~")):
            in_code = not in_code             # code is not key-value data: x = 1 ... x = 2
            continue
        if in_code:
            continue
        inline = [m for m in (_KV.match(p) for p in re.split(r",\s+(?=[A-Za-z][\w ]{0,40}:)", line)) if m]
        if len(inline) >= 2:                      # one whole record on this line
            close()
            cells, keys = [], {}
            for m in inline:
                key, value = normalise_key(m.group(1)), m.group(2).strip()
                if key:
                    if key in keys and keys[key].lower() != value.lower() and len(value) >= 3:
                        conflicts.append((len(rows), key))
                    keys.setdefault(key, value)
                    cells.append(Cell(key, value, n))
            rows.append(Row(tuple(cells)))
            pairs_found += len(cells)
            continue
        m = _KV.match(line)
        if not m:
            continue
        key, value = normalise_key(m.group(1)), m.group(2).strip()
        if not key or len(value) < 3:
            continue
        pairs_found += 1
        if key in seen:
            # A repeat of the record's FIRST key after other keys starts the next record
            # (a list of records). Any other repeat with a different value is a conflict.
            if current and current[0].label == key and len(seen) >= 2:
                close()
            elif seen[key].lower() != value.lower():
                conflicts.append((len(rows), key))
        seen.setdefault(key, value)
        current.append(Cell(key, value, n))
        if len(rows) >= MAX_ROWS:
            break
    close()
    if pairs_found < 2:
        return None
    return Records("kv", tuple(rows), conflicts=tuple(conflicts))


# ------------------------------------------------------------- inner fields ----
def row_path(leaf_path: str, i: int) -> str:
    return f"{leaf_path}.@row[{i}]"


def cell_path(leaf_path: str, i: int, j: int) -> str:
    return f"{row_path(leaf_path, i)}.@col[{j}]"


def inner_fields(records: Records, leaf_path: str, depth: int) -> tuple[ParsedField, ...]:
    """Row (object) and cell (string) fields under one string leaf."""
    out: list[ParsedField] = []
    for i, row in enumerate(records.rows):
        rp = row_path(leaf_path, i)
        out.append(ParsedField(path=rp, key=None, parent_path=leaf_path, depth=depth + 1,
                               value_type="object"))
        for j, cell in enumerate(row.cells):
            out.append(ParsedField(path=cell_path(leaf_path, i, j),
                                   key=cell.label if records.kind == "kv" else None,
                                   parent_path=rp, depth=depth + 2,
                                   value_type="string", value=cell.value))
    return tuple(out)


# ----------------------------------------------------------------- checks ----
def record_findings(records: Records, leaf_path: str) -> tuple[list[Finding], list[Finding]]:
    """Counted (``record_conflict``) and logged (``weak_signal``) findings.

    A counted finding is reported on the row AND on each of its cells, so tagging marks
    every value copied out of that row as coming from a forged source. Every row involved
    is flagged: which of two rows sharing an identifier is the forged one is unknowable.
    """
    counted: list[Finding] = []
    logged: list[Finding] = []

    def flag(i: int, detail: str) -> None:
        counted.append(Finding(kind="record_conflict", path=row_path(leaf_path, i), detail=detail))
        for j, _ in enumerate(records.rows[i].cells):
            counted.append(Finding(kind="record_conflict", path=cell_path(leaf_path, i, j),
                                   detail=detail))

    rows = records.rows
    if records.kind == "table":
        for col in range(records.width):
            values = [(i, r.cells[col].value) for i, r in enumerate(rows)
                      if len(r.cells) > col and r.cells[col].value]
            if not values or sum(is_identifier(v) for _, v in values) < _DOMINANT_SHARE * len(values):
                continue
            by_value: dict[str, list[int]] = {}
            for i, v in values:
                by_value.setdefault(v.lower().replace(" ", ""), []).append(i)
            for v, idx in by_value.items():
                if len(idx) > 1:
                    for i in idx:
                        flag(i, f"dup_identifier: column {col} repeats an identifier")
        firsts = Counter(re.sub(r"\(.*?\)", "", r.cells[0].value).strip().lower()
                         for r in rows if r.cells and r.cells[0].value)
        for name, count in firsts.items():
            if count > 1 and len(name) > 2 and not is_identifier(name):
                logged.append(Finding(kind="weak_signal", path=leaf_path,
                                      detail="dup_entity: first column repeats a name"))
        odd = [i for i, r in enumerate(rows) if len(r.cells) != records.width]
        if odd:
            logged.append(Finding(kind="weak_signal", path=row_path(leaf_path, odd[0]),
                                  detail=f"odd_row: {len(odd)} row(s) differ from {records.width} columns"))
    else:
        for i, key in dict.fromkeys(records.conflicts):
            flag(i, f"conflicting_key: '{key}' has two different values in one record")
    # A row flagged by two rules is still one flag per path.
    unique = list({(f.path, f.detail): f for f in counted}.values())
    return unique, logged


def scan_leaf(text: str, leaf_path: str) -> tuple[list[Finding], list[Finding]]:
    records = split_records(text)
    if records is None:
        return [], []
    return record_findings(records, leaf_path)
