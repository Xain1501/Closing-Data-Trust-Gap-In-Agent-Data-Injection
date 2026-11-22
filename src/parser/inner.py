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
import json
import re
from collections import Counter
from collections.abc import Sequence
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
    text: str = ""                      # the row's own text: a copied whole row links to it


@dataclass(frozen=True)
class Records:
    kind: Literal["table", "kv", "json"]
    rows: tuple[Row, ...]
    width: int = 0                      # dominant column count (tables)
    separator: str | None = None
    truncated: bool = False             # rows beyond MAX_ROWS were not split
    conflicts: tuple[tuple[int, str], ...] = field(default=())   # kv: (row, key) pairs that conflict
    header: tuple[str, ...] = ()        # tables: normalised column names from a header row
    header_row: int = 0                 # index of that header row


@dataclass(frozen=True)
class Token:
    kind: str                           # iban | email | url | phone | amount | date
    value: str
    offset: int


MAX_TOKENS = 500
_TOKENS = (
    ("email", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")),
    ("url", re.compile(r"\bhttps?://[^\s<>\"')\]]+|\bwww\.[^\s<>\"')\]]+")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")),
    ("phone", re.compile(r"(?<![\w+])\+\d[\d\s().-]{7,}\d\b")),
    ("date", re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?\b")),
    ("amount", re.compile(r"(?<![\w.,-])(?:[$€£]\s?)?\d{1,3}(?:,\d{3})*\.\d{1,2}(?![\w.])"
                          r"|(?<![\w.,-])[$€£]\s?\d+(?![\w.])")),
)
# Markdown / mail claim headers: who says they wrote this, and in which role.
_CLAIMS = (
    re.compile(r"^\s*(?:[*_]{1,2})?@?(?P<author>[A-Za-z0-9][\w.-]{0,38})(?:[*_]{1,2})?\s+"
               r"(?:commented|wrote|replied|said|approved|reviewed)\b"
               r"(?:[^(\n]{0,40}\((?P<role>[A-Za-z_ ]{2,30})\))?"),
    re.compile(r"^\s*>?\s*On .{0,80}?,\s*(?P<author>[^,<>\n]{2,60}?)\s*(?:<[^>]+>\s*)?wrote:"),
)
_EMPHASIS = re.compile(r"\*{1,3}|`+|(?<!\w)_{1,2}|_{1,2}(?!\w)")   # keeps snake_case keys


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
    """Rows and cells of a table, key-value block or embedded JSON inside ``text``, else None."""
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        return None
    if "\n" not in text:
        return _embedded_json(text)
    return _table(text) or _kv(text) or _embedded_json(text)


def split_tokens(text: str) -> tuple[Token, ...]:
    """Identifier and number tokens anywhere in a text (IBAN, email, URL, phone, date,
    amount), in order, without overlaps. A token that is the whole text is skipped:
    the leaf itself already carries that value."""
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        return ()
    found: list[Token] = []
    taken: list[tuple[int, int]] = []
    for kind, rx in _TOKENS:
        for m in rx.finditer(text):
            start, end = m.span()
            if any(start < e and s < end for s, e in taken):
                continue
            value = m.group(0).rstrip(".,;:")
            if value.strip() == text.strip():
                continue
            taken.append((start, start + len(value)))
            found.append(Token(kind, value, start))
    found.sort(key=lambda t: t.offset)
    return tuple(found[:MAX_TOKENS])


def _embedded_json(text: str) -> Records | None:
    """A JSON object or array written inside a string: its leaves as one record whose
    cell labels are dotted key paths (``role``, ``user.login``)."""
    start = next((i for i, ch in enumerate(text) if ch in "{["), None)
    if start is None:
        return None
    try:
        value, _ = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return None
    if not isinstance(value, (dict, list)) or not value:
        return None
    cells: list[Cell] = []

    def walk(node, prefix: str) -> None:
        if len(cells) >= MAX_ROWS:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{prefix}[{i}]")
        else:
            label = normalise_key(re.sub(r"\[\d+\]", "", prefix).replace(".", " ")) or prefix
            cells.append(Cell(label, "" if node is None else str(node), 0))

    walk(value, "")
    if not cells:
        return None
    return Records("json", (Row(tuple(cells), text[start:start + 2000]),))


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
        rows.append(Row(tuple(Cell(str(i), p.strip(), n) for i, p in enumerate(parts)), line.strip()))
    width = mode + 1 if sep != "|" else Counter(len(r.cells) for r in rows).most_common(1)[0][0]
    header, header_row = _header(rows, width)
    return Records("table", tuple(rows), width=width, separator=sep, truncated=truncated,
                   header=header, header_row=header_row)


def _header(rows: list[Row], width: int) -> tuple[tuple[str, ...], int]:
    """Normalised column names and the header's row index, when the first full-width
    row (after any preamble such as "Review summary:") is a header: every cell is a
    short name (no number, no identifier) and the row does not repeat later."""
    idx = next((i for i, r in enumerate(rows) if len(r.cells) == width), None)
    if idx is None or idx >= len(rows) - 1:
        return (), 0
    first = [c.value for c in rows[idx].cells]
    if any(not v or len(v) > 40 or is_identifier(v) or re.fullmatch(r"[\d.,\s%$€£-]+", v)
           for v in first):
        return (), 0
    names = tuple(normalise_key(v) or v.lower() for v in first)
    if len(set(names)) != len(names) or any(r.text == rows[idx].text for r in rows[idx + 1:]):
        return (), 0
    return names, idx


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
            rows.append(Row(tuple(current), "\n".join(
                lines[c] for c in dict.fromkeys(cell.line for cell in current))))
        current, seen = [], {}

    lines = text.splitlines()

    pairs_found = 0
    in_code = False
    for n, line in enumerate(text.splitlines()):
        if line.lstrip().startswith(("```", "~~~")):
            in_code = not in_code             # code is not key-value data: x = 1 ... x = 2
            continue
        if in_code:
            continue
        claim = next((m for m in (rx.match(line) for rx in _CLAIMS) if m), None)
        if claim is not None:                     # "**@eqy** commented (OWNER):" is a record header
            close()
            cells = [Cell("author", claim.group("author").strip(), n)]
            role = claim.groupdict().get("role")
            if role:
                cells.append(Cell("role", role.strip(), n))
            rows.append(Row(tuple(cells), line.strip()))
            pairs_found += len(cells)
            continue
        line = _EMPHASIS.sub("", line)            # "**Author:** x" reads as "Author: x"
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
            rows.append(Row(tuple(cells), line.strip()))
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
    if pairs_found < 2 and not any(c.label in ("author", "role") for r in rows for c in r.cells):
        return None
    return Records("kv", tuple(rows), conflicts=tuple(conflicts))


# ------------------------------------------------------------- inner fields ----
def row_path(leaf_path: str, i: int) -> str:
    return f"{leaf_path}.@row[{i}]"


def cell_path(leaf_path: str, i: int, j: int) -> str:
    return f"{row_path(leaf_path, i)}.@col[{j}]"


def token_path(leaf_path: str, k: int) -> str:
    return f"{leaf_path}.@tok[{k}]"


def cell_key(records: Records, i: int, cell: Cell) -> str | None:
    """A cell's key: its key-value / JSON key, or its table column name (header rows
    themselves have none)."""
    if records.kind in ("kv", "json"):
        return cell.label
    if records.header and i > records.header_row:
        col = int(cell.label)
        return records.header[col] if col < len(records.header) else None
    return None


def inner_fields(records: Records, leaf_path: str, depth: int) -> tuple[ParsedField, ...]:
    """Row and cell fields under one string leaf. A row carries its own text as value,
    so an argument that copies a whole row links to that row."""
    out: list[ParsedField] = []
    for i, row in enumerate(records.rows):
        rp = row_path(leaf_path, i)
        out.append(ParsedField(path=rp, key=None, parent_path=leaf_path, depth=depth + 1,
                               value_type="string", value=row.text or None))
        for j, cell in enumerate(row.cells):
            out.append(ParsedField(path=cell_path(leaf_path, i, j), key=cell_key(records, i, cell),
                                   parent_path=rp, depth=depth + 2,
                                   value_type="string", value=cell.value))
    return tuple(out)


def token_fields(tokens: tuple[Token, ...], leaf_path: str, depth: int) -> tuple[ParsedField, ...]:
    """One field per token; amounts are numbers, so number arguments can link to them."""
    out: list[ParsedField] = []
    for k, tok in enumerate(tokens):
        value: str | float = tok.value
        value_type = "string"
        if tok.kind == "amount":
            digits = re.sub(r"[^\d.]", "", tok.value)
            try:
                value, value_type = float(digits), "number"
            except ValueError:
                pass
        out.append(ParsedField(path=token_path(leaf_path, k), key=tok.kind, parent_path=leaf_path,
                               depth=depth + 1, value_type=value_type, value=value))
    return tuple(out)


def leaf_inner_fields(text: str, leaf_path: str, depth: int) -> tuple[ParsedField, ...]:
    """Everything inferred inside one string leaf: records (rows, cells) then tokens."""
    records = split_records(text)
    out = inner_fields(records, leaf_path, depth) if records is not None else ()
    return out + token_fields(split_tokens(text), leaf_path, depth)


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


# ---------------------------------------------------------------- mimicry ----
# Untrusted text that copies a trusted field. The trusted reference is the result
# object's own structure: its key names and each field's own value (from the skeleton).
# Text inside one field cannot rename another field or change its value.
_KEY_GROUPS = {
    "author": ("author", "login", "user login", "username", "user", "sender", "from",
               "owner login", "commenter"),
    "role": ("role", "author association", "association", "permission", "permissions",
             "user role"),
    "recipient": ("recipient", "recipients", "to", "receiver"),
}
_GROUP_OF = {k: g for g, keys in _KEY_GROUPS.items() for k in keys}
_QUOTE_BLOCK = re.compile(r"^\s*(>|-{3,}\s*forwarded|begin forwarded|-{3,}\s*original message)", re.I)


def canonical_key(key: str | None) -> str:
    """A key as a comparable name: 'author_association' -> 'role', 'user.login' -> 'author'.
    "" for index-like or numeric keys ('[1]', '+1', '2024'): they name positions or
    counters, never a field an attacker could impersonate."""
    if not key:
        return ""
    k = normalise_key(key.replace(".", " ").replace("_", " ").replace("-", " "))
    if not re.search(r"[a-z]", k):
        return ""
    return _GROUP_OF.get(k, k)


def _same(a: object, b: object) -> bool:
    def norm(v: object) -> str:
        return str(v).strip().lstrip("@").casefold()
    return norm(a) == norm(b)


def _common_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def mimicry_findings(
    real_fields: Sequence[ParsedField], inner: Sequence[ParsedField],
) -> tuple[list[Finding], list[Finding]]:
    """Counted ``mimicry`` and logged ``weak_signal`` findings.

    Contradiction (counted): an inner node's key names a real field of the same object
      and its value differs from that field's value (body says ``role: OWNER``, the
      comment's real ``author_association`` is ``NONE``).
    Shadow key (logged): the key names a real field, values agree.
    Claims inside a quoted or forwarded block are logged only: quoting is normal.
    A counted finding is reported on the inner node, its row and the row's cells.
    """
    reference: dict[str, list[ParsedField]] = {}
    for f in real_fields:
        if f.value_type in ("object", "array") or f.key is None:
            continue
        names = {canonical_key(f.key)}
        parent = f.parent_path.rsplit(".", 1)[-1] if f.parent_path and "." in f.parent_path else ""
        if parent and not parent.startswith("$"):
            names.add(canonical_key(f"{parent} {f.key}"))
        for name in names:
            if name:
                reference.setdefault(name, []).append(f)
    if not reference:
        return [], []
    by_path = {f.path: f for f in inner}
    children: dict[str, list[ParsedField]] = {}
    for f in inner:
        if f.parent_path:
            children.setdefault(f.parent_path, []).append(f)

    counted: list[Finding] = []
    logged: list[Finding] = []
    for node in inner:
        if node.key is None or ".@tok[" in node.path or node.value in (None, ""):
            continue
        name = canonical_key(node.key)
        candidates = reference.get(name)
        if not candidates:
            continue
        leaf = node.path.split(".@", 1)[0]
        real = max(candidates, key=lambda f: _common_prefix(f.path, leaf))
        if real.path == leaf:
            continue
        row = by_path.get(node.parent_path or "")
        quoted = row is not None and isinstance(row.value, str) and bool(_QUOTE_BLOCK.match(row.value))
        if _same(node.value, real.value):
            logged.append(Finding(kind="weak_signal", path=node.path,
                                  detail=f"mimicry_shadow: repeats real field {real.path}"))
            continue
        detail = f"mimicry: '{node.key}' contradicts real field {real.path}"
        if quoted:
            logged.append(Finding(kind="weak_signal", path=node.path, detail=f"{detail} (quoted)"))
            continue
        targets = [node.path]
        if row is not None:
            targets += [row.path] + [c.path for c in children.get(row.path, [])]
        for path in dict.fromkeys(targets):
            counted.append(Finding(kind="mimicry", path=path, detail=detail, ref_path=real.path))
    return counted, logged


def localise(text: str, leaf_path: str, matches: Sequence[str]) -> list[str]:
    """Paths of the rows, cells and tokens on the line(s) where a delimiter match was
    found, so a forgery flag lands on those values and not on everything in the leaf."""
    if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
        return []
    spans: list[tuple[int, int]] = []
    for m in matches:
        start = text.find(m)
        if start < 0:
            continue
        line_start = text.rfind("\n", 0, start) + 1
        end = text.find("\n", start + len(m))
        spans.append((line_start, len(text) if end < 0 else end))
    if not spans:
        return []
    lines = {text.count("\n", 0, s) for s, _ in spans} | {text.count("\n", 0, e) for _, e in spans}
    out: list[str] = []
    records = split_records(text)
    if records is not None:
        for i, row in enumerate(records.rows):
            if any(c.line in lines for c in row.cells):
                out.append(row_path(leaf_path, i))
                out.extend(cell_path(leaf_path, i, j) for j in range(len(row.cells)))
    for k, tok in enumerate(split_tokens(text)):
        if any(s <= tok.offset < e for s, e in spans):
            out.append(token_path(leaf_path, k))
    return out

