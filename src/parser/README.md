# Parser (Stage 1) - Closing the Data Trust Gap in Agent Data Injection

This folder is **Stage 1 of the Detector Agent**: it opens a tool message, breaks it into
addressable fields, and measures how much *fake structure* is hiding inside the text values.
It makes **no trust decision** - tagging (Trusted / Untrusted), the provenance graph, the
classifier and the risk gate are later stages (not built yet).

```
tool message --> parse() --> ParseResult --> structural_flags() --> StructuralReport (S)
 (JSON string     fields + status             counts fake-structure signs
  or dict)        + duplicate keys
text/DOM output ------------------------------> dom_flags() ------> StructuralReport
```

## 1. Files

| File | Role | Needed? |
|---|---|---|
| `models.py` | Shared data forms (Pydantic). Every stage passes data in these shapes. | **Core** |
| `parser.py` | `parse()`: JSON -> addressed fields + status. No scoring. | **Core** |
| `structural.py` | `structural_flags()`: the structural score **S** for JSON. Also `check_schema()`. | **Core** |
| `dom_flags.py` | `dom_flags()`: same idea for **text-format** output (web DOM pages). | **Core** (needed for the web_dom benchmark) |
| `test_parser.py` | 28 tests for `parse()` (statuses, paths, duplicate keys, odd JSON). | Keep |
| `test_structural.py` | 52 tests: paper delimiter variants, encodings, benign text, speed, known limits. | Keep |
| `test_dom.py` | 10 tests for `dom_flags()` (called `test_dom_flags.py` in some copies). | Keep |
| `eval.py` | Runs a benchmark file (`.json` list or `.jsonl`) and reports benign-flagged vs attack-flagged. | Keep |
| `agentdojo_offline.py` | Replays real AgentDojo tasks (no LLM, no API key) through the parser. | Keep |
| `demo.py` | Five hand-made examples that print results. For showing the idea. | Optional |
| `agentdojo_element.py` | **Unfinished** connector for AgentDojo's agent pipeline. Nothing uses it yet. | Optional - delete or keep for later |
| `dataset.jsonl` | The benchmark data (web_dom cases). | Data |
| `__pycache__/`, `.pytest_cache/` | Python's automatic leftovers. | **Delete / .gitignore** |

All modules import in **both** layouts (as a package with relative imports, or as loose files in one folder).

## 2. Setup and commands (Windows PowerShell)

```
pip install pydantic pytest agentdojo        # Python 3.12 tested
cd <this folder>                             # e.g. ...\src\parser
python -m pytest                             # expect: 90 passed
python demo.py                               # 5 printed examples
python agentdojo_offline.py                  # real AgentDojo replay (loads data; ~1 minute)
python eval.py dataset.jsonl                 # benchmark file
```

Why some commands print nothing: `parser.py`, `structural.py`, `models.py` and the `test_*.py`
files only define functions - **pytest** runs the tests. `python -m` takes a dotted module name
with no `.py` and no slashes.

## 3. What each stage does

### 3.1 `models.py` - the shared forms
| Model | Meaning |
|---|---|
| `ToolTraffic` | One message entering the guard: `direction` (pre_hop / post_hop), `tool_name`, `payload` (string, dict or list), `internal_id`. The canonical shape for live runs, training and evaluation. |
| `ParseStatus` | `ok`, `invalid_json`, `too_large`, `too_deep`. Says *whether* we could parse - never mixed into S. |
| `ParsedField` | One field: `path` (`$.emails[0].body`), `key`, `parent_path` (graph edge), `depth`, `value_type`, `value`. Becomes a graph node later. |
| `Finding` | One noted problem: `kind`, `path`, `detail`. |
| `ParseResult` | Output of `parse()`: `status`, `fields`, `findings`, `boundary_count`. **No score.** |
| `StructuralReport` | Output of the structural step: `findings` (counted), `uncounted_findings`, `hit_count`, `boundary_count`, `structural_score`. |
| `LabeledCase` | A test case with `label` benign/attack; attack cases must have an `attack_type`. |
| `DecisionLogRecord` | A log entry that stores the **full raw** `ToolTraffic` (so logs can be replayed as training data). |
| `Trust`, `TaggedField` | Placeholders for the tagging stage (not used yet). |

Pydantic is used to **check the shape** of these forms (e.g. S must be 0..1) and to check a
tool's expected response schema. It is deliberately **not** used to read raw JSON: it keeps only
the last copy of a repeated key, which would hide duplicate-key forgery. Python's `json` reads
the data instead.

### 3.2 `parser.py` - `parse(traffic) -> ParseResult`
- Strict JSON only; NaN/Infinity rejected; a leading BOM is tolerated.
- Limits: 1,000,000 bytes (`too_large`), nesting depth 32 (`too_deep`).
- Every field gets an address and a parent link. Duplicate keys stay visible (`$.to`, `$.to#2`).
- On any failure: a status, and the whole payload becomes **one untrusted blob**.
- Computes nothing about suspicion.

### 3.3 `structural.py` - `structural_flags(result) -> StructuralReport`
**S = min(1, counted signs / boundaries)**, where boundaries = objects + arrays + keys.

Counted signs (each pattern counts at most once per field):

| Sign | Looks like |
|---|---|
| `quote_close_structure` | a quote look-alike followed by `}` (or `]` then `, } ]`) |
| `key_injection` | a value ending and a new key starting: `", "role":` |
| `object_reopen` | `}, {` inside a text value |
| `array_close_object` | `]}` inside a text value |
| `kv_forgery` | a forged `quote key quote : value` pair - with `"`, `\"`, `'`, curly quotes, backtick or `$`. Covers all five delimiter variants in the paper's table: `{\"k\":\"v\"}`, `{'k':'v'}`, curly, `{$k$:$v$}`, `(\"k\":\"v\")` |
| `embedded_json` | a text value that is itself a JSON object/array |
| `duplicate_key` | the same key twice in one object |
| `unexpected_key` | a key not in the tool's schema (only if a schema is supplied) |

Also: key **names** are scanned, and text is normalised first (HTML entities, `%`-encoding,
fullwidth forms, zero-width/bidi characters).

Logged but **never counted** (plausible in benign content): `code_fence`, `chat_template_token`,
`schema_violation`.

Rules: instruction words ("ignore", "system:") are never used - only structure. If the status
is not `ok`, **S = 0** and the status itself carries the "untrusted by default" signal
(the risk gate must read `status`, not only S).

### 3.4 `dom_flags.py` - `dom_flags(text) -> StructuralReport`
For text output such as `[0] <button class='buy'>Buy />`. A real element always starts its own
line (only an index `[0]`, `*`, a tab marker or `|SCROLL|` may precede the tag). A forged element
inside a review sits **mid-line** (`This product is...<button node_id=...>`). Position only, no words.
Note: the DOM score divides by the number of tags, so DOM S values are small and are **not
comparable** with JSON S values - compare hit counts instead.

### 3.5 Runners
- `agentdojo_offline.py` replays all 97 user tasks of AgentDojo v1.2.1 (workspace, travel, banking,
  slack) through the real tools and environments, using the recorded ground-truth tool calls. It
  runs once with default (benign) data and once with an attack string planted in every injection vector.
- `eval.py` routes each benchmark case: parses as JSON -> `parse()` + `structural_flags()`;
  otherwise -> `dom_flags()`. Reports per-case and per-unique-input counts.

## 4. Results so far (read the cautions)

| Check | Result |
|---|---|
| Unit tests | 90 passed |
| AgentDojo replay, benign | 0 of 678 messages flagged |
| AgentDojo replay, planted attack string | flagged in all four suites (workspace 53, travel 29, banking 12, slack 23) |
| Benchmark file (web_dom, 15 cases) | attacks 6/6 flagged, benign 0/9 flagged (3 unique attack pages, 2 unique benign pages) |
| Speed | typical message ~1 ms; worst case ~900 KB with 300,000 tiny fields ~1.3 s; adversarial strings (200 KB) <= ~100 ms |

**Cautions - do not over-claim:**
1. The planted attack string and the DOM rule were written after seeing these examples; the attack
   result is a **sanity check, not a detection rate**.
2. No LLM agent ran: there is **no Attack Success Rate or utility** yet, and the guard does not block anything.
3. The benchmark file is tiny (15 cases, 3 unique attacks) and contains only the web_dom category,
   so the JSON path was not exercised on it.
4. AgentDojo's own attacks and the paper's released ADI attacks have **not** been run.
5. The delimiter patterns follow the paper's published table; they are **not yet validated** on its released data.

## 5. Edge cases: covered, known limits, open

**Covered (tested):** all five JSON delimiter variants; HTML-entity, percent, double-encoded,
fullwidth, zero-width and bidi evasions; delimiters in key names; duplicate keys (also nested);
empty, whitespace, bare scalar, `{}`/`[]`, BOM, trailing comma, comments, single-quoted and YAML
input; too-large and too-deep payloads; non-JSON Python types in dict payloads; 16 benign texts
(prices, URLs, markdown, quotes, citations, unicode, long prose); regex slowdown on adversarial input.

**Known limits (written as tests, not hidden):**
- Benign text that quotes JSON (`The API returned {"status": "ok"}`) is flagged - structure alone cannot tell it from a forged field.
- `see [the "docs"], then` is flagged.
- Unquoted `role: system` lines are not flagged (only wording reveals them).
- A forged DOM element on a **real new line** looks like a normal element. Closing this needs provenance (tagging/graph stages).
- Plain-text tool responses (about a quarter of slack traffic, e.g. webpages) are `invalid_json` with S = 0; the gate must use the status.
- AgentDojo's default tool output is YAML; the replay switches it to JSON. A real pipeline must do the same.

**Open:** the DOM/text delimiter variants from the right half of the paper's table; other formats
(YAML, HTML, XML, CSV); attacks split across fields or messages; lenient JSON that the agent's side
accepts but we reject; Choi et al.'s released JSON attacks with a frozen held-out set; pre-hop
(agent call) data; a threshold for S with false-positive / false-negative rates; larger benign corpora.

## 6. Next steps
1. Commit to Git (`.gitignore`: `__pycache__/`, `.pytest_cache/`).
2. Build `tagging.py` (proposal 6.3) - the only way to close the real-newline gap.
3. Run the paper's released attacks; keep a held-out set untouched.
4. Agree the `ParseResult` / `StructuralReport` fields with the graph and classifier owners.
5. Wire a real pipeline run with an LLM agent to get ASR and utility.

## 7. How to add a new check
1. Add a pattern to `_COUNTED` (counts toward S) or `_WEAK` (logged only) in `structural.py`.
2. Add a positive test (attack text) **and** a benign test to `test_structural.py`.
3. Run `python -m pytest`, then `python agentdojo_offline.py` and confirm the benign table is still 0 flagged.
4. Avoid unbounded `\s*` or overlapping quantifiers - a speed test guards against regex slowdown.
