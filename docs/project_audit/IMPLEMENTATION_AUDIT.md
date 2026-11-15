# Implementation Audit — Correctness, Reliability, Security (read-only)

Date: 2026-11-15 · Branch: `zain/experimental` (HEAD `66fec89`) · Auditor role: Correctness & Bug Investigator
Scope: first-party code in `src/`, `tests/`, `scripts/` (and `agents/` only for hygiene). Vendored `agentdojo/` and `llm-benchmark/` were read only where first-party code depends on them.
Nothing in the repository was modified. This file is the only artefact created.

## 0. Method and baseline

- Static read of every module in `src/clone`, `src/parser`, `src/trust_graph`, `src/classifier`, `src/pipeline`, `scripts/`, `tests/unit`, plus `docs/tagging-design.md` and `src/clone/tool_matrix.json`.
- Empirical reproduction with `.\.venv\Scripts\python.exe` (Python 3.12.10) using a scratch script **outside** the repo:
  `C:\Users\ZAINSA~1\AppData\Local\Temp\claude\9f96d31193ab5ce7\eb3cf56a-5509-46ec-9a3c-d210b73bfa84\scratchpad\repro_audit.py`
  (it inserts `<repo>\src` into `sys.path` and imports first-party modules; every "Repro output" block below is copied verbatim from its run).
- Baseline: `pytest -q -p no:cacheprovider` collects **310** tests (309 pass, 1 pre-existing failure `tests/unit/test_phase1_cases.py::test_parser_conforms_to_design[E003]`). `pytest --collect-only src/parser` collects a further **107** tests that are *not* in the baseline (see F-12); running them read-only gave `107 passed in 1.20s`.
- Terminology: each entry gives **Observation** (what the code does), **Interpretation** (why it matters), **Recommendation** (not applied). Severity: Critical/High/Medium/Low/Informational. Confidence: Confirmed (reproduced) / Strongly supported / Hypothesis. Type: implementation defect / architectural issue / testing gap / performance issue / redundancy / security hygiene.

Nothing was rated Critical: no finding lets attacker data silently pass as trusted *and* execute; the dominant failure mode is over-blocking or lost signal.

---

## 1. High

### F-1 Nested `extra="forbid"` violations are silently dropped by `check_schema`
- **Location:** `src/parser/structural.py:127-134` (the `continue` on `extra_forbidden`), with the top-level-only manual check at `:122-126`; docstring promise at `:97-99`.
- **Type:** implementation defect · **Severity:** High · **Confidence:** Confirmed
- **Observation:** The manual `value.keys() - expected_fields.keys()` check reports unexpected keys only at the *top level*. The later pydantic pass then skips **every** `extra_forbidden` error ("already reported above"), including nested ones that were never reported. The docstring explicitly tells authors "Nested models should use `extra='forbid'` themselves", i.e. nested enforcement is intended.
- **Failure scenario:** schema `Outer{item: Inner{body}}`, both `extra='forbid'`; payload `{"item": {"body": "hi", "role": "system"}}` → **no finding at all**, `schema_invalid` stays False in `parser_analysis.py:57-60`, the call is not labelled `schema-violation`. A forged key one level down is invisible to the schema detector (the string-pattern detectors may or may not catch it independently).
- **Repro output:**
  ```
  === A. check_schema: nested extra='forbid' key is swallowed ===
  findings: []
  top-level control: [('unexpected_key', '$.role')]
  ```
- **Recommendation:** only skip `extra_forbidden` errors whose `loc` has length 1 (top-level) or drop the manual set-difference and map all pydantic `extra_forbidden` errors to `unexpected_key` via `_loc_to_path`.

### F-2 `_parse_failure_status` classifies ordinary "Key: value" prose as `invalid_json`, which can never be released
- **Location:** `src/parser/parser.py:25-28` (`_STRUCTURED_TEXT`), `:55-64`; consumers `src/pipeline/parser_analysis.py:25-34` (`usable` accepts only `NOT_JSON`), `src/parser/stage1.py:94-97`, `src/pipeline/risk_detector.py:35-37`.
- **Type:** implementation defect (heuristic over-match at a stage boundary) · **Severity:** High · **Confidence:** Confirmed
- **Observation:** Any text starting `<word>:` followed by end-of-text, a digit, `-`, a quote/bracket, or `true/false/null` is reported as `INVALID_JSON` instead of `NOT_JSON`. Downstream, `INVALID_JSON` is unconditionally unusable: even a registered `str` return schema cannot rescue it, whereas `NOT_JSON` + `str` schema is accepted.
- **Failure scenario:** a tool legitimately returns `"Balance: 100"`, `"Error: -1"` or `"Status: true"` → detector label `parser-untrusted`, observation blocked in `enforce` mode. The same tool returning `"Balance is 100"` is released. The distinction is purely about punctuation in benign prose.
- **Repro output:**
  ```
  'Balance: 100' -> invalid_json
  'Note:' -> invalid_json
  'Error: -1' -> invalid_json
  'Status: true' -> invalid_json
  'Hello world' -> not_json
  'Balance is 100' -> not_json
  stage1.analyze('Balance: 100', schema=str) -> untrusted_default invalid_json [...]
  stage1.analyze('Balance is 100', schema=str) -> clean not_json
  ```
- **Recommendation:** either narrow `_STRUCTURED_TEXT` (e.g. require ≥2 `key:` lines, or only fire when the payload *also* contains a brace/bracket), or let `parser_analysis.usable`/`stage1` treat `INVALID_JSON`-by-heuristic like `NOT_JSON` when a text-accepting schema is registered. Note the test suite's E003 failure may be adjacent to this boundary.

### F-3 With the pip AgentDojo copy, the adapter's default formatter makes every structured result unparseable (and dicts become Python `repr`)
- **Location:** `src/clone/adapters/agentdojo.py:34-37` (inherits whichever `tool_result_to_str` is imported); `.venv/Lib/site-packages/agentdojo/agent_pipeline/tool_execution.py:22-42` (pip copy: `yaml.safe_dump`, **no dict branch** → `str(dict)`); vendored copy `agentdojo/src/agentdojo/agent_pipeline/tool_execution.py:22-48` (`json.dumps`, has dict branch). Already described in `docs/tagging-design.md` §11 as a hazard; this entry records its concrete effect at the parser boundary.
- **Type:** architectural issue (environment-dependent behaviour) · **Severity:** High · **Confidence:** Confirmed
- **Observation:** Under plain `.venv` Python the pip copy is imported. A `dict` result is formatted as `"{'balance': 100, 'iban': 'DE1'}"` (Python repr, single quotes) → parser status `invalid_json` → blocked by both detectors regardless of schema. A list of models becomes YAML → `not_json` → blocked unless a text-accepting schema is registered (AgentDojo return types are models, so it is not).
- **Repro output:**
  ```
  agentdojo module: ...\.venv\Lib\site-packages\agentdojo\__init__.py
  formatted dict: "{'balance': 100, 'iban': 'DE1'}" -> status invalid_json
  formatted model list: '- body: hello\n  id_: 1' -> status not_json
  ```
- **Interpretation:** `scripts/live_clone_parser_smoke.py:46` does pass `partial(tool_result_to_str, dump_fn=json.dumps)`, so the smoke path is safe; any other caller that constructs `TrustVerificationToolsExecutor` without a formatter (the constructor allows it) gets a pipeline that blocks nearly every post-hop result when not run under pytest's `pythonpath`.
- **Recommendation:** make the JSON formatter the adapter's own default (design decision D1) rather than inheriting; add an assertion/test that fails when the pip copy is the one imported.

### F-4 Every `field_trust_classes` value in the shipped TVM is `"unclassified"`, so the legacy tagging/graph path carries zero trust information
- **Location:** `src/clone/tool_matrix.json` (70 tools, 105 field entries, all `"unclassified"`); consumer `src/trust_graph/tagging.py:273-281` (`_legacy_tag_fields`: only `t/trusted/provenance_trusted` → `T`); `src/pipeline/risk_detector.py:46-47,63-67`; `src/trust_graph/graph.py:18`.
- **Type:** architectural issue / data defect · **Severity:** High (for any evaluation claim about the graph classifier) · **Confidence:** Strongly supported (counted from the file: `classes Counter({'unclassified': 105})`)
- **Observation:** With the current matrix, every `TaggedField.trust` is `UT`; every graph node label starts with `UT:`; the WL features differ between payloads only through `value_type`/`depth`/finding nodes. The evidence panel's `untrusted_content` lists *every* string field, and `provenance` is uniformly `path:UT`.
- **Interpretation:** any classifier trained on graphs built through `risk_detector` today learns structure-only features; the "trust-provenance" dimension is a constant. Results produced via this path should not be presented as validating provenance-aware classification. (The new `FieldTag` API fixes the model, but is not wired — see F-6.)
- **Recommendation:** populate `field_trust_classes` (or wire the new profile-based tagging) before training/evaluating the WL-SVM; add a test asserting at least one `T` label can be produced from the shipped matrix.

### F-5 Default 2 s detector timeout makes the human-review callback in `make_risk_detector` unusable inside the clone
- **Location:** `src/clone/core.py:57` (`detector_timeout_s: float = 2.0`), `:355-378` (`_run_detector` waits on a queue, returns "timed out"); `src/pipeline/risk_detector.py:78-79` (the `reviewer` callback is invoked *inside* the detector call); adapter default `src/clone/adapters/agentdojo.py:29`.
- **Type:** architectural issue · **Severity:** High (feature cannot work as designed) · **Confidence:** Confirmed (simulated with a 2.3 s detector)
- **Observation:** The reviewer callback (meant to "render the evidence packet in a UI and return allow/deny/evidence_only", docstring `:23-28`) runs synchronously within the detector thread that `InterceptionCore` abandons after `detector_timeout_s`. Any real human decision takes longer than 2 s, so the core records `detector_error` and blocks with "Blocked: detector unavailable"; the reviewer's eventual answer is discarded (the daemon thread keeps running and leaks).
- **Repro output:**
  ```
  allowed: False | Blocked: detector unavailable | Detector timed out after 2 seconds.
  ```
- **Recommendation:** either move review out of the detector call (detector returns `route=human_review`, the executor/pipeline suspends), or make the timeout configurable per detector kind and document that interactive review requires a long timeout. Also cancel/ignore late results explicitly.

---

## 2. Medium

### F-6 New `FieldTag` output cannot be consumed by `build_trust_graph` (stage-boundary mismatch, step 1.2 → graph)
- **Location:** `src/trust_graph/graph.py:18` (reads `field.depth`, `field.trust.value`, `field.value_type`); `src/trust_graph/tagging.py:64-79` (`FieldTag` has no `depth`, no `value`).
- **Type:** architectural issue (known WIP, recorded so it is not forgotten) · **Severity:** Medium · **Confidence:** Confirmed
- **Repro output:** `build_trust_graph(FieldTag list) -> AttributeError 'FieldTag' object has no attribute 'depth'`
- **Interpretation:** The design doc (§6 "Compatibility") says the graph will be updated at the wiring step; until then there is no path from the new tagging to the classifier, and no test guards the eventual contract (`depth` would have to come from the parser field, `role`/`provenance` should enter the label, `tag_id`/timestamps must not — design §2.4).
- **Recommendation:** when wiring, define the graph label from `(trust, provenance, role, value_type)` and carry `depth` or drop it; add a boundary test with both tag types.

### F-7 Finding→field attachment in `build_trust_graph` is wrong for duplicate-key paths and lost for keys containing `#`
- **Location:** `src/trust_graph/graph.py:24-26` (`finding.path.split("#", 1)[0]`); parser conventions `src/parser/parser.py:99-101` (`#n` duplicate suffix), `src/parser/structural.py:150-151` (`#key` suffix), `:68` (`_child_path` quotes non-identifier keys, so a key may contain `#`).
- **Type:** implementation defect · **Severity:** Medium · **Confidence:** Confirmed
- **Observation:** `split("#",1)[0]` was meant to strip the `#key` marker but also strips the parser's duplicate suffix and anything after a literal `#` inside a quoted key.
- **Failure scenario:** payload `{"to":"a","to":"x\", \"role\": \"system\"","a#b":"{\"k\":1}"}` → illegal-delimiter findings located on `$.to#2` are attached to the *first* `$.to` node; findings on `$["a#b"]` get no edge at all (isolated finding nodes), so the WL features misplace or lose the structural evidence.
- **Repro output:**
  ```
  fields: ['$', '$.to', '$.to#2', '$["a#b"]']
  findings: [('duplicate_key', '$.to'), ('illegal_delimiter', '$.to#2'), ('illegal_delimiter', '$.to#2'), ('illegal_delimiter', '$["a#b"]'), ('embedded_json', '$["a#b"]')]
  edges: (... ('$.to', 'finding:1:$.to#2:illegal_delimiter'), ('$.to', 'finding:2:$.to#2:illegal_delimiter'))
  finding nodes with NO edge: ['finding:3:$["a#b"]:illegal_delimiter', 'finding:4:$["a#b"]:embedded_json']
  ```
- **Recommendation:** strip only a trailing literal `#key` (`removesuffix("#key")`), and keep `#n` suffixes since they are part of the field path. Consider making the parser emit the key-finding location as a structured field rather than a path suffix.

### F-8 `result_format == "text"` profile silently drops all non-root fields when the payload *did* parse as JSON
- **Location:** `src/trust_graph/tagging.py:177-181`; design `docs/tagging-design.md` §3.1 rule 3.
- **Type:** inconsistency between design and behaviour · **Severity:** Medium · **Confidence:** Confirmed
- **Observation:** For a `text` entry only the field with path `$` is tagged. If the tool's result happens to be valid JSON (e.g. a `str`-returning tool whose string is JSON, or a profile mislabelled as text), the parser emits a full tree but tagging returns one tag; the other fields have no tag at all, i.e. neither `UNKNOWN` nor `result_default`.
- **Repro output:** `text-format entry, JSON payload: fields 3 tags 1 ['$']`
- **Interpretation:** Downstream "no tag" is not a defined state (design says every field gets a tag). Either tag every field with `result_default` (containment rule 5 would give the same answer), or raise/flag the profile mismatch.

### F-9 `result_fields` patterns use dotted syntax but the parser quotes non-identifier keys → pattern never matches
- **Location:** `src/trust_graph/tagging.py:222-224` (`_compile_pattern` escapes the pattern literally); parser `src/parser/parser.py:68` (`$["content-type"]`).
- **Type:** inconsistency (undocumented contract between profile authors and parser) · **Severity:** Medium · **Confidence:** Confirmed
- **Repro output:** `hyphen key path: ['$', '$["content-type"]'] -> [('$', 'EXTERNAL'), ('$["content-type"]', 'EXTERNAL')]` with pattern `$.content-type: SYSTEM` — the intended `SYSTEM` tag became the `EXTERNAL` default.
- **Interpretation:** silent fall-back to the default is the "safe" direction (UT), but it will corrupt Phase-2 profiles for any key with `-`, space, or leading digit (common in HTTP/Slack/GitHub payloads). The design doc gives only `$[*].body`-style examples and never states the quoting rule.
- **Recommendation:** normalise patterns through the same `_child_path` logic, or document and validate in `ProfileEntry.__post_init__` that pattern segments must be identifiers or `["..."]`.

### F-10 `unexpected_key` finding order is nondeterministic (set iteration)
- **Location:** `src/parser/structural.py:124` (`value.keys() - expected_fields.keys()`).
- **Type:** implementation defect (nondeterminism) · **Severity:** Medium (reports/ledger/evidence text differ between processes; `scripts/build_phase1_cases.py:373-377` already had to re-exec itself with `PYTHONHASHSEED=0` for a related reason) · **Confidence:** Confirmed
- **Repro output:** payload keys `a, zeta, alpha, mid, beta` → `['$.mid', '$.beta', '$.zeta', '$.alpha']` (neither insertion nor sorted order; varies with hash seed).
- **Recommendation:** iterate `value.keys()` in payload order and filter (`[k for k in value if k not in expected_fields]`).

### F-11 Detector heuristics with reproducible false positives on benign content
All three are documented as heuristics, but the specific over-matches below are not in the stated limits and are cheap to tighten.
- **(a) `dom_flags` flags Markdown autolinks and angle-bracket e-mail addresses** — `src/parser/dom_flag.py:43,61-68`: `<https://…>` and `<admin@site.com>` mid-line are reported as forged elements.
  Repro: `'See <https://example.com> for details' -> [('illegal_delimiter', "element <https:> appears mid-text ...")]`, `'contact <admin@site.com> today' -> [... element <admin> ...]`.
  Severity Low–Medium (web_dom corpus is the one place this runs) · Confirmed.
- **(b) `md_flags` numbering rule treats a second list as a numbering error** — `src/parser/md_flags.py:66-70` compares against a single global counter.
  Repro: two lists separated by a heading → `('illegal_delimiter', 'line:4', 'record numbered 1 where 3 was expected')`. Severity Low · Confirmed.
- **(c) `kv_forgery` value alternative has no word boundary** — `src/parser/structural.py:46-47`: `true|false|null` match as prefixes (`"honesty": truest`, `"yes": nullify`). Severity Low (requires a quoted key + colon anyway) · Confirmed.
- **Recommendation:** (a) require the `<tag` to be followed by whitespace, `>`, `/` or an attribute, and exclude `<scheme:` / `<local@`; (b) reset the expected counter after a heading or when `num == 1` reappears; (c) add `\b` after the literals.

### F-12 Testing gaps: 107 parser tests are outside the baseline and the `tests/unit` stubs are empty
- **Location:** `pytest.ini` (`testpaths = tests src/clone src/pipeline` — no `src/parser`); `tests/unit/test_parser.py`, `test_classifier.py`, `test_provenance.py` are **0 bytes**; no `tests/unit/test_tagging.py` exists although the design doc §10 lists its fixtures; `src/trust_graph/tagging.py` (289 lines, new) has no direct unit test; `src/trust_graph/graph.py` is exercised only indirectly via `src/pipeline/test_classifier_risk_evaluation.py:160-161`.
- **Type:** testing gap · **Severity:** Medium · **Confidence:** Confirmed (`--collect-only`: 310 baseline vs +107 under `src/parser`; the 107 pass when run explicitly).
- **Interpretation:** the stated baseline "309 passed" does not cover the parser's own regression tests; a regression in `structural.py` would only surface through the 100 phase-1 cases.
- **Recommendation:** add `src/parser` to `testpaths` (or move the tests), delete or fill the empty stubs, add tagging/graph boundary tests (F-1, F-7, F-8, F-9 are good first fixtures).

### F-13 `_run_detector` leaves the detector thread running after a timeout; `check_call` still runs the detector on unclassified tools
- **Location:** `src/clone/core.py:365-378` (daemon thread, no cancellation); `:112-121` (transition `unclassified_tool`, then `_inspect` anyway).
- **Type:** reliability / performance · **Severity:** Medium (resource leak under repeated timeouts; the leaked thread can still mutate shared objects such as the reviewer UI) · **Confidence:** Strongly supported
- **Recommendation:** pass a cancellation flag/`Event` into the detector call and ignore late results; skip detector invocation when `entry.is_fallback and mode == "enforce"` since the outcome is predetermined (`:123-126`).

---

## 3. Low

### F-14 Dead `except ValidationError` after `json.loads` in `check_schema`
- `src/parser/structural.py:104-110`. `json.loads` raises `JSONDecodeError` (a `ValueError`), never pydantic's `ValidationError`, so the branch that maps `extra_forbidden` → `unexpected_key` is unreachable. Probably a refactor leftover; together with F-1 it shows the intended nested handling was lost. Implementation defect · Confirmed by inspection.

### F-15 Stale JSON-pointer unescaping in legacy `_root_key`
- `src/trust_graph/tagging.py:284-289` unescapes `~1`/`~0`, which the current parser never emits (it uses `$["..."]` quoting, `parser.py:68`); quoted roots return `""` → `unclassified` → `UT`.
- Repro: `_root_key('$["a/b"]') -> ''`, `_root_key('$.a~1b') -> 'a/b'`. Safe direction (UT) but a stale code path that no longer matches the data model. Low · Confirmed.

### F-16 Parser quirks around size limits
- `src/parser/parser.py:121-124`: byte limit is checked on UTF-8 length but truncation is by *characters* (`raw[:MAX_BYTES]`), so the stored opaque node can exceed 1 MB of UTF-8. `status != OK` already blocks, so impact is memory/ledger size only. Low · Strongly supported.
- `structural._scan_string` (`structural.py:77-84`) calls `json.loads` on every string value starting with `{`/`[` with no size cap; `_variants` runs `html.unescape`/`unquote` twice over full strings. Performance only (payload ≤ 1 MB). Informational.

### F-17 Adapter blocks unknown/empty tool names with a matrix denial before AgentDojo's "Invalid tool" path
- `src/clone/adapters/agentdojo.py:81-108` runs `check_call` for every tool call, so in `enforce` mode a hallucinated tool name yields "Blocked: unclassified tool" instead of the framework's `Invalid tool … provided.` error (`:110-115` is unreachable in enforce mode). Changes agent-facing error text versus the upstream baseline, which can affect utility comparisons. Low · Strongly supported.

### F-18 `_framework_args` applies `literal_eval` to *every* string argument
- `src/clone/adapters/agentdojo.py:157-168`. Mirrors upstream's `is_string_list`, but note (a) only `ValueError/SyntaxError` are caught (`RecursionError`/`MemoryError` would propagate out of `query`); (b) a user-supplied string that *looks* like a list (`"[1, 2]"`) is silently retyped before interception, so the pre-hop payload hashed into the ledger is not the argument the LLM emitted. Checked empirically: nesting up to 5 000 brackets does **not** crash on 3.12 (`50 ok / 500 ok / 5000 ok`), so (a) is theoretical. Low · Strongly supported for (b).

### F-19 Mutable default arguments
- `src/clone/adapters/agentdojo.py:56-57` (`messages=[]`, `extra_args={}`) — copied from upstream signature; not mutated, so harmless today. Informational.

### F-20 Ledger persistence is O(n) per event → O(n²) per run
- `src/clone/ledger.py:334-352` rewrites all three JSONL snapshots on **every** `capture`/`transition` (≈4–6 events per tool call). For long benchmark runs with `storage_dir` set this dominates latency and increases the chance of the 2 s detector budget being exceeded by I/O. Performance · Strongly supported.

### F-21 `assess_risk` thresholds and `review_reasons` ordering
- `src/pipeline/risk_gate.py:53-70`: with `impact=10`, any classifier probability ≥ 0.1 forces review (`0.1 10 -> moderate human_review`); with `impact=1` even probability 1.0 only reaches `moderate`. Behaviour is internally consistent and tested, but the structural score is validated as a probability yet is a density — fine as evidence, but the field is named `structural_score` in `RiskAssessment` while `EvidencePanel` exposes it as if comparable. Informational (design-level note, not a defect).

### F-22 `check_result` without a pre-record looks up the matrix with empty `expected_keys`
- `src/clone/core.py:189-194`: `lookup(tool, ())` never matches a real entry (all entries have keys) → fallback with `impact_tier=None` → `risk_detector` returns `risk-unclassified`. Fail-closed, but the degraded path is silent. Low · Strongly supported.

### F-23 Duplicate `send_email` entries in the TVM
- `src/clone/tool_matrix.json`: `tool_name` `send_email` appears twice (different `expected_keys`, allowed by `tvm.py:76-79`). Fine by design (lookup is by name+keys), but `_entry_for_record` (`core.py:258-261`) resolves by `internal_tool_id` only, so the two must have distinct ids; verify when editing. Informational.

---

## 4. Redundancy (logic that can drift)

- **Markdown combined report** exists twice: `src/parser/stage1.py:52-62` (`_markdown_report`) and `src/parser/adi_eval.py:117-128` (`_md_combined`), byte-for-byte the same algorithm.
- **"Expand `{"$generate": ...}` payload"**: `scripts/run_phase1_cases.py:39-43` and (per grep) `scripts/build_phase1_cases.py` share the oversize-payload convention; the test imports from `scripts/` via `sys.path` hacks (`tests/unit/test_phase1_cases.py:17-20`).
- **Two S-score assemblers**: `md_flags.py:78-81`, `dom_flag.py:83-86`, `stage1.py:60-62`, `adi_eval.py:126-128` each recompute `min(1, hits/boundaries)`; a helper on `StructuralReport` would prevent divergence.
- **Try/except import shims** (`try: from .x import … except ImportError: from x import …`) in every parser module to support "flat-folder layout"; `adi_eval.py:36-39,45-48` even has `except ImportError: from .dom_flag import dom_flags` identical to the `try` body (dead). Informational.
- **Unused import**: `src/pipeline/clone_parser_detector.py:5` imports `ParseStatus` and never uses it.
- **Two interception entry points**: `src/clone/interceptor.py` is a pure re-export shim of `adapters/agentdojo.py` (fine, but exports the private `_framework_args`).

## 5. Reliability notes (crash paths / error handling)

- `src/clone/core.py:371-372` converts *any* detector exception into a string error and blocks (fail-closed) — correct, but exceptions raised by programming errors in `risk_detector` (e.g. F-6's `AttributeError`) are indistinguishable in the ledger from timeouts except by message text; consider recording the exception type as a field.
- `src/pipeline/risk_detector.py:82-90`: `resolve_review` `ValueError` → `review-invalid`; an exception from the `reviewer` callback itself is not caught and becomes a generic detector error (fail-closed).
- `src/classifier/train.py:40-41` and `src/pipeline/evaluation.py:89-90` wrap `Exception` into `ValueError` with line numbers — good.
- `src/clone/ledger.py:205-211` raises `KeyError` inside `transition` if no raw payload exists — only reachable via `import_ledger` (which does not restore records); documented nowhere.

## 6. Security hygiene (first-party)

- No `eval`/`exec`/`pickle`/unsafe `yaml.load`/`shell=True` in `src/`, `scripts/`, `tests/`. `subprocess.run` uses argument lists (`scripts/run_phase1_cases.py:87-88`, `scripts/build_phase1_cases.py:377`, test files).
- `joblib.load` (`src/classifier/wl_svm.py:146`) is pickle-based: loading an untrusted `.joblib` executes arbitrary code. The docstring in `train.py:7` says "Only load artifacts produced from trusted sources" — adequate for an FYP, but the `format_version` check happens *after* unpickling, so it is not a safety control. Informational.
- Secrets: `scripts/live_clone_parser_smoke.py` reads `GROQ_API_KEY` from `.env`/environment; no keys found in code.
- Path handling: `InterceptionLedger(storage_dir)` writes under a caller-supplied directory with fixed file names (`ledger.py:349-352`); run names in the smoke script are built from a timestamp, not from payload data. No injection into file paths observed.
- Privacy: when `storage_dir` is set, **raw payloads are always persisted** (`ledger.py:339`), i.e. "opt-in" means opting into everything; there is no way to persist only the hash-chained ledger.
- `agents/camel/interpreter/interpreter.py:2231` uses raw `eval(field_type, …)` on type-hint text. This is vendored CaMeL baseline code (no first-party imports of `clone`/`pipeline`/`parser` exist anywhere in `agents/`), noted for completeness only.

## 7. Items checked and found sound (so they are not re-audited)

- `wl_features` (`wl_svm.py:52-72`): self-loops counted once, neighbour multiset sorted, deterministic digest; sparse `int32` index coercion present in both `fit` and `predict`.
- `assess_risk`/`resolve_review`: operator precedence at `risk_gate.py:98` is `A or (B and C)`, and `options` already exclude `allow` for high tier; every denial path is fail-closed.
- `parse`: duplicate keys retained via `object_pairs_hook`; NaN/Infinity rejected; BOM stripped; `_TooDeep`/`RecursionError` both mapped to `TOO_DEEP`; `boundary_count ≥ 1` guaranteed.
- `tagging._explicit_provenance`: memoised containment propagates only explicit `EXTERNAL`, matching the design's rule 5 and the docstring's rationale; `_strip_duplicate_suffix` and `_argument_name` agree with the parser's `#n` and `$["..."]` conventions (verified against `parser.py:68,101`).
- `tagging.ProfileEntry.__post_init__`: validates enums and rejects `DERIVED/USER/UNKNOWN` as result provenance.
- `ledger.verify_chain`: hash excludes `entry_sha256`, genesis constant, sequential `event_seq` check.
- `literal_eval` depth: no crash up to 5 000 nested brackets on Python 3.12.10 (see F-18).

## 8. Repro command

```
.\.venv\Scripts\python.exe "C:\Users\ZAINSA~1\AppData\Local\Temp\claude\9f96d31193ab5ce7\eb3cf56a-5509-46ec-9a3c-d210b73bfa84\scratchpad\repro_audit.py"
.\.venv\Scripts\python.exe -m pytest --collect-only -q -p no:cacheprovider            # 310 tests
.\.venv\Scripts\python.exe -m pytest --collect-only -q -p no:cacheprovider src/parser # 107 tests (not in baseline)
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider src/parser               # 107 passed
```
The scratch script is session-local; sections A–L in its output map to findings F-1 (A), F-2/F-3 (B/B2), F-18 (C), F-7 (D), F-6/F-8/F-9 (E), F-15 (F), F-11a (G), F-11b (H), F-11c (I), F-10 (J), F-21 (K), F-5 (L).
