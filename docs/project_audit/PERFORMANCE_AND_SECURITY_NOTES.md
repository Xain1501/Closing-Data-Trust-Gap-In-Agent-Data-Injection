# Performance and Security Notes

Read-only research audit of the first-party hot path (`src/`), branch `zain/experimental`
(commit `66fec89`). Date: 2026-11-15. Scope: per-tool-call overhead, scaling behaviour,
first-party security hygiene, self-defense of the pipeline against hostile payloads, and the
dependency picture. Vendored AgentDojo internals were not benchmarked.

Every finding is classified as **Severity** (Critical / High / Medium / Low / Informational),
**Confidence** (Confirmed = reproduced empirically here / Strongly supported = read in code with
clear mechanism / Hypothesis), and **Type**. Every proposal is a proposal only and requires
researcher approval before any code change.

Machine caveat for all numbers: Windows 11 Pro 10.0.26300, Python 3.12.10 (`.venv`), Intel
"Family 6 Model 170" (Meteor Lake class laptop CPU), single process, no CPU pinning, background
load not controlled. Numbers are medians of 5-21 repeats unless stated; treat them as
order-of-magnitude, not as reproducible absolute figures. Benchmark scripts lived outside the
repo (`%TEMP%\claude\...\scratchpad\bench_hotpath.py`, `probes.py`, `probes2.py`,
`probe_okprefix.py`) and imported the repo via `sys.path.insert(0, "<repo>/src")`.

---

## 1. Summary of findings

| # | Finding | Severity | Confidence | Type |
|---|---------|----------|------------|------|
| P1 | Ledger with `storage_dir` rewrites all three JSONL snapshots on **every** capture/transition: per-call latency grows linearly with run length, cumulative cost is quadratic (31.7 ms at call 1 -> 331 ms at call 200; 34.5 s total vs 0.51 s in-memory) | High | Confirmed | performance issue |
| P2 | Full in-memory chain (`check_result` + `parser_detector`) costs ~1.6 ms for a 1 KB result, ~11 ms for a 100 KB result (structural scan dominates), and a <1 MB crafted payload takes ~1.7 s, i.e. 85% of the 2 s detector budget | Medium | Confirmed | performance issue |
| P3 | Every detector invocation spawns a fresh `Thread` (+ `Queue`): ~0.6 ms fixed overhead per pre-hop and per post-hop inspection; timed-out detector threads keep running (leak) | Medium | Confirmed | performance / reliability |
| P4 | Payload is deep-copied 3-4 times and canonically re-serialised (`json.dumps` + SHA-256) per hop; raw payloads are retained in memory for the whole process lifetime (unbounded growth) | Medium | Confirmed | performance issue |
| P5 | `structural_flags` runs 7 regexes x up to 2 normalised variants + a speculative `json.loads` per string field and per key; cost scales with total string bytes (~18 ms for 1000 fields / 117 KB) | Low | Confirmed | performance issue |
| P6 | Tagging + graph + WL(h=2) are linear but non-trivial: ~31 ms at 1000 fields, ~330 ms at 10 000 fields | Low | Confirmed | performance issue |
| P7 | `TrustMatrix.lookup` is a linear scan rebuilding `set(entry.expected_keys)` per entry (70 entries, 0.9-8.4 us) and `_entry_for_record` is a second linear scan; `check_schema` builds a fresh pydantic `TypeAdapter` per call (~10 us) | Informational | Confirmed | performance issue |
| S1 | A lone UTF-16 surrogate in a tool result or argument (`"\ud800"`) raises an **uncaught** `UnicodeEncodeError` inside `InterceptionLedger.capture` -> `_payload_hash`, *before* the detector runs and outside the detector's try/except. The whole executor call crashes | High | Confirmed | security concern (self-defense / crash) |
| S2 | `parser/dom_flag.py::_OK_PREFIX` has polynomial catastrophic backtracking: a line prefix of N spaces followed by a non-matching character costs 53 ms (N=250), 365 ms (N=500), 3.0 s (N=1000), >12 s (N=2000). Not on the live clone path today (only `adi_eval.py`, `eval.py`, `stage1.py`) | Medium | Confirmed | security concern (ReDoS) |
| S3 | A crafted sub-1 MB payload can keep the parser busy for ~1.7 s (150 k duplicate keys -> 100 000 `Finding` objects; 60 k embedded-JSON strings). On a slower machine this crosses the 2 s timeout -> every such call is blocked *and* the worker thread keeps burning CPU | Medium | Confirmed | reliability / DoS |
| S4 | `_framework_args` runs `ast.literal_eval` on every string argument the LLM emits; a 1 MB `"[1,1,...]"` string took 1.78 s to evaluate and is then deep-copied through the pipeline. Deep-nesting bombs are safely rejected (tokenizer limit -> `SyntaxError`) | Low | Confirmed | reliability |
| S5 | `WLGraphSVM.load` uses `joblib.load` (pickle): loading an attacker-controlled model artifact is arbitrary code execution. Current artifacts are code-owned | Low | Strongly supported | security concern |
| S6 | `MAX_BYTES` is checked in UTF-8 bytes but truncation uses a character slice (`raw[:MAX_BYTES]`): a multibyte payload keeps 1 000 022 bytes / 500 012 chars. Cosmetic inconsistency, not exploitable | Informational | Confirmed | reliability |
| S7 | No secrets in tracked files; `.env` is gitignored and untracked, local `.env` has all values empty; `.env.example` contains placeholders only. `README.md:385` shows a placeholder `export ANTHROPIC_API_KEY="your-anthropic-key"` | Informational | Confirmed | security hygiene (positive) |
| S8 | No `eval`/`exec`/`pickle.load`/`yaml.load`/`shell=True` in `src/`. `subprocess` appears only in tests/scripts with list arguments. `agents/camel/interpreter/interpreter.py:2231` contains a real `eval(...)` (third-party CaMeL re-implementation, outside `src/`) | Informational | Confirmed | security hygiene |
| D1 | Two AgentDojo copies at the same version string 0.1.35 but with **different code**: 64 of 82 vendored `.py` files differ from the pip copy and 14 vendored files have no pip counterpart. `pytest.ini` puts `agentdojo/src` first (tests use vendored), plain `python` resolves to site-packages (runtime uses pip). `tool_execution.py` and `functions_runtime.py`, which the adapter subclasses, are among the differing files | High | Confirmed | dependency risk |
| D2 | `requirements.txt` lists only `cohere>=5.3.4` and `scikit-learn>=1.5,<2`; no lock file; the venv holds 84 packages (agentdojo, pydantic, joblib, numpy, scipy, pytest, ...) none of which are pinned. Environment is not reproducible from the repo | Medium | Confirmed | dependency risk |
| D3 | joblib 1.6.0 is above the fixed version for CVE-2022-21797 (`Parallel(pre_dispatch=...)` eval, fixed in 1.2.0). CVE-2024-34997 concerns pickle deserialization in joblib and has no clean fixed-version statement in the sources found; the mitigation is identical to S5 (never load untrusted artifacts) | Low | Strongly supported | dependency risk |

---

## 2. Hot-path analysis (code reading)

Live path for one tool call (AgentDojo adapter `src/clone/adapters/agentdojo.py:81-152`):

```
_framework_args(args)                          deepcopy #1 + literal_eval on every str arg
core.check_call(...)                           src/clone/core.py:83
  tool_matrix.lookup()                         linear scan, 70 entries           (P7)
  payload = {"tool":..., "args": deepcopy()}   deepcopy #2
  ledger.capture()                             _payload_hash: json.dumps + sha256 of whole payload
                                               deepcopy #3 into raw_payloads (kept forever)   (P4)
                                               _append_ledger_locked -> asdict + json.dumps + sha256
                                               _persist_locked -> rewrite 3 JSONL files        (P1)
  _inspect()                                   transition(decision_pending) -> persist again
    _run_detector(deepcopy #4 ...)             new Thread + Queue per call                   (P3)
      parser_detector -> analyze_clone_payload
        parse()                                json.loads #1, pydantic ParsedField per node
        ToolSchemaRegistry() + register()      fresh registry per call
        check_schema()                         json.loads #2 of same payload, TypeAdapter built per call (P7)
        structural_flags()                     7 regex x 2 variants x (fields + keys), speculative json.loads #3 per "{"/"[" string (P5)
    transition(decision_received) -> persist
  transition(allowed) -> persist
runtime.run_function(...)                      actual tool
core.mark_executed() -> persist
core.check_result(...)                         same shape again for the post-hop text
  _entry_for_record()                          second linear scan over matrix
```

Observations:

- **Ledger persistence is O(total history) per event.** `_persist_locked` (`ledger.py:334-352`)
  serialises *every* ledger entry and *every* retained raw payload to disk on every `capture`
  and every `transition`. One tool call produces 4-6 persist events on the pre hop and 3-4 on
  the post hop, so a run of N calls does Theta(N^2) serialisation work and Theta(N^2) bytes of
  disk writes. Confirmed in section 3.2.
- **Unbounded in-memory growth.** `records`, `ledger`, `raw_payloads` are lists that are never
  trimmed (`clear()` exists but nothing on the hot path calls it). After the 1 MB benchmarks a
  single `check_result` retained ~5 MB (payload copy + hashed copies); a long benchmark run in
  one process keeps every tool result it has ever seen.
- **Repeated parsing/serialisation of the same payload.** The same text is `json.loads`-ed
  in `parse()` and again in `check_schema()`; canonically `json.dumps`-ed and hashed in
  `_payload_hash` on capture; deep-copied four times on the pre hop.
- **Regex compilation**: all hot-path patterns are module-level compiled; `_child_path`
  (`parser.py:68`) uses `re.fullmatch` with a literal pattern per field (served by the `re`
  cache, measured cost negligible). `_compile_pattern` in tagging recompiles profile patterns
  per message (not on the legacy live path).
- **No quadratic matching found in the live tagging path.** `_explicit_provenance` is memoised
  and `build_trust_graph` uses set/dict lookups. The substring-lineage matching described in the
  design document is not implemented yet (step 1.3); when it is, matching every argument field
  against every prior result field is the obvious place quadratic behaviour would appear, and
  benchmark suites with long histories would feel it first (see 4.2).
- **`tool_matrix.json` is loaded once** per executor construction (`agentdojo.py:42`), not per
  call (0.83 ms cold load measured). Good.

---

## 3. Benchmark methodology and results

Synthetic payloads: `{"field_i": "lorem ipsum ..."}` with `n` string fields sharing a total
byte budget; a 1 MB single-string case; and crafted adversarial cases. `median()` over repeats;
`time.perf_counter`. Full-chain numbers use `InterceptionCore(InterceptionLedger(), parser_detector,
load_tool_matrix(), mode="enforce").check_result(...)`. Scripts: see header.

### 3.1 Component costs (ms, median)

Copies and hashing (`deepcopy`, `clone.ledger._payload_hash`):

| fields | bytes | deepcopy(dict) | deepcopy(str) | hash pre (dict) | hash post (str) |
|-------:|------:|---------------:|--------------:|----------------:|----------------:|
| 10 | 1 150 | 0.011 | 0.001 | 0.066 | 0.005 |
| 100 | 101 590 | 0.080 | 0.001 | 0.890 | 0.130 |
| 1000 | 1 016 890 | 0.828 | 0.001 | 9.752 | 1.307 |
| 1 | 1 000 015 | 0.004 | 0.001 | 8.661 | 1.277 |

Parser and structural pass (`parser.parse`, `structural.structural_flags`):

| fields | bytes | parse | structural | status |
|-------:|------:|------:|-----------:|--------|
| 10 | 1 150 | 0.09 | 0.17 | ok |
| 100 | 2 590 | 0.56 | 1.01 | ok |
| 1000 | 17 890 | 5.96 | 11.55 | ok |
| 10 | 100 150 | 0.28 | 7.50 | ok |
| 100 | 101 590 | 0.75 | 10.48 | ok |
| 1000 | 116 890 | 9.71 | 18.27 | ok |
| 1 / 100 / 1000 / 10000 | >1 000 000 | 0.13-0.96 | 0.00 | too_large (short-circuit) |

Interpretation: `parse()` is dominated by per-field pydantic object creation (~6 us/field);
`structural_flags` by per-byte normalisation + regex (~70-100 ns/byte) plus per-field overhead.
Payloads over `MAX_BYTES` are cheap because they are not parsed at all.

Other fixed costs:

| item | measured |
|------|---------:|
| `TrustMatrix.lookup`, 70 entries: hit first / hit last / miss | 0.9 / 4.3 / 8.4 us |
| `load_tool_matrix()` cold | 0.83 ms |
| `TypeAdapter(Args)` construction / cached `validate_python` / construct+validate | 9.6 / 2.4 / 11.5 us |
| `_run_detector(trivial)` (thread + queue) vs direct call | 600.8 us vs 0.3 us |

Tagging, graph, WL features (legacy `tag_fields(parse_result, {})` path used by `risk_detector`):

| fields | tag | graph | wl(h=2) | nodes |
|-------:|----:|------:|--------:|------:|
| 10 | 0.09 | 0.02 | 0.20 | 11 |
| 100 | 0.77 | 0.12 | 1.64 | 101 |
| 1000 | 8.99 | 1.23 | 20.66 | 1001 |
| 10000 | 112.84 | 16.43 | 203.08 | 10001 |

Linear in node count; WL dominates (one `json.dumps` + SHA-256 per node per iteration).

### 3.2 Full chain per tool-call hop

`check_result` with `parser_detector`, in-memory ledger (median of 5):

| fields | bytes | per hop | notes |
|-------:|------:|--------:|-------|
| 10 | 1 150 | 1.60 ms | 5 ledger records created, ~5.7 KB retained |
| 100 | 101 590 | 11.26 ms | ~508 KB retained |
| 1000 | 1 016 890 | 2.80 ms | TOO_LARGE short-circuit, ~5.1 MB retained |
| 1 | 1 000 015 | 3.13 ms | TOO_LARGE short-circuit, ~5.0 MB retained |

`check_call` pre-hop with small arguments (`add_calendar_event_participants`): 1.38 ms.

**Per-tool-call overhead estimate (in-memory ledger, parser-only detector):** pre hop ~1.4 ms +
post hop ~1.6-11 ms, so roughly **3-13 ms per tool call** for realistic 1-100 KB results, of
which ~1.2 ms is the two thread spawns and the rest is scanning. With the risk detector add
~0.3 ms (10 fields) to ~31 ms (1000 fields) for tagging + graph + WL + SVM. Against a typical
LLM round-trip of seconds this is 0.1-1%, acceptable for the research claim *provided ledger
persistence is off*.

**Ledger with `storage_dir` set** (10 KB result per call, 200 consecutive calls in one run):

| call # | per-call latency | cumulative | files on disk | ledger entries |
|-------:|-----------------:|-----------:|--------------:|---------------:|
| 1 | 31.70 ms | 0.03 s | 0.01 MB | 4 |
| 10 | 41.17 ms | 0.35 s | 0.14 MB | 40 |
| 25 | 63.58 ms | 1.20 s | 0.36 MB | 100 |
| 50 | 128.16 ms | 3.70 s | 0.72 MB | 200 |
| 100 | 186.16 ms | 11.70 s | 1.45 MB | 400 |
| 200 | 331.35 ms | 34.52 s | 2.89 MB | 800 |

Same 200 calls, in-memory ledger: 2.1-3.4 ms each, **0.51 s cumulative**. Persistence makes the
pipeline **~68x slower over 200 calls** and the gap keeps widening (quadratic). Extrapolating
the linear per-call growth (~1.5 ms per prior call at 10 KB payloads) a 1000-call run would spend
on the order of 15 minutes in ledger rewrites alone; larger payloads scale this up
proportionally because `raw-payloads.jsonl` is rewritten in full every time.

### 3.3 Not benchmarked (limitations)

- Live AgentDojo executor end-to-end (`TrustVerificationToolsExecutor.query`) -- requires
  runtime/env objects and would import vendored internals; estimated from components above.
- `risk_detector` end-to-end with a trained `WLGraphSVM` -- no fitted model was loaded; component
  costs for tag/graph/WL are given, SVM `predict_proba` on a single sparse row was not timed.
- The new profile-based `tag_fields("post", ...)` path and the not-yet-implemented lineage
  matching (step 1.3).
- Memory footprint over time was only observed indirectly (retained payload bytes), not with a
  memory profiler.

---

## 4. Scaling risks for the research metrics

### 4.1 Confirmed today

1. **Any benchmark run with ledger persistence enabled measures the ledger, not the defense.**
   If latency/overhead figures are reported from runs with `storage_dir` set, they are inflated
   by a term that grows with run length (P1). Latency comparisons between short and long suites
   would be confounded.
2. **Per-call `detector_latency_ms` in the ledger excludes most of the overhead.** It is measured
   around `_run_detector` only (`core.py:312-320`), so it omits the deepcopies, hashing, matrix
   lookup and all persistence. Reporting it as "defense overhead" understates true cost by the
   persistence term (tens to hundreds of ms per call in long runs).
3. **Memory grows without bound per process.** A benchmark harness that reuses one
   `InterceptionLedger` across many tasks keeps every raw payload. With 100 KB results this is
   ~0.5 MB per hop; a 2000-hop sweep approaches 1 GB.
4. **Fail-closed timeouts can be triggered by size alone.** A benign but large/complex tool result
   (<1 MB) costing >2 s on a slower machine will be *blocked* with `detector-error`, which would
   show up in utility metrics as a false positive even though no detection logic fired (S3).

### 4.2 Hypotheses for upcoming work (requires researcher attention, not confirmed)

- Substring lineage matching (design step 1.3) that compares every argument string with every
  earlier result string is Theta(args x history x length). On long AgentDojo tasks (dozens of
  tool calls, each with hundreds of fields) this will dominate quickly unless indexed
  (e.g. hashed exact matches first, bounded candidate sets for substring checks).
- If per-message profile patterns are compiled on every call (`_compile_pattern`), cost is
  O(patterns) per message; negligible now, worth caching once profiles exist.

---

## 5. Security findings (first-party code)

### S1. Lone surrogate crashes the executor before the detector runs -- High / Confirmed

Probe (`probes.py: surrogate_in_result`):

```
UNCAUGHT in check_result: UnicodeEncodeError 'utf-8' codec can't encode character '\ud800' in position 6: surrogates not allowed
UNCAUGHT in check_call:   UnicodeEncodeError 'utf-8' codec can't encode character '\udfff' in position 17: surrogates not allowed
```

Mechanism: `ledger._payload_hash` (`ledger.py:355-364`) encodes with `payload.encode("utf-8")`
and `json.dumps(..., ensure_ascii=False).encode("utf-8")` with the strict error handler. Python
strings can hold lone surrogates (e.g. a tool that returns `json.loads('"\\ud800"')`, or a web
page / email body decoded with `surrogateescape`). The exception is raised in `capture()`, which
runs *outside* `_run_detector`'s try/except, so it propagates out of
`TrustVerificationToolsExecutor.query` and aborts the agent step. The parser itself handles the
same input fine (`parser status ok`), so this is purely a ledger robustness gap. Impact: a
payload-controlled crash of the defense (availability), not a bypass: nothing is released.
Proposal (needs approval): encode with `errors="surrogatepass"` (or `"backslashreplace"`) in
`_payload_hash`, and wrap `capture()` so that hashing failures become a `detector-error`-style
block rather than an exception.

### S2. ReDoS in `dom_flag._OK_PREFIX` -- Medium / Confirmed (eval path only)

Pattern (`dom_flag.py:46-50`): `^(?:\d+(?:→|â†’))?(?:\|\w+\|)?(?:\\t|\s)*\*?(?:\[\w+\])?\*?\s*(?:\(\s*-?\d+\s*,\s*-?\d+\s*\))?\s*$`.
`(?:\\t|\s)*` followed by `\s*` and another `\s*` gives three adjacent whitespace quantifiers,
so a long run of spaces that ends in a non-matching character backtracks polynomially:

| leading spaces | `_OK_PREFIX.match` time |
|---:|---:|
| 250 | 53.4 ms |
| 500 | 365.1 ms |
| 1000 | 3005.9 ms |
| 2000 | >12 s (killed) |

Growth ~x7-8 per doubling (roughly cubic). `dom_flags()` calls this once per `<tag` per line
with the line prefix as input, so one hostile line (`" " * 2000 + "x<a>"`) stalls the call. Today
`dom_flags`/`md_flags` are reachable only from `src/parser/adi_eval.py`, `eval.py`, `stage1.py`
(evaluation scripts), not from `pipeline/parser_analysis.py`, so the live clone path is not
exposed; if DOM text handling is ever wired into the detector this becomes High. Other
patterns probed (`kv_forgery`, `key_injection`, all `_COUNTED` on `'$` runs, `_variants` on
`%25%26amp%3B` runs, `md_flags` on 16 000 markers, `dom_flags` on 4 000 tags in one line) grew
linearly (e.g. `kv_forgery` 0.3 ms -> 1.2 ms for 10 k -> 40 k chars). Proposal: rewrite
`_OK_PREFIX` with a single whitespace class (`[\s\\t]*` semantics via `(?:\\t|[ \t])*` and no
trailing `\s*` duplicates), or add a prefix length cap before matching.

### S3. Sub-1 MB parser bombs approach the 2 s detector budget -- Medium / Confirmed

Through the full `check_result` in enforce mode (this machine):

```
150k dup keys (900001 B):              1670 ms  allowed=False label=parser-untrusted  (too_many_fields)
60k embedded-json strings (720001 B):  1717 ms  allowed=False label=adi-detected
```

Both are correctly blocked, but on a 1.5-2x slower CPU the same payloads exceed
`detector_timeout_s=2.0`, which (a) also blocks, (b) leaves the worker thread running to
completion (probe `detector_timeout_thread_leak`: `threads before=1 after=2
alive_names=['tvm-detector']` after a timed-out call), and (c) makes every such call cost the
full timeout. Contributing factors: `MAX_FIELDS` caps `fields` but not `findings` (150 k
duplicate keys created 100 000 `Finding` objects before the field cap fired), and the speculative
`json.loads` per `{`/`[`-prefixed string value. Deep nesting is handled well (`[`x500 000 ->
`too_deep` in 1.3 ms) and >1 MB payloads short-circuit in <4 ms. Proposal: cap `findings`
alongside fields; consider a byte budget for `_scan_string` work; consider a cooperative deadline
inside the detector instead of (or in addition to) the thread timeout.

### S4. `ast.literal_eval` on LLM-emitted argument strings -- Low / Confirmed

`_framework_args` (`agentdojo.py:157-168`) mirrors AgentDojo behaviour. Probes: 100 000 `[`
-> `SyntaxError` (caught, 1 ms); balanced 5 000-deep -> caught (0.3 ms); 100 000-digit integer ->
caught `ValueError` (28.5 ms, int-string limit); 300 nested tuples -> caught; a 1 MB
`"[1,1,...]"` string -> evaluated to a 500 000-element list in **1 784 ms** and then deep-copied
three more times downstream. CPython's tokenizer nesting limit protects against the classic
recursion crash; the residual issue is CPU time on large literal lists.

### S5 / D3. Pickle-based model loading -- Low / Strongly supported

`classifier/wl_svm.py:145` `joblib.load(path)`; joblib uses pickle, so a tampered `.joblib`
artifact executes code on load (see the public PoC and CVE-2024-34997 discussion below).
Artifacts are code-owned today; the risk is in sharing/downloading models. Proposal: document the
trust boundary; optionally hash-pin artifacts in a manifest.

### S6. Byte/char truncation mismatch -- Informational / Confirmed

`parse()` compares `len(raw.encode("utf-8","ignore")) > MAX_BYTES` but truncates with
`raw[:MAX_BYTES]` (characters). Probe: an all-`é` payload kept 500 012 chars = 1 000 022 bytes.
Harmless (status is already `too_large`), just inconsistent with the documented 1 MB cap.

### S7 / S8. Hygiene checks (positive)

- `git ls-files .env` -> not tracked; `.gitignore` excludes `.env` and `.env.*` except
  `.env.example`. Local `.env` (484 bytes) has `GROQ_API_KEY`, `MODEL_NAME`, `MODEL_PROVIDER`,
  `LOCAL_MODEL_PATH` all **empty** (values not printed).
- Secret-pattern grep (sk-/gsk_/AKIA/ghp_/`api_key=...`) over tracked files excluding vendored
  dirs: only `README.md:385` placeholder.
- `src/`: no `eval`, `exec`, `pickle`, `yaml.load`, `shell=True`, `os.system`. `subprocess.run`
  with list args only in `src/clone/test_*.py` and `scripts/*.py`.
- `agents/camel/interpreter/interpreter.py:2231` uses raw `eval(field_type, ...)`; `agents/`
  is a third-party agent re-implementation outside the first-party pipeline; flagged for awareness.
- Path traversal: no payload-derived strings reach filesystem APIs in `src/` (ledger paths come
  from configuration; `storage_dir / name` uses fixed names).
- Archive handling: none in `src/`.

---

## 6. Dependencies

### D1. Vendored vs pip AgentDojo -- High / Confirmed

- `pip show agentdojo` -> 0.1.35 in `.venv\Lib\site-packages`; `agentdojo/pyproject.toml` ->
  0.1.35. `import agentdojo` from plain `python` resolves to **site-packages**.
- `pytest.ini`: `pythonpath = src agentdojo/src` -> tests import the **vendored** copy.
- SHA-256 comparison of the 82 vendored `agentdojo/src/agentdojo/**/*.py` files against the pip
  copy: **64 differ, 14 missing from pip** (e.g. `agents/*`, `attacks/data_only_attack.py`,
  `default_suites/v1/camel_bypass_poc/*`, `default_suites/v1/security_checks.py`,
  `benchmark_prev.py`, `task_suite/task_suite_prev.py`). After normalising CRLF/LF,
  `agent_pipeline/tool_execution.py` (163 vs 158 lines), `functions_runtime.py` (320 vs 313)
  and `agent_pipeline/agent_pipeline.py` (275 vs 266) still differ; `types.py` is identical.
- Consequence: `TrustVerificationToolsExecutor(ToolsExecutor)` is tested against one
  `ToolsExecutor`/`FunctionsRuntime` and run against another. Behavioural differences in
  argument conversion or result formatting would silently change what the detector sees.
  Proposal: pick one copy (editable install of the vendored tree, `pip install -e agentdojo`,
  or remove the vendored tree) and record the decision.

### D2. Requirements do not describe the environment -- Medium / Confirmed

`requirements.txt` = `cohere>=5.3.4`, `scikit-learn>=1.5,<2`. The venv has 84 packages
(inventory below). No `pyproject.toml`, `requirements.lock`, `uv.lock` or `pip freeze` output
for the first-party project (the vendored agentdojo has its own `uv.lock`). Reproducing the
research environment from the repo is not possible.

### Inventory of key versions (`.\.venv\Scripts\python.exe -m pip list`, 2026-11-15)

| package | version | role |
|---|---|---|
| Python | 3.12.10 | interpreter |
| agentdojo | 0.1.35 | benchmark framework (dual copy, D1) |
| pydantic / pydantic_core | 2.13.5 / 2.46.5 | parser models, schema validation |
| scikit-learn / scipy / numpy | 1.9.1 / 1.18.1 / 2.5.4 | WL-SVM |
| joblib | 1.6.0 | model persistence (S5) |
| cohere | 7.2.0 | LLM client (requirements says >=5.3.4) |
| openai / anthropic / google-genai | 3.22.1 / 1.9.0 / 2.25.0 | LLM clients (via agentdojo) |
| langchain / langchain-core / langgraph | 1.4.3 / 1.6.6 / 1.2.12 | agentdojo deps |
| requests / urllib3 / httpx / cryptography | 2.34.2 / 2.8.0 / 0.28.1 / 50.0.1 | HTTP stack |
| PyYAML | 6.0.3 | agentdojo `yaml_loader` (first-party code does not call yaml) |
| python-dotenv | 1.2.3 | `.env` loading |
| pytest | 9.1.1 | tests |

### D3. Advisory check -- Low / Strongly supported

Only joblib was checked against public advisories (web search; rate limits prevented further
lookups, see limitations):

- CVE-2022-21797: arbitrary code execution via `eval()` in `Parallel(pre_dispatch=...)`; fixed in
  joblib 1.2.0. Installed 1.6.0 is **not affected**. Sources: [Gentoo GLSA 202401-01](https://security.gentoo.org/glsa/202401-01),
  [NVD CVE-2022-21797](https://nvd.nist.gov/vuln/detail/CVE-2022-21797),
  [Safety SFTY-20220926-34155](https://getsafety.com/vulnerabilities/SFTY-20220926-34155).
- CVE-2024-34997: unsafe pickle deserialisation in joblib; the sources found disagree on attack
  vector and give no clean fixed version. Source: [Feedly CVE-2024-34997](https://feedly.com/cve/CVE-2024-34997).
  A public PoC of code execution on `joblib.load` exists: [Hugging Face PoC](https://huggingface.co/joekaw/j0x-critical-poc).
  Mitigation for this project is behavioural (S5), independent of version.
- Not verified (limitation): whether `requests 2.34.2`, `urllib3 2.8.0`, `cryptography 50.0.1`,
  `pydantic 2.13.5`, `scikit-learn 1.9.1` carry open advisories as of the audit date. Version
  strings are recent (2026) so "very outdated" does not apply, but no advisory lookup was done.

---

## 7. Proposals (all require researcher approval; none implemented)

1. **Ledger persistence:** append events to `ledger.jsonl` incrementally (open in append mode,
   write one line per event) and persist raw payloads once at capture; drop the full rewrite.
   Alternatively persist only at run end. Expected effect: removes the quadratic term (P1) and
   makes reported overhead independent of run length.
2. **Bounded retention:** cap `raw_payloads` by count/bytes per run or make raw retention opt-in
   per payload size; expose `clear()`/per-run eviction to benchmark harnesses.
3. **Surrogate-safe hashing** (S1) and routing of `capture()` exceptions into a fail-closed
   verdict rather than an unhandled exception.
4. **Detector execution:** a reusable worker (thread pool of 1) instead of a thread per call
   (saves ~0.6 ms per hop) and a cooperative deadline passed into the detector so a timeout stops
   the work instead of leaking a busy thread.
5. **Findings cap and scan budget** in `parser.py`/`structural.py` (S3).
6. **Rewrite `_OK_PREFIX`** (S2) and add a regression test with a 2 000-space prefix under a
   time bound; consider running a ReDoS linter over all `_COUNTED`/`_WEAK`/dom/md patterns.
7. **Single AgentDojo copy** (D1) and a frozen requirements/lock file generated from the venv (D2).
8. **Report overhead honestly:** when publishing latency numbers, state whether persistence was
   on, and measure around `check_call`/`check_result` rather than `detector_latency_ms`.

---

## 8. Exact commands run (abridged)

```
git branch --show-current                      -> zain/experimental
git status --short                             -> (clean)
git ls-files .env .env.example                 -> .env.example
.\.venv\Scripts\python.exe -m pip list
.\.venv\Scripts\python.exe -m pip show agentdojo
.\.venv\Scripts\python.exe -c "import agentdojo, inspect; print(inspect.getfile(agentdojo))"
Get-FileHash comparison of agentdojo\src\agentdojo\**\*.py vs .venv\Lib\site-packages\agentdojo\**\*.py
.\.venv\Scripts\python.exe <scratchpad>\bench_hotpath.py
.\.venv\Scripts\python.exe <scratchpad>\probes.py        (each probe: python -I -c ... with 60 s timeout)
.\.venv\Scripts\python.exe <scratchpad>\probes2.py       (per-case 20-60 s timeouts)
.\.venv\Scripts\python.exe <scratchpad>\probe_okprefix.py (per-case 12 s timeout)
```

No repository file other than this document was created or modified.
