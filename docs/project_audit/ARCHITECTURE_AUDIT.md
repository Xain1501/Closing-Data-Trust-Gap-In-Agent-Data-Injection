# Architecture Audit — "Closing the Data Trust Gap in Agent Data Injection"

Date: 2026-11-15 · Branch audited: `zain/experimental` (HEAD `66fec89`) · Mode: read-only research audit
Author role: Architecture Analyst (automated audit, no code changed)

How to read this document
- Every finding carries **Severity** (Critical / High / Medium / Low / Informational), **Confidence**
  (Confirmed / Strongly supported / Hypothesis / Research-dependent) and **Type** (architectural issue /
  implementation defect / performance issue / unresolved design decision / research opportunity).
- Each finding separates **Observation** (what the files say), **Interpretation** (what it means) and
  **Recommendation** (a proposal, never an action taken). All recommendations in Section 9 require researcher approval.
- Citations are `path:line` relative to the repository root. Nothing below was fabricated; where a claim was not
  verified by reading or running something it is labelled Hypothesis.
- `src/provenance/` (empty package) is a planned placeholder for tagging step 1.3 and is **not** treated as dead code.
  `src/trust_graph/tagging.py` was rewritten in commit `66fec89` (step 1.2) and is treated as in-progress work.

---

## 1. Architecture overview

### 1.1 Intended pipeline (from `docs/tagging-design.md:11-13`)

```
clone -> parser -> TAGGING -> trust-provenance graph -> WL kernel + SVM -> risk gate -> review
```

### 1.2 What actually exists (component / flow diagram)

```
                         AgentDojo agent loop (vendored fork OR pip 0.1.35 — see F-01)
                         AgentPipeline([SystemMessage, InitQuery, llm, ToolsExecutionLoop([executor, llm])])
                                                  |
                                                  | assistant message with tool_calls
                                                  v
 +------------------------------------------------------------------------------------------------+
 | src/clone/adapters/agentdojo.py  TrustVerificationToolsExecutor(ToolsExecutor)   [framework adapter] |
 |   _framework_args() -> {"tool", "args"}      output_formatter(tool_result) -> str                 |
 +---------------------------+------------------------------------------+-------------------------+
                             | check_call(pre)                          | check_result(post)
                             v                                          v
 +------------------------------------------------------------------------------------------------+
 | src/clone/core.py  InterceptionCore  [framework-neutral]                                        |
 |   TrustMatrix.lookup (tvm.py, tool_matrix.json, 70 entries)                                    |
 |   InterceptionLedger.capture / transition (ledger.py, hash chain, optional JSONL persistence)   |
 |   _run_detector(): daemon thread + Queue timeout (default 2 s) -> DetectorDecision | error      |
 |   mode: off | passthrough | enforce ; denial text returned to the agent                         |
 +---------------------------------------------+--------------------------------------------------+
                                               | detector(payload_copy, DetectorContext)
                                               v
          +------------------------------------+--------------------------------------+
          |  Detector A (wired today)           |  Detector B (opt-in, tested, not run live)  |
          |  pipeline/clone_parser_detector.py  |  pipeline/risk_detector.make_risk_detector  |
          +------------------------------------+--------------------------------------+
                           |                                       |
                           v                                       v
          pipeline/parser_analysis.analyze_clone_payload   (shared: ToolTraffic -> parse -> schema -> structural)
                           |                                       |
          parser/parser.parse()  --> ParseResult(fields, status)   |
          parser/structural.structural_flags() --> StructuralReport (hit_count, S)
          parser/schema_registry + structural.check_schema (schema from DetectorContext.schema)
                           |                                       |
          allow iff OK & no hits & schema ok                       v
                                                 trust_graph.tagging.tag_fields(parse_result, field_trust_classes)
                                                   [LEGACY 2-arg path; TVM "unclassified" -> everything UT]
                                                                   v
                                                 trust_graph.graph.build_trust_graph -> classifier.wl_svm.GraphSnapshot
                                                                   v
                                                 classifier.wl_svm.WLGraphSVM.predict  (joblib artifact, sklearn)
                                                                   v
                                                 pipeline/classifier_gate.classify_and_assess
                                                   -> pipeline/risk_gate.assess_risk  (risk = p_attack * impact_tier)
                                                                   v
                                                 pipeline/evidence_panel.EvidencePanel -> reviewer callback
                                                   -> risk_gate.resolve_review -> DetectorDecision

   NOT CONNECTED to the live path:
     trust_graph.tagging NEW API  tag_fields("pre"|"post", tool_name, fields, ProfileEntry, run_state)  (step 1.2)
     src/provenance/  (RunState, lineage — step 1.3 placeholder)
     parser/stage1.analyze(), parser/dom_flag.py, parser/md_flags.py  (only reachable from parser's own tests/evals)
     src/detector/, src/risk/  (empty, untracked directories)
```

### 1.3 Entry points (how a run actually starts)

| Entry point | What it does | Dependencies | Output |
|---|---|---|---|
| `scripts/live_clone_parser_smoke.py:24-110` | Real Groq-backed AgentDojo `workspace/user_task_0`, optional `--attack`, through `TrustVerificationToolsExecutor(parser_detector, mode="enforce")` with an explicit JSON formatter (`:43`) | agentdojo (whichever copy imports), `clone`, `pipeline.clone_parser_detector`, `python-dotenv`, `GROQ_API_KEY` | `runs/live_clone_parser_smoke/<stamp>/{ledger,raw-payloads,run-metadata}.jsonl`, `summary.json` |
| `scripts/run_phase1_cases.py:95-147` | Offline Stage-1 conformance + detection metrics over the 100 Phase-1 fixtures | `parser.*` via `sys.path.insert(0, src)` (`:29`) | stdout report, `experiments/results/phase1_run.json` |
| `scripts/build_phase1_cases.py` | Deterministic builder of the 100-case fixture set by replaying AgentDojo ground-truth calls | agentdojo, `src/parser` **flat layout** (`:41`) | `tests/fixtures/phase1/*` |
| `scripts/pdi_build_cases.py` | Builds email ADI cases from `llm-benchmark` generated instances, with extra delimiter variants | llm-benchmark output files | `tests/fixtures/cases/*.jsonl` |
| `python -m classifier.train <graphs.jsonl> <model.joblib>` (`src/classifier/train.py:48-58`) | Trains/saves the calibrated WL-SVM from pre-built graph JSONL | sklearn, joblib | `.joblib` artifact |
| `python -m pipeline.evaluation <cases.jsonl>` (`src/pipeline/evaluation.py:94-100`) | ASR / utility / FPR / FNR metrics over per-case agent results | stdlib | JSON on stdout |
| `src/parser/demo.py`, `eval.py`, `adi_eval.py`, `agentdojo_offline.py` | Developer demos / offline parser evaluations | flat-layout imports (`from models import ...`) | stdout |
| `pytest` (root) | `pythonpath = src agentdojo/src`, `testpaths = tests src/clone src/pipeline` (`pytest.ini:2-3`) | root `.venv` | 310 tests collected (verified) |
| `python -m agentdojo.scripts.benchmark --agent baseline ...` (`README.md:401-467`) | Upstream ADI benchmark runner; the `agents/*` defenses | vendored agentdojo via `uv` | `runs/` |

There is **no single pipeline driver** that assembles clone + parser + tagging + graph + classifier + gate for a real
run. The only live driver uses the parser-only detector; the classifier path is exercised solely by
`src/pipeline/test_classifier_risk_evaluation.py` with a synthetic in-test classifier.

### 1.4 Data flow of one intercepted tool call (traced)

1. Agent emits `tool_calls`; `ToolsExecutionLoop` calls `TrustVerificationToolsExecutor.query` (`src/clone/adapters/agentdojo.py:51`).
2. `run_id` is minted per `extra_args` (`:69-72`); each call's args are normalised by `_framework_args` (`:157-168`, `literal_eval` of list-looking strings).
3. `InterceptionCore.check_call` (`src/clone/core.py:83-164`): TVM lookup by `(tool_name, expected_keys)`; payload `{"tool","args"}` captured into the ledger with hash; detector invoked in a daemon thread with a deep copy; outcome `allowed` / `blocked` / `passthrough_release`; a denial also writes a synthetic post record (`_deliver_denial`, `:273-303`).
4. If allowed, the adapter executes the tool (`agentdojo.py:117`), formats the result with `self.output_formatter` (`:118`) and calls `check_result` (`core.py:172-256`) with the **string** result and the pre-interception id.
5. The detector (`pipeline/clone_parser_detector.py:9-49`) converts payload to `ToolTraffic` (`pipeline/parser_analysis.py:37-61`: pre-hop uses `payload["args"]`), parses, validates against `DetectorContext.schema`, scans structure, and returns `DetectorDecision(allowed = usable and no hits and schema ok)`.
6. The adapter returns the original observation or the denial text to the model (`agentdojo.py:133-152`).
7. Ledger persistence (if `storage_dir` set) rewrites all three JSONL files after every capture/transition (`ledger.py:334-352`).

---

## 2. Component responsibilities (as implemented)

| Module | Responsibility | State | Notes |
|---|---|---|---|
| `src/clone/core.py` | Framework-neutral interception, policy modes, detector invocation/timeouts, ledger lifecycle | Mature, tested (`test_core.py`, `test_static.py` 45 tests) | Pure; imports only `clone.ledger`, `clone.tvm` |
| `src/clone/adapters/agentdojo.py` | AgentDojo `ToolsExecutor` subclass bridging the core | Mature | Only place that imports `agentdojo` inside the defense proper |
| `src/clone/interceptor.py` | Backward-compatible re-export shim | Legacy | Importing it pulls in agentdojo (`:3`) |
| `src/clone/tvm.py` + `tool_matrix.json` | Read-only Tool Trust Matrix: 70 entries, impact tiers, `field_trust_classes` (all `"unclassified"` in the sampled entry), `authority_arguments` | Schema v1 | Linear lookup; strict validation on load |
| `src/clone/ledger.py` | In-memory interception trace, hash-chained event log, raw payload store, optional JSONL snapshots | Mature | Thread-safe via one `Lock` |
| `src/parser/models.py` | Pydantic contracts (`ToolTraffic`, `ParseResult`, `StructuralReport`, `TaggedField` stub, …) | Stable | Shared by all stages |
| `src/parser/parser.py` | Pure JSON parse to addressable fields; status; duplicate-key preservation | Stable, tested | Limits: 1 MB / depth 32 / 100k fields |
| `src/parser/structural.py` | Structural flag heuristics (`S`), schema check | Stable, tested | Heuristic regexes; paper-derived delimiter table |
| `src/parser/stage1.py` | "Single entry point" `analyze()` (json / dom / markdown, min_hits) | Orphaned from the pipeline | See F-07 |
| `src/parser/dom_flag.py`, `md_flags.py`, `schema_registry.py` | Text/DOM and Markdown heuristics; per-tool schema registry | Stable | dom/md unreachable from live path |
| `src/parser/{demo,eval,adi_eval,agentdojo_offline,make_extra_cases}.py` | Developer evaluation tooling | Scripts living inside the library package | Flat-layout imports |
| `src/trust_graph/tagging.py` | NEW field-level tagging (Provenance / Role / LineageStatus / `FieldTag` / `ProfileEntry`) + legacy 2-arg `tag_fields` | In progress (step 1.2) | Not wired; no `test_tagging.py` yet (commit msg) |
| `src/trust_graph/graph.py` | `TaggedField` + findings -> `GraphSnapshot` | Minimal | Consumes legacy `TaggedField`, not `FieldTag` |
| `src/classifier/wl_svm.py`, `train.py` | WL feature map, calibrated linear SVM, joblib persistence, CLI trainer | Implemented, tested via pipeline tests | No trained artifact or training JSONL in repo |
| `src/pipeline/*` | Detector bridges, shared parse pass, classifier gate, risk gate, evidence panel, evaluation metrics | Implemented | Two detectors (parser-only vs risk-composed) |
| `src/provenance/` | Placeholder for `RunState` and lineage (step 1.3) | Empty `__init__.py` | Planned, not dead |
| `src/detector/`, `src/risk/` | Empty directories, no git history | Untracked | See F-10 |
| `agents/*` | Upstream ADI benchmark defense agents (LangGraph / CaMeL / Progent) | Vendored | Do not reference `clone` (grep confirmed) |
| `agentdojo/` | Vendored AgentDojo fork with ADI attacks | Vendored | Dual copy with pip 0.1.35 (F-01) |
| `llm-benchmark/` | Upstream standalone LLM ADI benchmark | Vendored | Source of `pdi_build_cases.py` inputs |
| `benchmarks/`, `experiments/config/` | Empty | — | README (`README.md:155-203`) describes planned use |
| `tests/unit/` | `test_phase1_cases.py` (238 parametrised tests); `test_parser.py`, `test_classifier.py`, `test_provenance.py` are **0-byte** | Partially placeholder | See F-06 |

---

## 3. Dependency map

### 3.1 Import graph (own code; verified by grep over `src/`)

```
parser.models  <-- parser.parser <-- parser.structural <-- parser.schema_registry <-- parser.stage1
     ^                 ^                   ^
     |                 |                   |
trust_graph.tagging    pipeline.parser_analysis ----------------------+
trust_graph.graph ---> classifier.wl_svm                               |
     ^                      ^                                          |
     |                      |                                          |
pipeline.risk_detector ---> pipeline.classifier_gate -> pipeline.risk_gate <- pipeline.evidence_panel
     |                                                                 |
     +----> clone.core, clone.ledger  <---- pipeline.clone_parser_detector
                 ^
clone.adapters.agentdojo ---> agentdojo.*      (only defense module importing the framework)
clone.interceptor ----------> clone.adapters.agentdojo (shim)
parser.agentdojo_offline ---> agentdojo.*      (eval tool inside the parser package)
scripts/* -------------------> agentdojo.*, clone, parser, pipeline (via sys.path hacks)
```

Layering summary:
- Framework-neutral core (`clone.core`, `parser.*` except `agentdojo_offline`, `trust_graph`, `classifier`, `pipeline`) does **not** import `agentdojo` — the design rule in `docs/tagging-design.md:28-30` is respected for tagging. **Confirmed.**
- `src/parser/agentdojo_offline.py:7-9` is the one framework import inside a "neutral" package; it is an evaluation tool, not pipeline code, but it lives in the library package.
- `trust_graph.graph` depends on `classifier.wl_svm` for `GraphSnapshot` (`graph.py:5`), i.e. the graph stage depends *downstream* on the classifier for its output type. Mild inversion (F-08).

### 3.2 Environment / path mechanics

| Mechanism | Where | Effect |
|---|---|---|
| `pythonpath = src agentdojo/src` | `pytest.ini:2` | Under pytest the **vendored** AgentDojo wins and `parser`, `clone`, … are top-level packages |
| `python.analysis.extraPaths` | `.vscode/settings.json` | Pylance sees both roots; interpreter path points at `llm-benchmark/.venv`, which **does not exist** on this machine (verified: only root `.venv`) |
| `sys.path.insert(0, ROOT/"src")` | `scripts/run_phase1_cases.py:29` | `parser` = the package |
| `sys.path.insert(0, ROOT/"src"/"parser")` | `scripts/build_phase1_cases.py:41` | `parser` = the **module** `parser.py`; `models`, `structural`, `agentdojo_offline` become top-level |
| `sys.path.insert(0, ROOT/"scripts")` | `tests/unit/test_phase1_cases.py:20` | A unit test imports a script (`run_phase1_cases`) |
| `try: from .models … except ImportError: from models …` | `parser/parser.py:17-20`, `structural.py:27-32`, `stage1.py:24-37`, `schema_registry.py:12-16`, `eval.py`, `adi_eval.py` | Dual package/flat import identity for the same files |
| No `pyproject.toml` / `setup.cfg` for `src/` | repo root | Nothing is installable; `requirements.txt:1-2` lists only `cohere` and `scikit-learn` |

---

## 4. Execution flows in detail

### 4.1 Live parser-only enforcement (the only end-to-end path that runs today)
`scripts/live_clone_parser_smoke.py` → `AgentPipeline` → `TrustVerificationToolsExecutor.query` → `InterceptionCore.check_call` → `parser_detector` → `analyze_clone_payload` → `parse` + `check_schema` + `structural_flags` → `DetectorDecision` → execute or deny → `check_result` → same detector on the formatted string → release or deny → ledger JSONL. Integrity re-check: reload `ledger.jsonl`, `verify_chain`, compare post-hop payload hashes (`:63-77`).

### 4.2 Risk-composed path (tested, not driven)
`make_risk_detector(classifier, reviewer, user_query)` (`pipeline/risk_detector.py:17`) → `analyze_clone_payload` → hard blocks for unusable parse / schema / missing impact tier (`:36-44`) → legacy `tag_fields(parsed, field_trust_classes)` (`:46`) → `build_trust_graph` → `classify_and_assess` → `EvidencePanel` → reviewer callback or fail-closed `deny` (`:78-81`) → `resolve_review` → `DetectorDecision`. Requires a trained `WLGraphSVM`; none is shipped and there is no graph JSONL to train one from.

### 4.3 Offline Stage-1 evaluation
`scripts/run_phase1_cases.py` and `tests/unit/test_phase1_cases.py` share `evaluate()`; `parse` + `structural_flags` directly (not `stage1.analyze`). Results JSON records git rev and `agentdojo` package version (`:138-141`).

### 4.4 Training (classifier)
`classifier/train.py` consumes `{"case_id","label","graph":{node_labels,edges}}` JSONL. No code path produces this file from the parser/tagger output; graphs must be produced by hand or by future tooling (F-09).

---

## 5. State, configuration, logging, errors, external services

- **State.** Per-run state lives in `InterceptionLedger` (records, event chain, raw payloads, run metadata). `run_id` is minted by the adapter and travels in `extra_args["_clone_tvm_run_id"]` (`adapters/agentdojo.py:18,69-72`). The future `RunState` (design doc §4) is to be caller-supplied; no owner of it exists yet.
- **Configuration.** Mode / timeout / formatter / matrix path are constructor arguments; there is no config file, no CLI flags beyond the smoke script, and `experiments/config/` is empty. Parser limits are module constants (`parser.py:22-24`). Risk thresholds are literals in `risk_gate.py:59-69`.
- **Environment.** `.env` (git-ignored) with `GROQ_API_KEY`; loaded only in `live_clone_parser_smoke.py:28`. `python-dotenv` is not in `requirements.txt`; it arrives transitively via AgentDojo's dependencies (`agentdojo/pyproject.toml`).
- **Logging.** No `logging` usage anywhere in `src/` (grep for `import logging` returned nothing in the own-code modules read). The ledger *is* the audit log; developer feedback is `print` in scripts.
- **Error handling.** Detector exceptions and timeouts become `detector_error` → block in `enforce`, release in `passthrough` (`core.py:305-341,355-387`). Expected parse failures never raise (`parser.py:116-156`). Validation errors in loaders raise `ValueError` early (`tvm.py`, `train.py`, `evaluation.py`).
- **External services.** Only the agent's LLM (Groq in the smoke script, `openai/gpt-oss-120b`, `:32`). The defense itself calls no LLM (evidence panel renders without one, `evidence_panel.py:59-61`).
- **Test infrastructure.** `pytest.ini` collects `tests/`, `src/clone`, `src/pipeline` only. Verified collection: 238 (`tests/unit/test_phase1_cases.py`) + 45 + 7 (`src/clone`) + 14 + 6 (`src/pipeline`) = 310. The eight `src/parser/test_*.py` files are **not collected** by the root run.

---

## 6. Findings

### F-01 Dual AgentDojo copies decide the post-hop payload format
- **Severity:** High · **Confidence:** Confirmed · **Type:** architectural issue / unresolved design decision
- **Observation.** Vendored `agentdojo/src/agentdojo/agent_pipeline/tool_execution.py:23` defaults `dump_fn = json.dumps`; pip 0.1.35 at `.venv/Lib/site-packages/agentdojo/agent_pipeline/tool_execution.py:23` defaults `yaml.safe_dump` (verified by grep). Root `.venv` resolves `import agentdojo` to the pip copy (verified: `.venv\Lib\site-packages\agentdojo\__init__.py`); pytest resolves to the vendored copy (`pytest.ini:2`). The adapter inherits whichever default is imported when `tool_output_formatter is None` (`src/clone/adapters/agentdojo.py:34-35`). `README.md:28-33` instructs installing into `llm-benchmark/.venv` (absent on this machine) with an editable vendored install.
- **Interpretation.** Blast radius: (a) every post-hop detector result depends on the interpreter used — under YAML the parser returns `not_json`/`invalid_json`, the parser-only detector then **blocks every structured result** (`clone_parser_detector.py:22-24`, `parser_analysis.py:25-34`), and per-field tagging is impossible; (b) pytest and "plain python" exercise different framework code (types, `FunctionsRuntime`, attack classes); (c) results files record `version("agentdojo")` (`run_phase1_cases.py:140`) but not *which copy* was imported. The smoke script already mitigates (a) by passing an explicit JSON formatter (`live_clone_parser_smoke.py:43`); the adapter default does not.
- **Recommendation.** Resolve D1/D2 from `docs/tagging-design.md:389-392`: make the adapter default the formatter explicitly (JSON) rather than inheriting; pick one AgentDojo copy, remove or pin the other, and record `agentdojo.__file__` in run outputs. Trade-off: pinning the vendored fork keeps the ADI attacks but diverges from upstream fixes; pinning pip loses the ADI attack suite.

### F-02 The documented pipeline is not assembled anywhere; tagging/graph/classifier run only in tests
- **Severity:** High · **Confidence:** Confirmed · **Type:** architectural issue
- **Observation.** The only live driver (`scripts/live_clone_parser_smoke.py:45-51`) wires `parser_detector`. `make_risk_detector` (`src/pipeline/risk_detector.py`) is referenced solely by `src/pipeline/test_classifier_risk_evaluation.py:11`. No trained `WLGraphSVM` artifact, no graph-training JSONL and no code that emits graph JSONL from parsed traffic exist in the repo (`train.py:1-8` expects a hand-built format). The new `tag_fields("pre"|"post", …)` API (`tagging.py:133-169`) has no caller; `risk_detector.py:46` still calls the legacy form.
- **Interpretation.** The "end-to-end" claim currently means clone + parser. Everything after the parser is unit-validated but unmeasured on real traffic. This is expected for an in-progress FYP, but it is the main gap between `docs/tagging-design.md:11` and reality.
- **Recommendation.** After step 1.3, add one composition module (e.g. `pipeline/compose.py` or a `scripts/run_pipeline.py`) that builds the full detector from configuration, plus a graph-JSONL exporter so the classifier can be trained from Phase-1 fixtures. Trade-off: committing to a composition now may constrain the step-1.3 `RunState` ownership decision; keep it thin.

### F-03 Legacy tagging mis-keys post-hop results and the TVM carries no trust classes
- **Severity:** High · **Confidence:** Confirmed · **Type:** implementation defect (in the legacy path) / unresolved design decision
- **Observation.** `risk_detector.py:46` tags both directions with `context.matrix_entry.field_trust_classes`, which is keyed by **argument names** (`tvm.py:80-82`, must equal `expected_keys`). For post-hop payloads the field paths are result paths (`$[0].body`), so `_root_key` (`tagging.py:284-290`) never matches and every field defaults to `UT` (`:278-279`). Moreover the sampled matrix entry has every class `"unclassified"` (`tool_matrix.json`, first entry) — so even pre-hop everything is `UT`. The graph label is `trust:value_type:depth` (`graph.py:18`).
- **Interpretation.** In the current composed path the trust dimension of the graph is constant; the WL-SVM would effectively learn from shape and findings only. The design doc acknowledges this path is to be replaced (`:260-264`) but the gap should be stated explicitly in any interim results.
- **Recommendation.** Treat any interim classifier numbers from the legacy path as shape-only baselines; prioritise wiring `FieldTag` (provenance + role) into `build_trust_graph`. No code change proposed before step 1.3.

### F-04 Ledger persistence rewrites all files on every transition (quadratic I/O)
- **Severity:** Medium · **Confidence:** Confirmed · **Type:** performance issue / reliability concern
- **Observation.** `_persist_locked` (`src/clone/ledger.py:334-352`) serialises the **entire** ledger, raw-payload list and run metadata to three temp files and replaces them on every `capture`, `transition` and `set_run_metadata` — typically 5–7 times per tool call (`core.py` transitions: captured, decision_pending, decision_received, allowed/blocked, executed, released…). Raw payloads include full tool results.
- **Interpretation.** Write volume grows O(n²) with interceptions per ledger; for a multi-suite benchmark run with persistence enabled this will dominate latency and could exceed the 2 s detector budget indirectly (persistence happens inside the lock on the executor thread, not in the detector thread). Memory is also unbounded (`records`, `raw_payloads`, `ledger` lists are never truncated).
- **Recommendation.** Append-only JSONL for the event chain (it is already hash-chained and append-friendly), snapshot raw payloads once at capture, and keep the atomic-replace only for run metadata. Trade-off: append-only files need a recovery check on reload (`import_ledger` already recomputes `verify_chain`).

### F-05 Detector timeout leaks the worker thread and cannot cancel work
- **Severity:** Medium · **Confidence:** Confirmed · **Type:** reliability concern
- **Observation.** `_run_detector` (`core.py:355-387`) starts a daemon `Thread` per inspection and waits on a `Queue` with `timeout_s`; on timeout it returns an error but the thread keeps running to completion. The default timeout is 2 s (`core.py:56`).
- **Interpretation.** A slow or hung detector (e.g. a large payload through the regex scanner in `structural.py:38-48`, or a future lineage pass over a 2 M-char `RunState`) accumulates threads; under `enforce` the call is blocked (fail-closed, correct), under `passthrough` released. The daemon thread also still holds its deep copy of the payload. Not a correctness bug, but a resource and determinism concern for benchmark-scale runs.
- **Recommendation.** Use a bounded `ThreadPoolExecutor` with a per-call `Future`, record `latency_ms` even on timeout, and expose a hard upper bound on payload size handed to detectors. Trade-off: pool reuse changes thread-identity assumptions in `test_static.py` if any test inspects thread names.

### F-06 Test infrastructure: parser tests are not collected; three unit files are empty; a test imports a script
- **Severity:** High · **Confidence:** Confirmed · **Type:** implementation defect (test configuration)
- **Observation.** `pytest.ini:3` lists `tests src/clone src/pipeline`; `src/parser/test_parser.py`, `test_structural.py`, `test_stage1.py`, `test_dom.py`, `test_dom_layout.py`, `test_dom_linenum.py`, `test_md_flags.py` (≈580 lines) are outside it (verified: 310 collected, none from `src/parser`). `tests/unit/test_parser.py`, `test_classifier.py`, `test_provenance.py` are 0 bytes. `tests/unit/test_phase1_cases.py:20-22` inserts `scripts/` on `sys.path` and imports `run_phase1_cases`. `.vscode/settings.json` `pytestArgs` lists only `tests` and `src/clone`.
- **Interpretation.** A regression in `structural.py` regexes would only be caught indirectly via Phase-1 conformance; the parser's own limit tests (`MAX_FIELDS`, depth, schema) are silently skipped in CI-style runs. The empty files create a false sense of coverage in `tests/unit/`.
- **Recommendation.** Add `src/parser` to `testpaths` (or move parser tests under `tests/unit/`), delete or fill the 0-byte files, and move the shared `evaluate()` helper out of `scripts/` into `src/` so tests do not import scripts. Trade-off: parser tests use flat-layout fallbacks (`test_stage1.py:10-15`) and may need import fixes when collected from the root.

### F-07 Two orchestrations of Stage 1 with divergent policy (`stage1.analyze` vs `parser_analysis`)
- **Severity:** Medium · **Confidence:** Confirmed · **Type:** architectural issue (duplicate / divergent implementation)
- **Observation.** `src/parser/stage1.py:1-3` calls `analyze()` "the single entry point of Stage 1" and supports `fmt="json"|"dom"|"markdown"`, `min_hits`, and a `text_schema_ok` rule (`:94-97`). The pipeline never calls it: `pipeline/parser_analysis.py:37-61` re-implements the parse → schema → structural sequence with its own `usable` rule (`:24-34`). `dom_flag.py` and `md_flags.py` are therefore unreachable from the clone path. `src/pipeline/README.md` describes only the pipeline version.
- **Interpretation.** Two sources of truth for "what counts as usable text" (`stage1.py:94` vs `parser_analysis.py:30-34` — they agree today but are maintained separately), and the DOM/Markdown heuristics the parser team built have no production consumer. `src/parser/eval.py` and `adi_eval.py` also each implement their own routing (`eval.py:7-12`, `adi_eval.py:15-22`), a third and fourth variant.
- **Recommendation.** Either make `parser_analysis` delegate to `stage1.analyze` (and pass format from the TVM/profile) or retire `stage1.py` and document that DOM/Markdown are out of scope for the live pipeline. Trade-off: delegating pulls `min_hits` policy into the detector, which the risk gate currently treats as "any hit forces review" (`risk_gate.py:57-58`).

### F-08 Component boundary smells: graph depends on classifier; `TaggedField` lives in `parser.models`; evaluation tools live in the library package
- **Severity:** Low · **Confidence:** Confirmed · **Type:** architectural issue
- **Observation.** `trust_graph/graph.py:5` imports `GraphSnapshot` from `classifier.wl_svm`; `parser/models.py:104-106` defines the tagging output type `TaggedField` ("left here so the interface is fixed"); `src/parser/` contains five eval/demo scripts and eight tests beside the library; `src/parser/__init__.py` is empty so `from parser import parse` only works in flat layout.
- **Interpretation.** Dependency direction runs downstream→upstream for the graph type, and the parser package doubles as the parser team's workspace. Harmless now, but it makes the intended layering (parser → tagging → graph → classifier) harder to enforce and encourages the sys.path tricks in §3.2.
- **Recommendation.** Move `GraphSnapshot` to a neutral `trust_graph/types.py` (classifier imports it), let `FieldTag` supersede `TaggedField` once wired, and move `parser/{demo,eval,adi_eval,agentdojo_offline,make_extra_cases}.py` to `scripts/` or `experiments/`. Trade-off: churn in import paths across tests.

### F-09 No packaging, minimal requirements, mixed import identities
- **Severity:** Medium · **Confidence:** Confirmed · **Type:** architectural issue / reliability concern
- **Observation.** No `pyproject.toml` for `src/`; `requirements.txt:1-2` pins only `cohere` and `scikit-learn` while code imports `pydantic`, `joblib`, `python-dotenv`, `agentdojo`. Import identity differs per entry point (§3.2): `scripts/build_phase1_cases.py:41` treats `parser` as a module, `scripts/run_phase1_cases.py:29` as a package; commit `9244995` ("phase-1 test and runner shadowed the parser package") shows this has already bitten once. `parser` is also a generic top-level name that can collide with third-party packages.
- **Interpretation.** Reproducibility depends on an undocumented environment (root `.venv` with pip agentdojo) that contradicts `README.md:28-33`. Each new script needs its own path hack.
- **Recommendation.** Add a minimal `pyproject.toml` with `[tool.setuptools] package-dir = {"" = "src"}` (or `src` layout with a project name such as `adi_defense`), `pip install -e .`, full pinned requirements, and remove the `try/except ImportError` flat-layout fallbacks. Trade-off: renaming `parser` to avoid the generic name would touch every import; can be deferred.

### F-10 Empty, untracked scaffolding directories `src/detector/` and `src/risk/`
- **Severity:** Informational · **Confidence:** Confirmed · **Type:** redundant / obsolete component (local only)
- **Observation.** Both directories exist on disk (created 2025-09-30), contain no files, have no git history (`git log -- src/detector src/risk` empty) and are therefore not in the repository. The responsibilities their names suggest are implemented in `src/pipeline/{clone_parser_detector,risk_detector,risk_gate}.py`; `README.md:54-60` does not list them.
- **Interpretation.** Leftover local scaffolding from an earlier layout; teammates do not see them. They mislead only the local developer and tooling.
- **Recommendation.** Delete locally (not a repo change) or, if a `risk` package is intended to absorb `risk_gate.py`, record that decision in the design doc first.

### F-11 Ledger records `detector_decision=False` for allowed-but-unclassified tools
- **Severity:** Low · **Confidence:** Confirmed · **Type:** implementation defect (audit fidelity)
- **Observation.** In `check_call`, when the detector allows but the tool is a matrix fallback in `enforce` mode (`core.py:123-126`), control falls through to the common `blocked` transition which writes `detector_decision=False` (`:153-162`) and `label="unclassified"`, although the detector returned `allowed=True`.
- **Interpretation.** The ledger cannot distinguish "detector blocked" from "policy blocked despite detector allow" except via the label. For research metrics (detector FPR vs policy FPR) this conflates two causes.
- **Recommendation.** Record the actual detector verdict and add a separate `policy_decision` field (ledger schema v2). Trade-off: `entry_schema_version` bump invalidates chain verification of old files unless versioned.

### F-12 Evidence panel forwards raw untrusted strings to the reviewer
- **Severity:** Low · **Confidence:** Confirmed · **Type:** research opportunity / reliability concern
- **Observation.** `risk_detector.py:63-66` copies every `UT` string field value verbatim into `EvidencePanel.untrusted_content`, and `proposed_call_or_result` carries the full payload (`:62`).
- **Interpretation.** By design the reviewer must see the content, but the panel is the one place where attacker text reaches a human (or a future LLM-assisted reviewer) unmodified — the same channel the project is defending. The project's own goal (review as inert evidence, `risk_gate.py:106-110`) suggests rendering with provenance tags and length caps.
- **Recommendation.** Keep raw content but annotate each item with its tag (`path`, provenance, role, length) and truncate/escape for display; document the reviewer-injection threat in the design doc.

### F-13 `RunState` ownership and `interception_id` plumbing are undecided
- **Severity:** Medium · **Confidence:** Strongly supported · **Type:** unresolved design decision
- **Observation.** `docs/tagging-design.md:150-152,277` say `RunState` and `interception_id` are "supplied by the caller until the clone's `DetectorContext` carries them". `DetectorContext` (`core.py:19-25`) has no `run_id`, `interception_id`, or user prompt; the ledger owns `run_id` and the record id, but the detector receives only `(payload, context)`. `make_risk_detector` already needs a `user_query` callback for the same reason (`risk_detector.py:21,59`).
- **Interpretation.** Step 1.3 cannot be wired without either extending `DetectorContext` (a clone-owned change) or giving detectors access to the ledger (a layering break). This is the next architectural fork and is not yet recorded as a decision.
- **Recommendation.** Extend `DetectorContext` with `run_id`, `interception_id` and an optional `user_prompt` provider (clone remains the single owner of ids); keep `RunState` per-run inside the detector factory, cleared on run end. Trade-off: `DetectorContext` is frozen and used widely in `test_static.py`; add fields with defaults to stay backward compatible.

### F-14 Risk gate semantics worth re-checking before evaluation
- **Severity:** Low · **Confidence:** Strongly supported · **Type:** unresolved design decision / research opportunity
- **Observation.** `assess_risk` (`risk_gate.py:52-71`) computes `risk = p_attack × impact` with fixed cut-points 1.0 / 5.0 and forces review on any structural hit or `S > 0`. With impact 10 auto-allow needs `p_attack < 0.10`; with impact 1 it never exceeds `low` tier (max 1.0 → `moderate` only at exactly 1.0). `structural_score` is validated as a probability (`:46`) although documented as a density, not a probability (`:41-43`).
- **Interpretation.** Thresholds are untuned constants; the tier for impact-1 tools is effectively capped, which may be intended (low-impact tools never high risk) but should be a stated policy. `options` for `low` and `moderate` are identical (`:59-65`).
- **Recommendation.** Make cut-points configurable and derive them from the calibrated classifier's ROC on Phase-1 graphs; record the impact-1 cap as a design decision.

### F-15 `build_trust_graph` drops findings on non-field paths and key-findings
- **Severity:** Low · **Confidence:** Confirmed · **Type:** implementation defect (minor) / research opportunity
- **Observation.** `graph.py:24-26` attaches a finding node only if `finding.path.split("#",1)[0]` is a known field path. Key-name findings use `f"{path}#key"` (`structural.py:151`) so they attach to the field — fine — but duplicate-key findings are reported at the un-suffixed child path (`parser.py:100`) while the field itself is stored at `base#2` (`:101`); the first occurrence exists at `base`, so the edge lands on the *first* key's node, not the duplicate. Unattached findings still add isolated nodes.
- **Interpretation.** The WL features still see the finding label, but the topology signal ("which field was forged") is slightly off for duplicates.
- **Recommendation.** Attach duplicate-key findings to the suffixed node; add a test with `{"to":"a","to":"b"}`.

---

## 7. Redundant, divergent or obsolete elements (investigated)

| Item | Status | Verdict |
|---|---|---|
| `src/provenance/__init__.py` (empty) | Planned step 1.3 home (`tagging-design.md:255-256`) | Keep |
| `src/detector/`, `src/risk/` | Empty, untracked | Local leftovers (F-10) |
| `src/clone/interceptor.py` | Re-export shim; `test_static.py:21` still imports it | Keep until tests migrate; importing it forces agentdojo import |
| `parser/stage1.py` + `dom_flag.py` + `md_flags.py` | Not on the live path | Divergent orchestration (F-07) |
| `parser/eval.py`, `adi_eval.py`, `agentdojo_offline.py`, `make_extra_cases.py`, `demo.py` | Dev tooling inside library | Relocate (F-08) |
| `tagging.py` legacy `_legacy_tag_fields` | Deliberate compatibility shim (`tagging.py:10-13`) | Keep until wiring |
| `parser.models.TaggedField` vs `tagging.FieldTag` | Two tag types; graph consumes the old one | Converge after 1.3 |
| `tests/unit/{test_parser,test_classifier,test_provenance}.py` | 0 bytes | Placeholders (F-06) |
| `benchmarks/`, `experiments/config/` | Empty | README-planned |
| `README.md` | Two READMEs concatenated (FYP structure `:1-338`, upstream ADI `:339-573`) | Documentation debt; the "repository structure" section omits `clone/`, `agentdojo/`, `agents/`, `llm-benchmark/` |

---

## 8. Bottlenecks, single points of failure, reliability

| Concern | Evidence | Classification |
|---|---|---|
| Per-transition full-file persistence | F-04 | Performance, Medium |
| Detector thread-per-call with no cancellation | F-05 | Reliability, Medium |
| Single global `Lock` serialises all ledger work including disk writes (`ledger.py:140,189,334`) | Confirmed | Performance, Low (single-threaded executor today) |
| Linear TVM lookup over 70 entries per call (`tvm.py:42`) | Confirmed | Negligible now; Informational |
| Regex structural scan runs on every string field including 1 MB payloads (`structural.py:69-85`, two variants each) | Confirmed | Performance, Low–Medium under adversarial sizes; bounded by `MAX_BYTES` |
| `TrustMatrix` is the single source of impact tiers; a missing tool blocks every call in `enforce` (`core.py:123-126`) | Confirmed | SPOF by design (fail-closed); needs coverage tracking for new suites |
| The LLM provider (Groq) is the only external dependency; the defense has none | Confirmed | Good isolation |
| Default `tool_output_formatter=None` inherits framework default | F-01 | Reliability, High |
| No logging; failures inside scripts surface only via exceptions/prints | §5 | Low |

---

## 9. Proposed improvements (proposals only — require researcher approval)

Ordered by expected value for the FYP timeline; each lists the trade-off.

1. **Freeze the framework boundary (F-01).** Explicit JSON formatter default in the adapter; one AgentDojo copy; record `agentdojo.__file__` in every results file. *Trade-off:* a one-line behavioural change in the adapter that all existing static tests must be re-run against.
2. **Fix test collection (F-06).** Add `src/parser` to `testpaths`, remove or populate the three empty unit files, move `evaluate()` into `src/`. *Trade-off:* a handful of import fixes in parser tests.
3. **Decide the `RunState`/`DetectorContext` contract before step 1.3 (F-13).** Extend `DetectorContext` with ids and a prompt provider. *Trade-off:* frozen dataclass growth; keep defaults.
4. **One Stage-1 orchestration (F-07).** Pick `parser_analysis` or `stage1.analyze`; document DOM/Markdown scope. *Trade-off:* possible loss of `min_hits` flexibility.
5. **Append-only ledger persistence (F-04).** *Trade-off:* reload/verify logic must tolerate partial last lines.
6. **Minimal packaging (F-09).** `pyproject.toml`, full requirements, drop flat-layout fallbacks. *Trade-off:* every teammate re-installs once.
7. **Graph export + training path (F-02, F-09).** A script that turns Phase-1 fixtures into graph JSONL via the new tagger, so the classifier can be trained and the full detector driven live. *Trade-off:* depends on 3 and on profile entries (Phase 2).
8. **Ledger schema v2 (F-11)** with separate detector vs policy decisions. *Trade-off:* version handling in `verify_chain`.
9. **Reviewer-facing evidence hygiene (F-12)** and **risk-threshold calibration (F-14)** as research tasks for the evaluation phase.
10. **Housekeeping (F-08, F-10, §7).** Relocate dev tooling, delete local empty dirs, split the README into project vs upstream sections.

---

## 10. Divergence from `docs/tagging-design.md` §6 (intended layout vs reality)

| Design §6 entry | Reality on `zain/experimental` |
|---|---|
| `src/trust_graph/tagging.py` updated with new types and `tag_fields(direction, …)` | Present (`tagging.py:34-169`); legacy call retained as specified |
| `src/provenance/run_state.py` | Not yet present (step 1.3) |
| `src/provenance/lineage.py`; `normalise()` temporarily in `tagging.py` | `normalise` at `tagging.py:115-121`; `lineage.py` not yet present |
| `tests/unit/test_tagging.py` (step 1.2 fixtures) | **Missing** (commit `66fec89` message: "Not done yet") |
| `tests/unit/test_provenance.py` "exists, currently empty" | Matches (0 bytes) |
| Compatibility: `risk_detector.py` and a pipeline test use the old call | Confirmed (`risk_detector.py:46`, `test_classifier_risk_evaluation.py:13`) |
| §1: tagging never imports `clone.adapters` or `agentdojo` | Confirmed (`tagging.py` imports only `parser.models`) |
| §11 D1–D3 open decisions | Still open; F-01 shows D1/D2 are the highest-leverage items |

---

## Appendix A — Verification log (commands run, all read-only)

- `git branch --show-current` → `zain/experimental`
- `git log --oneline -15`; `git show --stat 66fec89`; `git log -- src/detector src/risk` (empty)
- `pytest --collect-only -q` with root `.venv` → 310 tests; per-file counts in §5
- `.venv\Scripts\python.exe -c "import agentdojo; print(agentdojo.__file__)"` → site-packages (pip 0.1.35)
- `grep dump_fn` on both `tool_execution.py` copies → `json.dumps` (vendored) vs `yaml.safe_dump` (pip)
- `tool_matrix.json`: `schema_version 1`, 70 tools
- Directory listings of `src/`, `tests/`, `scripts/`, `agents/`, `experiments/`, `benchmarks/`, `llm-benchmark/`
- No file other than this report was created; no repository file was modified.
