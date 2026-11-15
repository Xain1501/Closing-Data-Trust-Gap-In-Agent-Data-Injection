# Testing and Validation Audit

Read-only audit of the test suite, validation artifacts, and static-check posture of the
FYP repository ("Closing the Data Trust Gap in Agent Data Injection").

- Date: 2026-11-15
- Branch: `zain/experimental` (verified with `git branch --show-current`; no git state was changed)
- Working tree at start: clean (`git status --short` printed nothing)
- Repository root: `C:\DESKTOP STUFF\Programming and Uni Shit here\FAST NUCES University Work\Fourth Year\sem 7\FYP-I\Code`
- Shell: Windows PowerShell 5.1; all commands run from the repository root
- Only file created by this audit: `docs/project_audit/TESTING_AND_VALIDATION.md` (this file)

Finding labels used below: **Severity** (Critical / High / Medium / Low / Informational),
**Confidence** (Confirmed / Strongly supported / Hypothesis), **Type** (testing gap /
implementation defect / reliability issue).

---

## 1. Environment

```
PS> .\.venv\Scripts\python.exe --version
Python 3.12.10

PS> .\.venv\Scripts\python.exe -m pytest --version
pytest 9.1.1
```

No plugins were listed by `pytest --version` (pytest only lists registered plugins; none are
installed).

Key packages from `.\.venv\Scripts\pip.exe list` (full list has 88 entries):

| Package | Version | Relevance |
|---|---|---|
| pytest | 9.1.1 | test runner |
| agentdojo | 0.1.35 | pip copy of the benchmark framework (a vendored copy also lives in `agentdojo/src`) |
| scikit-learn | 1.9.1 | `LinearSVC` + calibration in `classifier/wl_svm.py` |
| scipy | 1.18.1 | sklearn dependency |
| numpy | 2.5.4 | sklearn dependency |
| pydantic | 2.13.5 | parser models, schema validation |
| joblib | 1.6.0 | model save/load |
| openai 3.22.1, anthropic 1.9.0, google-genai 2.25.0, cohere 7.2.0 | installed | live-LLM clients; not exercised by this audit |
| langchain 1.4.3, langgraph 1.2.12 | installed | used by `agents/` baselines |

**Not installed** (checked by inspecting `pip list`; nothing was installed): `coverage`,
`pytest-cov`, `mypy`, `ruff`, `flake8`, `pylint`. Consequently the coverage pass and the linter /
type-check passes requested in the audit brief were **skipped**. The coverage numbers in this
report are therefore derived from reading the tests, not from instrumentation.

### Which `agentdojo` is imported

```
PS> $env:PYTHONPATH="src;agentdojo\src"; .\.venv\Scripts\python.exe -c "import agentdojo; print(agentdojo.__file__)"
...\Code\agentdojo\src\agentdojo\__init__.py            (vendored copy -- this is what pytest uses via pytest.ini pythonpath)

PS> .\.venv\Scripts\python.exe -c "import agentdojo; print(agentdojo.__file__)"
...\Code\.venv\Lib\site-packages\agentdojo\__init__.py (pip copy -- this is what any script run WITHOUT pytest.ini uses)
```

Under pytest the vendored copy wins because `pytest.ini` puts `agentdojo/src` on `pythonpath`.
Scripts (`scripts/live_clone_parser_smoke.py`, `python -m classifier.train`, `adi_eval.py`)
resolve the pip copy unless the caller sets `PYTHONPATH` manually. This is the known dual-copy
issue; `docs/tagging-design.md` section 11.2 documents it. No test file imports the two copies
inconsistently *within the suite* (every test resolves the vendored copy), but the suite and
the scripts do not agree with each other. See finding F-09.

---

## 2. Test suite run

### 2.1 Full suite (configured testpaths)

```
PS> .\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q
........................................................................ [ 23%]
........................................................................ [ 46%]
........................................................................ [ 69%]
...F.................................................................... [ 92%]
......................                                                   [100%]
================================== FAILURES ===================================
____________________ test_parser_conforms_to_design[E003] _____________________

c = {'case_id': 'E003', 'set': 'edge', 'family': 'malformed', 'source': 'handwritten', ...}

    @pytest.mark.parametrize("c", CASES, ids=lambda c: c["case_id"])
    def test_parser_conforms_to_design(c):
        r = evaluate(c)
>       assert r["status"] == c["expected_status"]
E       AssertionError: assert 'not_json' == 'invalid_json'
E
E         - invalid_json
E         + not_json

tests\unit\test_phase1_cases.py:58: AssertionError
=========================== short test summary info ===========================
FAILED tests/unit/test_phase1_cases.py::test_parser_conforms_to_design[E003]
1 failed, 309 passed in 42.15s
```

Wall-clock including interpreter start-up (measured with `[Diagnostics.Stopwatch]`): 48.42 s.
Pytest-reported runtime: 42.15 s. **No warnings** were reported in the summary line.
Skips: 0. XFail: 0.

This matches the baseline given in the brief (309 passed, 1 failed) exactly. The E003 failure
is **pre-existing** and was not touched.

**E003 analysis** (from `tests/fixtures/phase1/phase1_cases.jsonl`): the payload is the plain
string `"Welcome to Zurich Restaurant. Opening hours 9-17."`, `family = malformed`,
`expected_status = "invalid_json"`, `parser_expect = {flagged: false, basis: "spec", rationale:
"plain-text webpage response (like slack get_webpage)"}`. `parser.models.ParseStatus` has both
`NOT_JSON = "not_json"` and `INVALID_JSON = "invalid_json"`. The parser classifies free prose as
`not_json`; the fixture author wrote `invalid_json`. The `flagged` assertion on line 59 is never
reached. This is a **fixture-vs-parser status taxonomy disagreement**, not a detection
regression: the test is checking the parser against its *design*, and the design expectation
in the fixture appears to be the wrong one of two valid enum members for prose. Whether the fix
belongs in the fixture or in the parser is a product decision; the audit records it only.

- **F-01** E003 conformance failure. Severity: Low. Confidence: Confirmed. Type: implementation
  defect (fixture/enum mismatch). Pre-existing; out of scope to fix.

### 2.2 Collection inventory

```
PS> .\.venv\Scripts\python.exe -m pytest -p no:cacheprovider --collect-only -q
...
310 tests collected in 17.28s
```

Collection alone takes 17 s because `tests/unit/test_phase1_cases.py` loads and evaluates the
100-case fixture at import time (`CASES = load_cases()` at module level) and `src/clone/test_static.py`
imports the vendored `agentdojo` package.

Collected tests per file:

| File | Tests | Notes |
|---|---|---|
| `tests/unit/test_phase1_cases.py` | 238 | 100 x schema, 100 x parser conformance, 20 x planted-attack location, 3 dataset-integrity, 1 oversize |
| `src/clone/test_static.py` | 45 | Clone executor / ledger / matrix / adapter behaviour; 1657 lines |
| `src/pipeline/test_classifier_risk_evaluation.py` | 14 | WL-SVM, risk gate, review resolution, evidence panel, metrics, tagging (legacy API), composed risk detector |
| `src/clone/test_core.py` | 7 | `InterceptionCore` hold/release/block, detector context immutability, import isolation |
| `src/pipeline/test_clone_parser_detector.py` | 6 | Clone -> parser bridge, schema violations, ledger persistence |
| **Total** | **310** | |

### 2.3 Test files that exist but are NOT collected

`pytest.ini`:

```
[pytest]
pythonpath = src agentdojo/src
testpaths = tests src/clone src/pipeline
```

`src/parser` is **not** in `testpaths`, yet it contains seven real pytest files (107 tests):

```
src/parser/test_dom.py           (4 tests)
src/parser/test_dom_layout.py    (8 tests)
src/parser/test_dom_linenum.py   (4 tests)
src/parser/test_md_flags.py      (6 tests)
src/parser/test_parser.py
src/parser/test_stage1.py
src/parser/test_structural.py
```

Run explicitly, they all pass:

```
PS> .\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q src\parser
........................................................................ [ 67%]
...................................                                      [100%]
107 passed in 1.61s
```

So the real passing test count for the repository is **416 passed, 1 failed**, but the default
command (and therefore any CI or reviewer running `pytest`) only exercises 310 of them. The
project's own `src/parser/README.md` line 46 still says `python -m pytest  # all tests`, and
`src/pipeline/README.md` line 172 / `src/clone/README.md` line 150 document
`python -m pytest -q --durations=5 src\parser` as a separate manual step, which suggests the
omission from `testpaths` is a configuration drift rather than a decision.

- **F-02** 107 parser tests silently excluded from the default run. Severity: **High**.
  Confidence: Confirmed. Type: testing gap / reliability issue. A regression in
  `parser/structural.py`, `dom_flag.py`, `md_flags.py` or `stage1.py` would only be caught
  indirectly through the 100 Phase-1 conformance cases.

### 2.4 Zero-byte placeholder tests and fixtures

```
PS> Get-ChildItem tests\unit\*.py | Select-Object Name,Length
test_classifier.py          0
test_parser.py              0
test_phase1_cases.py     2643
test_provenance.py          0

PS> Get-ChildItem tests\fixtures -Recurse -File | Select-Object Name,Length
classifier_cases.json       0
email_answer_key.jsonl   3529
email_cases.jsonl       22604
hard_benign.jsonl       17117
prehop_cases.jsonl      10077
phase1_cases.jsonl     114440
phase1_manifest.json      888
```

`tests/unit/test_classifier.py`, `tests/unit/test_parser.py`, `tests/unit/test_provenance.py`
and `tests/fixtures/classifier_cases.json` are **empty files tracked in git**
(`git ls-files tests/fixtures` lists `classifier_cases.json`). They collect zero tests and
give a false impression of coverage in a directory listing. `docs/tagging-design.md` section 10
names `tests/unit/test_tagging.py` (step 1.2) and `tests/unit/test_provenance.py` (step 1.3) as
the planned homes for tagging and lineage tests; `test_tagging.py` does not exist and
`test_provenance.py` is empty.

- **F-03** Placeholder test files with no content. Severity: Medium. Confidence: Confirmed.
  Type: testing gap.

---

## 3. Coverage map by pipeline stage

Coverage tooling is not installed, so this map is built from reading every test file against
the module list. "Behaviours asserted" is what the tests actually check; "Design says" is taken
from the module docstrings, `src/*/README.md`, `docs/tagging-design.md` and the proposal
summary in `docs/project_audit/PROJECT_UNDERSTANDING.md`.

### 3.1 Clone (interception layer) -- `src/clone/`

| Module | Lines | Tests | Assessment |
|---|---|---|---|
| `core.py` | 377 | `test_core.py` (7), `test_static.py` (many) | Good: hold/release, block + denial record, off mode, detector receives deep copy, frozen context, legacy 1-arg detector, lazy import isolation |
| `ledger.py` | 360 | `test_static.py`, `test_clone_parser_detector.py::test_ledger_persists...` | Good: capture/transition, export, persistence to `tmp_path`, 5000-record index test |
| `tvm.py` | 84 | `test_static.py` (matrix load, entries) | Adequate |
| `adapters/agentdojo.py` | 153 | `test_static.py` (executor query, passthrough/enforce, tool errors, timeout, run metadata) | Good, but bound to the vendored AgentDojo API |
| `interceptor.py` | 20 | re-export shim, `test_static.py::...shim_framework_args` | Adequate |

Behaviours asserted include fail-closed on detector timeout (`test_detector_timeout_fails_closed`),
denial text delivered to the agent, raw payload never mutated by detector, and import safety
when `agentdojo` is absent (two subprocess tests). This is the best-tested stage.

Quality concerns in `test_static.py`:

- `test_clone_import_and_workload_diagnostics` and
  `test_ledger_indexes_scale_to_5000_records_and_keep_exports_unchanged` measure wall-clock with
  `perf_counter()` and `print()` the timings. They do **not** assert on the timings, so they are
  not flaky, but they are diagnostics dressed as tests (no performance regression would fail
  them). Informational.
- `test_detector_timeout_fails_closed` relies on `sleep(0.05)` vs `detector_timeout_s=0.001`.
  The 50x margin is comfortable; low flake risk. Low.
- Three tests spawn `subprocess.run([sys.executable, ...])` with a hand-built `PYTHONPATH`
  (`test_static.py:203-285`, `test_core.py:155-175`). They depend on the parent `PYTHONPATH`
  environment and on `cwd=src_dir`; this is the only place where a different `agentdojo` copy
  could sneak in (if the user's shell `PYTHONPATH` already points at site-packages first). They
  passed in this environment. Low.

- **F-04** Timing/diagnostic tests with no assertion on the measured quantity. Severity:
  Informational. Confidence: Confirmed. Type: testing gap (weak assertion).

### 3.2 Parser (Stage 1 structural parsing) -- `src/parser/`

| Module | Lines | Tests | Assessment |
|---|---|---|---|
| `parser.py` | 124 | `src/parser/test_parser.py` (not collected by default), Phase-1 conformance (100 cases) | Good when the parser tests are actually run |
| `structural.py` | 136 | `src/parser/test_structural.py` (19 paper delimiter variants, encoded/hidden delimiters), Phase-1 | Good |
| `stage1.py` | 89 | `src/parser/test_stage1.py` | Covered, not collected by default |
| `dom_flag.py` | 73 | `test_dom.py`, `test_dom_layout.py`, `test_dom_linenum.py` | Covered, not collected by default |
| `md_flags.py` | 72 | `test_md_flags.py` | Covered, not collected by default |
| `models.py` | 101 | indirectly everywhere | Adequate |
| `schema_registry.py` | 33 | indirectly via `test_clone_parser_detector.py` schema tests | Thin |
| `adi_eval.py` (236), `eval.py` (78), `agentdojo_offline.py` (61), `make_extra_cases.py` (108), `demo.py` (22) | -- | **none** | Evaluation / fixture-generation scripts; no tests. `adi_eval.py` is the tool that produces the "0 false positives on benign sets" claim in `src/parser/README.md` and is untested itself |

The Phase-1 conformance test (`test_parser_conforms_to_design`) is a strong design-level
regression net: it asserts `status` and `flagged` for 100 cases whose expectations were written
from the spec, not copied from parser output (per `scripts/build_phase1_cases.py` docstring).
However it only asserts the *boolean* `flagged`, not **which paths** were flagged, even though
every case carries `expected_untrusted_paths`. The planted-attack location test
(`test_planted_attack_really_in_untrusted_field`) only asserts the list is non-empty. The
detection metrics (TPR/FPR) are deliberately *reported, not asserted*
(`scripts/run_phase1_cases.py`), so a detection regression that preserves design conformance
would not fail CI.

- **F-05** Phase-1 conformance ignores `expected_untrusted_paths`; path-level correctness is
  not asserted anywhere. Severity: Medium. Confidence: Confirmed. Type: testing gap.

### 3.3 Structural policy / detectors -- `src/detector/`, `src/provenance/`

```
PS> Get-ChildItem src\detector -Force      -> (empty directory)
PS> Get-ChildItem src\provenance -Force    -> __init__.py (0 bytes)
```

Both packages are empty. There is nothing to test and nothing tested. The `README.md` /
proposal position these as the home of the structural-policy and lineage layers; today that
logic is split between `parser/structural.py` and `pipeline/parser_analysis.py`.
`pipeline/parser_analysis.py` (54 lines, `analyze_clone_payload`) has **no direct test**; it is
exercised only transitively through `parser_detector` and `make_risk_detector`.

- **F-06** `src/detector` and `src/provenance` are empty packages; lineage/provenance logic
  (design doc section 4) has no implementation and no tests. Severity: High (for the project's
  stated contribution; the lineage layer *is* the "trust-provenance" in the title).
  Confidence: Confirmed. Type: testing gap (and unimplemented scope).

### 3.4 Tagging -- `src/trust_graph/tagging.py` (228 lines, rewritten in step 1.2)

Design (`docs/tagging-design.md` sections 2-3, 10) requires: provenance enum (SYSTEM / USER /
EXTERNAL / DERIVED / UNKNOWN), trust *computed* from provenance (`trust_for`), role assignment
per the 3.1 table, containment (nested fields inside EXTERNAL are EXTERNAL), no-profile and
draft-profile cases all `UNKNOWN`, text-format result as a single `$` field, path-pattern
matching with duplicate-key suffix stripping, misuse raises `ValueError`, and an injectable
clock for `created_at`.

What is tested today: **one** test,
`test_classifier_risk_evaluation.py::test_tagging_defaults_unknown_classes_to_untrusted_and_graph_preserves_paths`,
which calls `tag_fields(parsed, {"account": "trusted"})` -- the **deprecated two-argument
legacy path** (`tagging.py:152-153 -> _legacy_tag_fields`). None of the new API
(`tag_fields("pre"/"post", tool_name, fields, profile_entry, run_state, ...)`, `ProfileEntry`,
`trust_for`, `normalise`, `Evidence`, `LineageStatus`, `Role`, `_tag_result`, `_tag_arguments`,
`_explicit_provenance`, `_compile_pattern`, `_strip_duplicate_suffix`, the four `ValueError`
misuse guards) has any test. `pipeline/risk_detector.py:46` also still calls the legacy
signature, so the new code path is **unreachable from the pipeline and from the suite**.

Reliability notes for future tests: `_TagFactory.__call__` uses `uuid.uuid4()` for `tag_id` and
`self.clock()` (default `time.time`) for `created_at`. The clock is injectable (good), the UUID
is not; any future snapshot/equality test must exclude `tag_id`.

- **F-07** Freshly rewritten tagging stage has zero tests on the new API and is not wired into
  the pipeline. Severity: **High**. Confidence: Confirmed. Type: testing gap. (Acknowledged by
  the team as a known gap; recorded here for completeness with the exact uncovered surface.)

### 3.5 Trust graph -- `src/trust_graph/graph.py` (24 lines)

`build_trust_graph` is covered by the single tagging test above (asserts one edge
`("$.account", "$.account.id")` exists). Node labelling (`T:`/`UT:` prefix + value type), edge
completeness for deeper trees, and behaviour on empty/plain-text results are not asserted.

- **F-08** Trust graph construction has one weak assertion. Severity: Medium. Confidence:
  Confirmed. Type: testing gap.

### 3.6 Classifier -- `src/classifier/`

| Module | Tests | Assessment |
|---|---|---|
| `wl_svm.py` (133) | `test_wl_features_are_stable_and_include_neighbor_structure`, `test_wl_svm_fits_and_returns_calibrated_attack_probability` | Determinism of WL features and separability on a 12-graph toy set. `save()` / `load()` **untested**. Calibration quality untested (only `0 <= p <= 1` and ordering) |
| `train.py` (52) | **none** | `load_training_jsonl` validation (duplicate ids, bad labels, malformed rows) untested; `main()` untested |

The toy fit uses two graph *shapes* repeated 6 times each; the model is effectively learning
one feature. This verifies the plumbing, not the method. There is **no training corpus**
(`graphs.jsonl`) and **no trained artifact** (`.joblib`) anywhere in the repository, so the
classifier has never been evaluated on real graphs. `tests/fixtures/classifier_cases.json` is
0 bytes. The WL-kernel + SVM claim in the proposal is therefore **not validated** by any
committed test or artifact.

- **F-10** Classifier never trained or evaluated on project data; `save/load` and
  `train.py` untested. Severity: **High**. Confidence: Confirmed. Type: testing gap.

### 3.7 Risk gate and review -- `src/pipeline/`

| Module | Tests | Assessment |
|---|---|---|
| `risk_gate.py` (97) | 5 tests: tier thresholds, `allow` removed at high risk, density is evidence not probability, structural hit forces review, missing classifier forces review, pre/post review resolution | Good behavioural coverage of the stated policy |
| `classifier_gate.py` (26) | indirect via `make_risk_detector` | Adequate |
| `risk_detector.py` (100) | 3 tests: reviewer called with evidence, fail-closed without reviewer, structural findings propagate | Good |
| `evidence_panel.py` (61) | 1 test: deterministic render, two substrings present | Weak: does not check that **raw untrusted content is withheld** from the panel in evidence-only mode, which is the panel's security property |
| `evaluation.py` (86) | 2 tests: metric arithmetic on 4 synthetic cases, missing-label error | Adequate for arithmetic; no test with a realistic case file |
| `clone_parser_detector.py` (43) | 6 tests | Good |
| `parser_analysis.py` (54) | **none direct** | Transitive only |

Note that `test_risk_thresholds_match_proposal_and_remove_allow_at_high_risk` asserts specific
numbers (`risk_score == 5.0`, tiers for 0.2/0.5) that encode the proposal's thresholds. This is
the right kind of test (behaviour pinned to the design), but there is only one data point per
tier; boundary values (exactly at a threshold) are untested.

- **F-11** Evidence panel's non-leakage property untested; threshold boundaries untested.
  Severity: Medium. Confidence: Confirmed. Type: testing gap.

### 3.8 End-to-end

There is **no automated end-to-end test** that runs clone -> parser -> tagging -> graph ->
classifier -> risk gate -> review on a real AgentDojo task. The only end-to-end path is
`scripts/live_clone_parser_smoke.py`, which requires `GROQ_API_KEY`, calls model
`openai/gpt-oss-120b` via Groq, and writes to `runs/live_clone_parser_smoke/<timestamp>/`.
It was **not run** (live model call; non-deterministic; writes into the repo tree). The closest
offline integration test is `test_parser_detector_scores_pre_and_post_payloads_in_core`
(clone + parser only) and `test_composed_risk_detector_*` (parser-analysis + fixed classifier
stub + risk gate + reviewer stub). The classifier in those tests is `_FixedClassifier` returning
a constant 0.2, so no test ever drives a *trained* model through the gate.

- **F-12** No offline end-to-end test of the full pipeline; the only full-path script needs a
  live LLM. Severity: **High**. Confidence: Confirmed. Type: testing gap.

### 3.9 `agents/` (baseline defences: CaMeL, IsolateGPT, LlamaFirewall, Progent, PromptGuard)

~60 Python files, all third-party or adapted baselines that call LLM providers through
LangChain / LangGraph. No tests, not in `testpaths`, and untestable offline. Informational;
these are comparison baselines, not project code under test.

### 3.10 Implementation-detail vs behaviour tests

Most tests assert externally observable behaviour (allowed / denied, ledger state, tiers). The
following lean on internals:

- `test_core.py::test_executor_export_is_loaded_lazily` and
  `test_static.py::test_clone_import_is_safe_without_agentdojo_in_fresh_processes` assert on
  `sys.modules` contents -- legitimate here because lazy import *is* the requirement.
- `test_classifier_risk_evaluation.py::test_wl_features_are_stable...` asserts a feature key
  prefix `"wl:2:"`, coupling the test to the feature-naming scheme. Low.
- `test_clone_parser_detector.py::test_parser_bridge_uses_parser_structural_score_for_each_direction`
  asserts `decision.score == report.structural_score` by recomputing the same function -- a
  tautology that would pass even if `structural_score` were wrong. Low.

### 3.11 Flaky-prone patterns found

| Pattern | Where | Risk |
|---|---|---|
| `uuid4()` | `test_classifier_risk_evaluation.py:145` (only as an input id), `ledger.py:145`, `adapters/agentdojo.py:71`, `models.py:44`, `tagging.py:265` | None today; tests never compare ids |
| `time.time` / `perf_counter` | `tagging.py:141` (injectable), `test_static.py` diagnostics | None today (not asserted) |
| `sleep` vs timeout | `test_static.py:1445` | Low (50x margin) |
| `subprocess` + env `PYTHONPATH` | `test_static.py:203-285`, `test_core.py:155-175` | Low; environment-dependent |
| `datetime.now()` | `scripts/build_phase1_cases.py` (fixture builder, forces `PYTHONHASHSEED=0` and strips timestamps) | Handled by the builder |
| Network | none in tests | -- |
| Dict ordering | `wl_features` sorts; `EvidencePanel.render` asserted deterministic | Handled |

No test depends on wall-clock, randomness, or the network. `WLGraphSVM` takes
`random_state=0`. The suite ran deterministically twice (310 collected both times).

---

## 4. Coverage tooling

Skipped. Neither `coverage` nor `pytest-cov` is present in `.venv` (verified via `pip list`);
nothing was installed per the audit rules. A rough file-level view from reading:

- Fully or well exercised: `clone/*`, `pipeline/risk_gate.py`, `pipeline/risk_detector.py`,
  `pipeline/clone_parser_detector.py`, `parser/parser.py`, `parser/structural.py`,
  `parser/stage1.py`, `parser/dom_flag.py`, `parser/md_flags.py` (the last four only when
  `src/parser` is passed explicitly).
- Partially exercised: `classifier/wl_svm.py` (no `save`/`load`), `pipeline/evidence_panel.py`,
  `pipeline/evaluation.py`, `trust_graph/graph.py`, `parser/schema_registry.py`.
- Exercised only via deprecated path: `trust_graph/tagging.py` (`_legacy_tag_fields` and
  `_root_key` only).
- Not exercised at all: `classifier/train.py`, `pipeline/parser_analysis.py` (direct),
  `parser/adi_eval.py`, `parser/eval.py`, `parser/agentdojo_offline.py`,
  `parser/make_extra_cases.py`, `parser/demo.py`, all of `scripts/`, all of `agents/`,
  all of `llm-benchmark/`.

---

## 5. What cannot currently be tested (and why)

| Item | Why untestable today | Status in this audit |
|---|---|---|
| `scripts/live_clone_parser_smoke.py` | Needs `GROQ_API_KEY`; live model `openai/gpt-oss-120b`; writes `runs/` under the repo | Not run; unverifiable |
| `agents/*` baselines | Live OpenAI / Anthropic / HF calls via LangChain | Not run; unverifiable |
| `llm-benchmark` `dib run` | Paid model APIs (`src/parser/README.md` line 60 explicitly warns "Do not use dib run") | Not run; unverifiable |
| `llm-benchmark` `dib generate` | Deterministic, but requires `uv` and the separate `llm-benchmark/.venv`; writes `out/generated/` | Not run (would write into repo) |
| `classifier/train.py` | No `graphs.jsonl` exists; `python -m classifier.train` has nothing to train on | No entry data; untested |
| `pipeline/evaluation.py` CLI | README documents `python -m pipeline.evaluation .\evaluation_cases.jsonl`; no such file exists | No entry data |
| New tagging API (`tag_fields("pre"/"post", ...)`) | Testable offline, but no caller exists in the pipeline (`risk_detector.py:46` uses the legacy signature) and no `ProfileEntry` fixtures exist | Testable; currently untested |
| Lineage / RunState (design section 4) | Not implemented (`src/provenance` empty) | Nothing to test |
| `scripts/build_phase1_cases.py` | Deterministic and offline, but **rewrites** `tests/fixtures/phase1/*` and re-executes itself with `PYTHONHASHSEED=0` | Not run (would modify tracked fixtures) |
| `scripts/pdi_build_cases.py` | Needs `llm-benchmark/out/generated/*.jsonl` (not committed); writes fixtures | Not run |
| `scripts/run_phase1_cases.py` | Offline and deterministic, but writes `experiments/results/phase1_run.json` (git-ignored) and shells out to `git` | Not run to avoid writing into the repo; its `evaluate()` is exercised by the pytest conformance test instead |

---

## 6. Benchmarks, experiments and validation artifacts

### 6.1 Inventory

- `benchmarks/` -- **empty directory**.
- `experiments/results/phase1_run.json` -- 52.9 KB, **git-ignored** (`.gitignore:57 results/`),
  present only on this machine. Header:
  ```
  "dataset_version": "phase1-v1", "parser_rev": "cb0376f", "agentdojo_package": "0.1.35",
  "python": "3.12.10",
  "summary": {"n": 100, "TP": 20, "FN": 26, "FP": 2, "TN": 52, "TPR": 0.435, "FPR": 0.037}
  ```
  `parser_rev cb0376f` is **not** the current HEAD (`66fec89`), so this result file is stale
  relative to the committed parser. The 43.5% TPR / 3.7% FPR is Stage-1-alone structural
  detection on the fixed 100-case set; the script's own docstring states it "is not an Attack
  Success Rate".
- `tests/fixtures/phase1/phase1_cases.jsonl` + `phase1_manifest.json` -- committed, 100 cases,
  40/40/20, built deterministically by `scripts/build_phase1_cases.py` from vendored AgentDojo
  v1.2.1 ground-truth replays (no LLM). **Reproducible from committed code** in principle; not
  re-run here because it overwrites the fixture.
- `tests/fixtures/cases/{email_cases,email_answer_key,prehop_cases,hard_benign}.jsonl` --
  committed; consumed by `src/parser/adi_eval.py` (manual evaluation script, not pytest). The
  answer key is kept separate from the cases by design. `email_cases.jsonl` derives from
  `llm-benchmark` generated instances via `scripts/pdi_build_cases.py`; the generated input is
  **not committed**, so the email cases are reproducible only if `dib generate` is re-run with
  the same seeds/config, which is documented in `src/parser/README.md` lines 57-58.
- `llm-benchmark/` -- a separate `uv` project with its own `pyproject.toml`, `uv.lock`, seeds,
  configs and a 126 KB `cli.py`. It has **no test directory** of its own. Its README's
  "Repository Layout" lists files that do not exist (`formats.yaml`, `tasks/*.yaml`,
  `html_parser.py`, `markdown_parser.py`, `csv_parser.py`, `text_parser.py`, `slack/`,
  `web_html/`, `web_search/` seeds) -- the README is ahead of or behind the code.
- `scripts/__pycache__/run_phase1_cases.cpython-312.pyc` -- present on disk, git-ignored
  (`.gitignore:16`), created by the pytest import of `run_phase1_cases`. It pre-dates this audit
  and this audit's `compileall` used `PYTHONPYCACHEPREFIX` so nothing new was written.

### 6.2 Are the commands documented?

Yes, partially, and spread across five READMEs with some drift:

- Root `README.md` line 43 runs the clone tests with
  `.\llm-benchmark\.venv\Scripts\python.exe` -- a **different venv** from the one `pytest.ini`
  and the brief assume (`.\.venv`). Lines 396-457 document `uv run dib --help` and
  `agentdojo.scripts.benchmark` invocations.
- `src/parser/README.md` line 46 says `python -m pytest  # all tests`, line 113 claims
  "106 passed" for the parser unit tests (now 107), lines 57-60 document `dib generate`.
- `src/pipeline/README.md` lines 156-157 document `python -m classifier.train .\graphs.jsonl
  .\wl_svm.joblib` and `python -m pipeline.evaluation .\evaluation_cases.jsonl`, but neither
  input file exists in the repo.
- `src/clone/README.md` and `src/pipeline/README.md` lines 171-173 document three separate
  pytest invocations rather than one.
- `scripts/run_phase1_cases.py` and `scripts/build_phase1_cases.py` carry correct usage in
  their docstrings.

- **F-13** Validation artifacts are not reproducible end-to-end from committed state: the only
  results file is git-ignored and stale (`cb0376f` vs HEAD `66fec89`); classifier training
  data and evaluation case files referenced by READMEs do not exist; `benchmarks/` is empty.
  Severity: **High**. Confidence: Confirmed. Type: reliability issue / testing gap.
- **F-14** README drift (wrong venv path, `pytest` "all tests" claim, phantom files in
  `llm-benchmark/README.md`). Severity: Low. Confidence: Confirmed. Type: reliability issue.
- **F-09** (from section 1) Pip vs vendored `agentdojo` resolve differently under pytest vs
  scripts. Severity: Medium. Confidence: Confirmed. Type: reliability issue. Both are 0.1.35
  today so behaviour currently matches, but there is no test guarding that.

---

## 7. Static checks

### 7.1 Byte-compilation (safe; nothing written into the repo)

```
PS> $env:PYTHONPYCACHEPREFIX="$env:TEMP\pycache_audit"
PS> .\.venv\Scripts\python.exe -m compileall -q src scripts tests benchmarks experiments llm-benchmark
PS> "EXIT: $LASTEXITCODE"
EXIT: 0
```

All Python files under `src`, `scripts`, `tests`, `benchmarks`, `experiments` and
`llm-benchmark` compile without syntax errors. `.pyc` output went to
`%TEMP%\pycache_audit`, outside the repository. `agents/` and `agentdojo/` were deliberately
excluded (third-party code, large).

### 7.2 Linters / type checkers

`mypy`, `ruff`, `flake8`, `pylint` are **not installed** in `.venv`; skipped per the no-install
rule. The code base carries `# type: ignore[arg-type]` (`tagging.py:153`) and `# noqa: E402` /
`# noqa: E731` markers, indicating linters were used at some point on some machine, but there is
no `pyproject.toml`, `setup.cfg`, `mypy.ini` or `ruff.toml` at the repo root to pin their
configuration, and no CI workflow directory (`.github/`) exists.

- **F-15** No linter/type-checker configuration or CI in the repository; static quality relies
  on individual developers' editors. Severity: Low. Confidence: Confirmed. Type: testing gap.

---

## 8. Consolidated findings

| ID | Finding | Severity | Confidence | Type |
|---|---|---|---|---|
| F-02 | 107 passing parser tests excluded from default `pytest` run (`testpaths` omits `src/parser`) | High | Confirmed | testing gap / reliability |
| F-06 | `src/detector` and `src/provenance` empty; lineage layer unimplemented and untested | High | Confirmed | testing gap |
| F-07 | Rewritten tagging API has zero tests and no pipeline caller; only legacy path exercised | High | Confirmed | testing gap |
| F-10 | WL-SVM never trained or evaluated on project data; `save/load`, `train.py` untested; 0-byte `classifier_cases.json` | High | Confirmed | testing gap |
| F-12 | No offline end-to-end pipeline test; only full-path script needs a live LLM | High | Confirmed | testing gap |
| F-13 | Results file git-ignored and stale; training/eval inputs referenced by docs do not exist; `benchmarks/` empty | High | Confirmed | reliability / testing gap |
| F-03 | Three 0-byte test files and one 0-byte fixture tracked in git | Medium | Confirmed | testing gap |
| F-05 | Phase-1 conformance asserts boolean `flagged` only, never `expected_untrusted_paths` | Medium | Confirmed | testing gap |
| F-08 | Trust graph: single weak edge assertion | Medium | Confirmed | testing gap |
| F-09 | Pip vs vendored `agentdojo` resolve differently for pytest vs scripts; no guard test | Medium | Confirmed | reliability |
| F-11 | Evidence panel non-leakage untested; risk-tier boundaries untested | Medium | Confirmed | testing gap |
| F-01 | E003 fails: fixture expects `invalid_json`, parser returns `not_json` (pre-existing) | Low | Confirmed | implementation defect |
| F-14 | README drift (wrong venv, "all tests" claim, phantom files in llm-benchmark README) | Low | Confirmed | reliability |
| F-15 | No lint/type-check config or CI | Low | Confirmed | testing gap |
| F-04 | Timing diagnostics presented as tests, no assertion on timings | Informational | Confirmed | testing gap |

---

## 9. Limitations of this audit

- No instrumentation-based coverage: `coverage`/`pytest-cov` absent and not installable under
  the audit rules. Coverage statements are from reading tests against module surfaces.
- No linter or type-checker output for the same reason.
- No live-LLM paths were exercised (`live_clone_parser_smoke.py`, `agents/`, `dib run`), so
  the end-to-end behaviour of the enforce-mode executor against a real model is unverified.
- Fixture-generating scripts (`build_phase1_cases.py`, `pdi_build_cases.py`,
  `run_phase1_cases.py`, `dib generate`) were not executed because they write into the
  repository tree; their reproducibility claims are assessed from docstrings and the manifest,
  not re-derived.
- `src/clone/test_static.py` (1657 lines, 45 tests) was sampled, not read line by line; the
  behavioural summary for the clone stage is based on test names, the sections read
  (`200-370`, `1425-1456`, `1595-1656`), and the two smaller clone/pipeline test files read in
  full.
- The suite was run once in full (plus one `--collect-only` and one explicit `src\parser` run);
  flakiness was assessed by pattern inspection, not by repeated runs.
- `agents/` and `agentdojo/` were excluded from `compileall`.

---

## 10. Exact command log

All run from the repository root in Windows PowerShell 5.1 with the project venv.

```
git branch --show-current
git status --short
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pytest --version
.\.venv\Scripts\pip.exe list
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider --collect-only -q   (output saved to %TEMP%\collect.txt)
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q src\parser
$env:PYTHONPYCACHEPREFIX="$env:TEMP\pycache_audit"; .\.venv\Scripts\python.exe -m compileall -q src scripts tests benchmarks experiments llm-benchmark
$env:PYTHONPATH="src;agentdojo\src"; .\.venv\Scripts\python.exe -c "import agentdojo; print(agentdojo.__file__)"
.\.venv\Scripts\python.exe -c "import agentdojo; print(agentdojo.__file__)"
git check-ignore -v scripts\__pycache__\run_phase1_cases.cpython-312.pyc .pytest_cache experiments\results\phase1_run.json
git ls-files experiments scripts benchmarks tests/fixtures
git status --short   (at the end; see final summary)
```

Read-only inspection used `Get-ChildItem`, `Get-Content`, `Select-String`, and the editor's
file reader. No file in the repository other than this report was created, modified, deleted
or renamed.
