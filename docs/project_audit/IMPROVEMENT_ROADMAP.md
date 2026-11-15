# Improvement Roadmap

Derived from the Phase 1 audit (`MASTER_AUDIT_REPORT.md`) with severities as corrected by `CRITICAL_REVIEW.md`. Date 2026-11-15, branch `zain/experimental`, HEAD `66fec89`.

**Nothing here has been implemented.** Every item is a proposal. Items marked **[decision]** need a researcher decision first (see `DECISIONS_REQUIRED.md`); items marked **[approve]** are confirmed defects with an obvious fix that still need the team's go-ahead because the audit was read-only. Effort is a rough size: S (< 1 h), M (half a day), L (days), XL (a phase).

Finding ids refer to `MASTER_AUDIT_REPORT.md` §3 (M/S/I/A/T/P) and to the specialist reports (SP = structural, IA = implementation, AA = architecture, TV = testing, PS = perf/security, RC = research critique, CR = critical review).

Recommended execution order: **§1 → §2 (measurement items) → §3.1–3.3 → §2 (policy items, now informed by data) → §4 → §5 → §6 → §7.**

---

## 1. Immediate confirmed fixes (no research decision needed)

| Id | Change | Why / evidence | Severity | Effort | Depends on | Gate |
|---|---|---|---|---|---|---|
| R1.1 | Make the JSON formatter the adapter's own default in `src/clone/adapters/agentdojo.py:34-37` instead of inheriting `tool_result_to_str`; handle `dict` results explicitly (the pip copy has no dict branch even with `dump_fn=json.dumps`). Record `agentdojo.__file__` in run outputs. | I1 (CR row 25). Under the pip copy every structured result is `invalid_json`/`not_json` → blocked. | High | S–M | — | [approve]; Phase-2 rule allows additive clone changes only when all clone tests pass |
| R1.2 | Add `src/parser` to `pytest.ini` `testpaths` (or move the tests under `tests/unit/`); fix flat-layout imports they rely on. | T1. 107 passing tests invisible to the default run. | Medium | S | — | [approve] |
| R1.3 | Delete or populate the 0-byte files `tests/unit/test_parser.py`, `test_classifier.py`, `test_provenance.py`, `tests/fixtures/classifier_cases.json`. | T2. False sense of coverage. | Medium | S | R6.1 for content | [approve] |
| R1.4 | Surrogate-safe hashing in `ledger._payload_hash` (`errors="surrogatepass"` or `backslashreplace`); route `capture()` exceptions into a fail-closed decision rather than an unhandled exception. | I9 (PS S1). Payload-controlled crash of the executor. | Medium | S | — | [approve] |
| R1.5 | `graph.py:24-26`: strip only a trailing `#key` (`removesuffix`) and keep `#n` duplicate suffixes as part of the path. Add a test with `{"to":"a","to":"b"}`. | I6. Findings mis-attached / isolated. | Medium | S | — | [approve] |
| R1.6 | `structural.py:124`: iterate payload keys in order and filter, instead of set difference. | I8. Hash-seed-dependent finding order leaks into ledger/evidence. | Medium | S | — | [approve] |
| R1.7 | Fix nested `extra="forbid"` handling: map all pydantic `extra_forbidden` errors via `_loc_to_path` (remove the dead `except ValidationError` at `:104-110`). | I2. Nested forged keys invisible to the schema detector when nested models forbid extras. | Medium | S | — | [approve] |
| R1.8 | Cap `findings` alongside `MAX_FIELDS`; add a byte budget to `_scan_string`'s speculative `json.loads`. | P3. 100k `Finding` objects from a 900 KB payload; 85% of the 2 s budget. | Medium | S | — | [approve] |
| R1.9 | Rewrite `dom_flag._OK_PREFIX` with a single whitespace class / no adjacent `\s*` quantifiers; add a regression test with a 2000-space prefix under a time bound; run a ReDoS check over all `_COUNTED`/`_WEAK`/dom/md patterns. | P4. Cubic backtracking; High the day DOM is wired. | Medium | S | — | [approve] |
| R1.10 | Add `\b` after `true|false|null` in `kv_forgery`; exclude `<scheme:` / `<local@` autolinks in `dom_flags`; reset the markdown numbering counter after a heading / on `1.` reappearing. | I12. Reproduced benign FPs. | Low–Medium | S | — | [approve] |
| R1.11 | Resolve E003: either the fixture's `expected_status` or the parser's taxonomy for plain prose. | T8. Known failing test. | Low | S | [decision] D-14 | [decision] |
| R1.12 | Remove the unused `ParseStatus` import in `clone_parser_detector.py`; drop the duplicate `except ImportError` bodies in `adi_eval.py`. | IA §4. Hygiene. | Informational | S | — | [approve] |
| R1.13 | Fix README drift: root README venv path; "pytest runs all tests"; `src/pipeline/README.md` prose-allowed contradiction (`:89` vs `:178`); phantom files in `llm-benchmark/README.md`. | T6, SP D12. | Low | S | R1.2 | [approve] |

## 2. Structural policy and scoring improvements

Measurement first (R2.1–R2.3 need no policy decision and will change how the rest is judged), then representation, then policy.

| Id | Change | Why / evidence | Severity | Effort | Depends on | Gate |
|---|---|---|---|---|---|---|
| R2.1 | **LLM-free denial-rate measurement**: replay AgentDojo ground-truth calls (as `scripts/build_phase1_cases.py` already does) through `TrustVerificationToolsExecutor` in enforce mode with the parser-only detector; report benign denials **by reason** (`parser-untrusted` split into None-return / `Key: value` / dict-repr / other, `schema-violation`, `adi-detected`, `unclassified`) per suite. | S10, I3, I4, CR §(d) "feasible intermediate". No report measured this; it decides whether the fail-closed cost is real. | High (value) | M | R1.1 | [approve] (new script under `scripts/`, writes outside tracked fixtures) |
| R2.2 | **Define `flagged`** in `evaluation.py` docs and code: per call vs per task; detector verdict vs classifier label vs policy block; how review-tier denials without a reviewer are labelled. Make `contains_adi` consistent with the decision or rename it. | S7. FPR/FNR currently undefined. | Medium | S–M | [decision] D-6 | [decision] |
| R2.3 | **Denial-reason breakdown in metrics**: add a `denial_reason` column to `EvaluationCase`; report ASR alongside the share attributable to detection vs accidental reasons. | S10, §5 of master report. The single best control against artificial ASR improvement. | High (value) | M | R2.2 | [approve] |
| R2.4 | **Redefine S** as per-field max over deduplicated evidence (collapse the 4 correlated delimiter regexes into one event per field; `embedded_json` separate), with `n_forged_fields` as a secondary feature. Keep `hits > 0` as the decision rule for now. | S2 (SP 10.1). Dilution and over-counting; must precede any reporting of S. | Medium | M | — | [approve]; changes `StructuralReport` semantics (shared model) |
| R2.5 | Per-rule reliability weights from benign firing rates (Wilson intervals) on the Phase-1/Phase-2 benign corpora; grouped correlated rules; `embedded_json` low, `duplicate_key` high. Threshold tuned to a stated target FPR. | S4 (SP 10.2). Evidence quality currently ignored. | Medium | M–L | R2.4, benign corpus, [decision] D-7 (target FPR), D-9 (`embedded_json`) | [decision] |
| R2.6 | **Explicit indeterminate outcome** in `DetectorDecision` / `RiskAssessment` / `EvaluationCase` (`unknown` beside allow/review/deny) with its *rate* reported as coverage. Policy for what `unknown` does per impact class is a decision; **do not default it to allow for read tools** (they carry injections; CR §(d)). | S3 (SP W2, 12.3; Phase-2 S2). | High | M | [decision] D-2 | [decision] |
| R2.7 | **Tier-1 / read-tool gating**: decide whether read tools (all 44 tier-1) should be reviewable by the classifier at all. If yes, replace `p × impact ≥ 1` with per-impact thresholds `t[impact]` where `t[1] < 1`; **note** that with no reviewer this routes every read result to deny and collapses utility — only viable with a reviewer stub or an `unknown` policy (R2.6). | S1 (SP D1, 11.3.2; CR row 1, §(d)). | High | S (code) / L (validation) | [decision] D-3, R2.6, calibration data | [decision] |
| R2.8 | Separate `confidence` from `classifier_score`: carry `(structural_evidence, p, margin or uncertainty, evidence_completeness, impact, direction)` into the decision and the evidence panel; `completeness` = profile approved? schema present? provenance assigned? format supported? | S8 (SP 7.3, 11.3.3). The user's decomposition. | Medium | M–L | R2.6, R3.1 | [decision] D-4 |
| R2.9 | Calibration on a held-out split (isotonic or beta, ≥ 100 per class) once a training set exists; report reliability diagram, ECE, Brier; expose SVM margin as an uncertainty dimension; add a reject band (Chow) with reported coverage. | S5, S6 (SP 11.2). | Medium | M | R4.2 | [approve] when data exists |
| R2.10 | Decide whether `finding:*` nodes stay in the graph; if they do, always report the finding-node ablation; if not, fuse Stage 1 and classifier only at the decision layer. | M2 (SP W5, RC M1). | High (conditional) | S (code) / M (experiment) | [decision] D-5 | [decision] |
| R2.11 | Wire `md_flags`/`dom_flags` behind a format router **or** formally exclude non-JSON formats from FYP-I claims. | S9 (SP D7, AA F-07). | Medium | M | [decision] D-13, R1.9 | [decision] |
| R2.12 | `_STRUCTURED_TEXT` scope: narrow (require ≥ 2 `key:` lines or a brace/bracket) or let `INVALID_JSON`-by-heuristic behave as `NOT_JSON` when a text-accepting schema is registered; handle `None` results (`'None'` string) explicitly. | I3, I4. Benign prose blocked on punctuation; 7/74 tools return None. | Medium | S | R2.1 (to size it), [decision] D-12 | [decision] |

**Proposals from the specialist reports that the reviewer flagged as distortion-prone — not adopted as roadmap items:** per-tool conformal thresholds (too few benign samples per tool; leakage against utility tasks; per-format at most), stacked meta-classifier and Bayesian per-tool priors (need end-to-end labelled runs / agreed priors), Dempster–Shafer (arbitrary masses, concept load), cost-sensitive thresholds without stated costs (replaces one set of constants with another), per-field rule relaxation (needs a per-field benign corpus; opens attack surface), and RC's "EXTERNAL → AUTHORITY_ARG ⇒ review" as a primary rule (AgentDojo user tasks legitimately flow email/web content into arguments; rests on evadable substring lineage). They remain documented in `STRUCTURAL_POLICY_RESEARCH.md` §10–11 and `RESEARCH_CRITIQUE.md` §5 as research options.

## 3. Important architectural improvements

| Id | Change | Why / evidence | Severity | Effort | Depends on | Gate |
|---|---|---|---|---|---|---|
| R3.1 | **Wire step-1.2 tagging into the graph**: `build_trust_graph` consumes `FieldTag`; node label from `(trust, provenance, role, value_type)` (never `tag_id`/timestamps); carry `depth` from the parser field or drop it; `Provenance.UNKNOWN` as its own label, not UT. Replace `risk_detector.py:46` legacy call. | M1, I7(c), I10 (AA F-03, IA F-6). The core hypothesis is untestable until this lands. | High | M | R3.2, tagging tests (R6.1) | [approve] (this *is* the planned step) |
| R3.2 | **`DetectorContext` contract for step 1.3**: add `run_id`, `interception_id`, optional `user_prompt` provider, with defaults (frozen dataclass stays backward-compatible); `RunState` lives per run inside the detector factory. | A3 (AA F-13). Lineage cannot be wired otherwise without a layering break. | Medium | S–M | [decision] D-10 | [decision]; clone change, additive |
| R3.3 | Fix the two step-1.2 tagging bugs: `text`-format profile on a JSON-parsed payload must tag every field (with `result_default`) or flag the mismatch; normalise `result_fields` patterns through the parser's `_child_path` quoting (or validate in `ProfileEntry.__post_init__` that segments are identifiers or `["..."]`). | I7(a),(b) (IA F-8, F-9). Silent fall-back corrupts Phase-2 profiles for `content-type`-style keys. | Medium | S | — | [approve] |
| R3.4 | One composition module (`pipeline/compose.py` or `scripts/run_pipeline.py`) that builds the full detector from configuration, plus a graph-JSONL exporter from parsed traffic so the classifier can be trained from fixtures. | A1 (AA F-02). Pipeline never assembled. | High | M | R3.1 | [approve] |
| R3.5 | Move human review out of the detector call (detector returns `route=human_review`; executor suspends), or make `detector_timeout_s` per detector kind and document that interactive review needs a long timeout; pass a cancellation `Event` so late results are ignored. | I5 (IA F-5, AA F-05). | Medium | M | [decision] D-11 | [decision] |
| R3.6 | Ledger schema v2: record the actual detector verdict and a separate `policy_decision`; version `verify_chain`. | I11 (AA F-11). Detector vs policy FPR conflated. | Low | S–M | — | [approve] |
| R3.7 | One Stage-1 orchestration: make `parser_analysis` delegate to `stage1.analyze` (format from TVM/profile) or retire `stage1.py`; retire the extra routing in `eval.py`/`adi_eval.py`. | A2 (AA F-07). | Medium | M | R2.11 | [decision] D-13 |
| R3.8 | Minimal packaging: `pyproject.toml` with `src` layout, `pip install -e .`, full pinned requirements / lock file generated from the venv; remove `try/except ImportError` flat-layout fallbacks and `sys.path` hacks in scripts/tests; move `evaluate()` out of `scripts/` into `src/`. | A4 (AA F-09, PS D2). Environment not reproducible; `parser` module/package identity already broke once. | Medium | M | — | [approve] |
| R3.9 | Pick one AgentDojo copy (editable install of the vendored fork, or remove the vendored tree) and record the decision (D1–D3 of `docs/tagging-design.md` §11.5). | I1. | High | S (decision) / M (cleanup) | [decision] D-1 | [decision] |
| R3.10 | Move `GraphSnapshot` to `trust_graph/types.py`; relocate `parser/{demo,eval,adi_eval,agentdojo_offline,make_extra_cases}.py` to `scripts/` or `experiments/`; split the root README into project vs upstream sections; delete the local untracked `src/detector/`, `src/risk/`. | A5, AA F-08/F-10, PU D8. | Low | S–M | — | [approve] |
| R3.11 | Evidence panel: annotate each untrusted item with path/provenance/role/length, truncate and escape for display; document reviewer-injection and denial-text-as-channel in the design doc. | A6 (AA F-12, CR §(g)). | Low | S–M | R3.1 | [approve] |

## 4. Research-dependent changes

These change what the thesis claims or measures; each needs the corresponding decision and, mostly, data that does not exist yet.

| Id | Change | Why / evidence | Depends on | Gate |
|---|---|---|---|---|
| R4.1 | **Reframe the contribution** as a retrofit, framework-external provenance monitor evaluated on the security / utility / reviewer-load trade-off; add CaMeL, FIDES, Progent, MELON, Task Shield, IPIGuard and arXiv:2601.04795 to the related-work table; drop "deterministic guarantee" wording for "reproducible, auditable, CPU-cheap, no LLM in the loop"; verify the CaMeL-strict claim against the ADI paper's full text before repeating it; cite Shervashidze et al. 2011 for WL. | M3, M4, M7, RC A3, F17; CR §(d),(e). | [decision] D-8 | [decision] |
| R4.2 | **Training set and classifier evaluation**: graph JSONL from Phase-1 fixtures and (later) replayed AgentDojo traffic via the new tagger; tool-grouped CV folds; ROC-AUC, PR-AUC, reliability, ECE, Brier; **provenance-shuffle ablation** (if AUC does not drop, the classifier is not a provenance classifier); **finding-node ablation** (circularity). A negative result is publishable at FYP level if the experiment is clean. | M1, M2, T4 (SP 13.3, RC E1/E2, G3). | R3.1, R3.4 | [approve] when R3.1 lands |
| R4.3 | **Graph enrichment experiment** (only if R4.2 shows the current labels carry no signal): role (`AUTHORITY_ARG`/`CONTENT`), lineage status, length buckets, and cross-message edges EXTERNAL source → DERIVED argument, so attacked vs benign *flows* differ. Alternatively scope the classifier to structural/flow anomalies only and say so. | M1, M5 (RC A4 recommendation, §5.2). | R4.2, step 1.3 | [decision] D-8 |
| R4.4 | **Resolve the scope contradiction**: either admit cross-call lineage into FYP-I scope (it is what RunState implements) or keep per-message scope and drop the claim that the detector catches ADI's downstream harm. | M5 (RC L3). | — | [decision] D-8 |
| R4.5 | **Argument trust semantics**: keep design decision 2 (USER→T via lineage, arguments DERIVED take the worst source) or switch to "arguments untrusted unless the TVM marks them trusted". Open from the tagging work; affects review load directly. | tagging design §2.2/§3.2; master report §7.11. | — | [decision] D-9b |
| R4.6 | **End-to-end AgentDojo runs** (provider-backed; `off` / `passthrough` / `enforce`; parser-only and composed) reporting benign utility, utility under attack, targeted ASR, per-call FPR/FNR, review rate and denial-reason breakdown; both stock NL attacks and `data_only_syntactic`. Needs API credentials and a cost estimate (629 security cases × model). | SP 13.6, RC E0/E3. | R1.1, R3.4, R2.3, credentials | [decision] D-15 (budget) |
| R4.7 | **Held-out structural set and over-defense set**: new delimiter templates authored by a different team member; NotInject-style benign set (JSON-in-prose, code, curl, markdown tables) with a stated FPR target; freeze both. | RC M2, M8, E5; SP 13.1, W8. | [decision] D-7 | [decision] |
| R4.8 | Baseline comparison against in-repo CaMeL-strict / Progent / IsolateGPT / Prompt Guard on the same tasks. **Not cheap** (paid LLM runs); plan with R4.6. | RC E4, CR §(d). | R4.6 | [decision] D-15 |
| R4.9 | Adaptive-attacker evaluation: regex-aware delimiter mutation, lineage evasion (encoding, splitting, RunState-cap flooding); report static and adaptive ASR. | RC L7, E6. | R4.6 | future |
| R4.10 | Human-review protocol (N reviewers × M cases, blinded, with/without panel) before reporting Human Approval Accuracy; until then report review-tier rate only. | RC M4, SP 13.10, W9. | reviewer UI | [decision] D-11 |

## 5. Performance improvements

| Id | Change | Why / evidence | Severity | Effort | Gate |
|---|---|---|---|---|---|
| R5.1 | Append-only `ledger.jsonl` (one line per event); persist raw payloads once at capture; keep atomic replace only for run metadata; `import_ledger` tolerates a partial last line. | P1 (34.5 s vs 0.51 s over 200 calls). | Medium | M | [approve] |
| R5.2 | Bounded raw-payload retention (count/bytes per run; opt-in by size); expose per-run eviction to harnesses. | P5. ~5 MB retained per 1 MB hop, forever. | Medium | S–M | [approve] |
| R5.3 | Reusable single-worker executor instead of a thread per detector call; cooperative deadline passed into the detector so a timeout stops work instead of leaking a busy thread. | I5, P3 (~0.6 ms × 2 per call; leak confirmed). | Medium | M | [approve] |
| R5.4 | Report overhead measured around `check_call`/`check_result` with persistence **off**, and say so; `detector_latency_ms` alone under-states cost. Commit a latency budget test (p95 per message, 10k-field payload). | PS §4.1, RC E8. | Low | S | [approve] |
| R5.5 | When step-1.3 lineage lands: index exact matches by hash first and bound substring-candidate sets; cache compiled profile patterns. | PS §4.2 (hypothesis: Θ(args × history × length)). | Medium (future) | M | with step 1.3 |
| R5.6 | Minor: cache `TypeAdapter` per schema; avoid the second `json.loads` in `check_schema`; `MAX_BYTES` truncation by bytes not characters. | PS P7, S6. | Informational | S | [approve] |

## 6. Testing improvements

| Id | Change | Why / evidence | Severity | Effort | Gate |
|---|---|---|---|---|---|
| R6.1 | Write `tests/unit/test_tagging.py` for the step-1.2 API (the drafted fixture list from the tagging session: approved/draft/no profile, text format, containment, role table, duplicate & quoted keys, argument roles, `trust_for`, no raw value in tags, `normalise`, misuse raises, legacy call unchanged, no framework imports) **plus** regression tests for I7(a)–(c). | T3, I7. | High | M | [approve] (planned step) |
| R6.2 | Boundary tests at every stage seam: parser → tagging (`ParsedField` contract), tagging → graph (`FieldTag` and legacy `TaggedField`), graph → classifier (`GraphSnapshot`), gate thresholds exactly at 1.0 and 5.0 and at float products. | I7(c), T7. | Medium | M | [approve] |
| R6.3 | Offline end-to-end test: clone → parser → tagging → graph → *trained-on-fixtures* classifier → gate → reviewer stub, on replayed AgentDojo ground-truth calls; no LLM. | T5. | High | M–L | R3.4, R4.2 |
| R6.4 | Phase-1 conformance: assert `expected_untrusted_paths`, not just boolean `flagged`; planted-attack test asserts the path, not non-emptiness. | T7 (TV F-05). | Medium | S | [approve] |
| R6.5 | Evidence panel: test that raw untrusted content is withheld in evidence-only mode. | T7 (TV F-11). | Medium | S | [approve] |
| R6.6 | Guard test for the AgentDojo copy: assert `agentdojo.__file__` is the pinned copy and that `tool_result_to_str({"a":1})` yields JSON. | I1 (TV F-09). | Medium | S | R1.1 |
| R6.7 | Classifier: `save/load` round-trip, `train.py` loader validation (duplicate ids, bad labels), calibration monotonicity. | T4. | Medium | S | [approve] |
| R6.8 | Determinism tests: `unexpected_key` order, evidence-panel render, WL features under different `PYTHONHASHSEED`. | I8. | Low | S | R1.6 |
| R6.9 | Tooling: add `pytest-cov`, `ruff`, `mypy` to a dev requirements file and a root config; a minimal CI workflow running the full suite incl. `src/parser`. (Installing is out of audit scope; listed for the team.) | TV F-15. | Low | S–M | [approve] |
| R6.10 | Commit reproducible validation artefacts: re-run `run_phase1_cases.py` at HEAD and track the results file (or a summary) instead of git-ignoring it; populate `benchmarks/` or remove the README section. | T6. | Medium | S | [approve] |

## 7. Future enhancements (beyond FYP-I unless time allows)

- Flow graph across the whole run (fields as nodes; parent/child, lineage and call-sequence edges) as the classifier's input — the representation under which a WL kernel has something to learn (RC §5.2).
- One-class / anomaly model on benign graphs per tool as a *novelty* signal, distinct from attack (SP 11.2).
- Reviewer UI that renders the evidence panel with provenance annotations; measured reviewer load as a first-class metric (RC M5).
- Denial-text channel analysis: how denial strings change agent trajectory; whether they can carry injection (CR §(g)).
- Progent-style per-tool policies as an enforcement layer beside detection, aligning with the design-patterns literature that detection alone is insufficient (RC §5.1, adapted).
- Model-artefact hash-pinning manifest for `joblib` loads (PS S5).
- Concurrency test of the ledger under parallel suites; Windows path edge cases (CR §(g)).
