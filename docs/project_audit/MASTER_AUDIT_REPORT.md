# Master Audit Report — "Closing the Data Trust Gap in Agent Data Injection"

Phase 1 research audit (read-only). Date: 2026-11-15. Branch `zain/experimental`, HEAD `66fec89`.
Prepared for: the FYP team (Zain, Madiha, Tasbiha) and supervisor, as the blueprint for the next implementation phase.

This document consolidates seven specialist reports and one independent critical review, all in this directory:

| File | Role | Independently reviewed |
|---|---|---|
| `PROJECT_UNDERSTANDING.md` | What the research proposes vs documents vs code vs demonstrable | yes |
| `RESEARCH_CRITIQUE.md` | Assumptions, novelty vs literature, limitations, experiments | yes |
| `STRUCTURAL_POLICY_RESEARCH.md` | Structural policy, score, classifier, fusion, ASR / benign utility (14 sections, all probes verbatim) | yes, deepest review |
| `ARCHITECTURE_AUDIT.md` | Components, dependencies, execution flow, divergence from design | yes |
| `IMPLEMENTATION_AUDIT.md` | 23 correctness / reliability / security findings with repro output | yes |
| `TESTING_AND_VALIDATION.md` | Exact commands, suite results, coverage map, reproducibility | yes |
| `PERFORMANCE_AND_SECURITY_NOTES.md` | Hot-path benchmarks, ReDoS / parser-bomb probes, dependencies | yes |
| `CRITICAL_REVIEW.md` | Verdict on every Critical / High finding; duplicates; contradictions; steelman | — |
| `IMPROVEMENT_ROADMAP.md`, `DECISIONS_REQUIRED.md` | Derived from the above (this phase's outputs) | — |

**Severity convention in this document.** Every severity below is the *post-review* severity from `CRITICAL_REVIEW.md` §(a). Where a specialist rated something higher, the original rating is shown in brackets. The reviewer upheld 13 of 43 Critical/High findings, corrected 6, downgraded 23, rejected 1; no finding was found fabricated, every empirical claim it re-ran reproduced in direction.

**Terminology.** The audit brief said "Attack Surface Rate". That term exists nowhere in the repository, proposal or literature. The metric is AgentDojo's **targeted Attack Success Rate (ASR)**; it is used as such throughout. Definitions were verified against AgentDojo §3.4 (`CRITICAL_REVIEW.md` §(e)).

---

## 1. Executive summary

The project is a mid-implementation research prototype. The parts that exist are mostly correct in what they do; the gap is between what the proposal *claims* the system does and what the mechanism *can* do, and between the pipeline as documented and the pipeline as wired.

Five facts dominate everything else:

1. **Only clone + parser run end to end.** The only live driver (`scripts/live_clone_parser_smoke.py`) uses the parser-only detector. Tagging, graph, classifier and risk gate are unit-tested but have never processed real traffic: no training data, no model artifact, no evaluation rows. **Every headline metric (ASR, benign utility) is currently unmeasured.** (High / Confirmed / status)
2. **The trust-provenance graph carries no provenance.** All 105 field classes in the tool trust matrix are `unclassified`, so the live tagging path marks every field UT; node labels are `UT:{type}:depth=N`. The reviewer confirmed empirically that a benign inbox and the same inbox with a natural-language injection produce **identical WL feature vectors** (even with a 5000-character body). As shipped, the "trust-provenance classifier" is a shape-plus-structural-hit classifier. This is known work-in-progress (tagging steps 1.2/1.3), but the proposal §6.5 claim that the classifier catches "structurally clean but adversarial" content is **not supported by the representation**. (Critical at claim level; High as implementation status / Confirmed)
3. **Two copies of AgentDojo decide what the parser sees.** pytest imports the vendored fork (JSON result formatter); plain `.venv` Python imports pip 0.1.35 (YAML formatter, and dict results become Python `repr`). 38 of 82 files differ after line-ending normalisation. Under the pip copy every structured post-hop result is blocked by the parser-only detector. The reviewer found that even the smoke script's explicit `dump_fn=json.dumps` does not fix dict results under the pip copy (18 of 74 suite tools return dicts). Any number produced before this is pinned is environment-dependent. (High / Confirmed)
4. **The risk gate cannot gate injected content.** `risk = p × impact` with cut-points 1 and 5 means a tier-1 tool auto-allows for every p < 1.0 (probe: p = 0.99 → auto-allow). All 44 tier-1 tools are *read* tools — exactly the carriers of injected post-hop content. The structural-hit override still forces review, so recall on delimiter forgeries is preserved, but the classifier can never influence the post-hop path. This is inherited from the proposal's own `confidence × impact` rule, not a coding slip. (High / Confirmed / design)
5. **"Unknown" means "deny", in five places, with no indeterminate verdict anywhere.** Unclassified tool, unparseable result, missing impact tier, missing classifier, missing reviewer — all deny. The cost was over-estimated by the specialists (all 74 stock AgentDojo tools resolve in the matrix; the adapter already registers return schemas) but is real in specific places: `None`-returning tools (7/74) are blocked as `parser-untrusted`; `"Balance: 100"`-style text is classified `invalid_json` and can never be released; dict results under the pip copy. The real benign denial rate has **never been measured** and can be, without an LLM. (High / design-level)

The structural detector itself is the one defensible, working component: deterministic, syntax-only, in-sample 15/15 recall on delimiter forgeries, 2/54 measured FPs, no lexical features. **Its weakness is the score, not the detection.** S is a diluted rule-match count that the gate rightly ignores; what remains is a zero-tolerance one-hit policy.

---

## 2. Scope, method and state

- **Mode:** read-only. No source, test, config, environment or existing documentation file was modified. The only writes are the files in `docs/project_audit/`. Verified at hand-over: `git status --short` → `?? docs/project_audit/` only; branch `zain/experimental`; no state-changing git command was run by any agent.
- **Agents:** six specialists (research/methodology, structural policy & scoring, architecture, correctness, testing, performance+security) worked in parallel; one independent critical reviewer then re-verified every Critical/High finding against source and re-ran the key probes with its own scripts.
- **Empirical basis:** full pytest run (`309 passed, 1 failed in 42.15 s`; the failure is the pre-existing E003 fixture/enum mismatch), plus `107 passed` from the uncollected `src/parser` tests; `compileall` exit 0; ~30 scratch probes against the real scoring, gate, classifier, parser and ledger code, all run outside the repo and reproduced verbatim in the reports. No live LLM call was made; nothing was installed.
- **Not verified:** anything requiring a provider-backed run (`.env` keys are empty locally); coverage/lint/type-check (tools not installed); full text of several cited papers (abstracts and HTML only).

---

## 3. Major findings (merged across reports)

Duplicates were merged per `CRITICAL_REVIEW.md` §(b). Each row names the primary evidence; details and repro output are in the referenced report.

### 3.1 Research claims vs mechanism

| # | Finding | Severity | Confidence | Type | Primary evidence |
|---|---|---|---|---|---|
| M1 | Graph labels `{trust}:{value_type}:depth` carry no content or flow information; with all-UT tagging, NL-injected and benign messages are WL-identical. The classifier is bounded by the parser's findings. | **Critical** (claim) / High (status) | Confirmed | methodological / architectural | RC A4, SP §3.2, CR row 3 & 20 (probe `cr_probe3`) |
| M2 | Structural findings become `finding:*` graph nodes, so any classifier "detection" of delimiter attacks re-learns Stage 1; joint reporting double-counts (label leakage). | High (conditional on a trained model) | Confirmed | methodological | SP W5, RC M1, CR row 11 & 27 |
| M3 | Contribution framing: "no published defense separates content-trust from provenance-trust at field level" is overstated; CaMeL and FIDES attach per-value provenance / integrity labels. The defensible slice is a *retrofit, framework-external* monitor with EXTERNAL→AUTHORITY lineage, evaluated on the security/utility/reviewer-load trade-off, plus the field-level graph classifier if it can be shown to add information. | Medium [was High] | Strongly supported | methodological | RC A1, CR row 18 |
| M4 | RC's statement that the ADI paper reports CaMeL-strict fully stops ADI is **unsupported** by the abstract or vendored README; must be checked against the full paper before being repeated. | Medium | Confirmed (as unsupported) | citation | CR §(e) |
| M5 | Scope contradiction: the proposal excludes multi-hop / cross-call trust, but the lineage design (RunState) re-admits exactly that flow — and it is the flow the detector most needs. | High | Strongly supported | unresolved design decision | RC L3, CR row 29 |
| M6 | "Tag forgery" threat model does not match an architecture whose tags are internal side records the attacker cannot reach; what is detected is forged *content structure*. Framing issue. | Medium [was High] | Strongly supported | methodological | RC A2, PU D9, CR row 19 |
| M7 | Possible prior art for the parsing contribution: arXiv:2601.04795 ("Defense Against Indirect Prompt Injection via Tool Result Parsing", Jan 2026) **exists**; relation to delimiter-forgery detection unproven (abstract only). | Medium | Research-dependent | research opportunity | RC F16, CR §(e) |

### 3.2 Structural policy, score, classifier, fusion

| # | Finding | Severity | Confidence | Type | Primary evidence |
|---|---|---|---|---|---|
| S1 | Tier-1 tools (44/70, all read tools) auto-allow for every p < 1.0; the classifier cannot gate post-hop injected content. Inherited from proposal formula. | High [was Critical] | Confirmed | design / methodological | SP D1, CR row 1 |
| S2 | S = hits/boundaries is dilution-inverted (same 4-hit forgery: 0.50 alone → ~0.02 in a 50-email inbox) and over-counts correlated rules (one forged substring fires 4 rules; benign quoted JSON scores 1.0). **Inert for decisions today** because the gate reads only `hits > 0`; latent for any future threshold and for anything reported as a "score". | Medium [was High] | Confirmed | methodological (latent) | SP §1.8, D6, W1; CR rows 4, 8, 15 |
| S3 | One scalar conflates "forgery evidence", "could not read", "no profile"; all collapse to S = 0 + status and then to deny. No UNKNOWN / indeterminate class in `DetectorDecision`, `RiskAssessment`, or `EvaluationCase`. | High | Confirmed | design | SP W2, §1.7, §6; CR row 9 |
| S4 | Zero-tolerance aggregation: any single counted hit forces review regardless of rule reliability; `embedded_json` + `kv_forgery` are the dominant known FP source (2/54). | Medium [was High] | Confirmed | methodological | SP W3, CR row 10 |
| S5 | Impact tiers {1,5,10} and cut-points {1,5} are policy defaults with no empirical basis; the loader *requires* `"policy default"` (an honesty guard, not a defect). Effective review thresholds: p ≥ 0.2 at tier 5, p ≥ 0.1 at tier 10, unreachable at tier 1; "high" tier unreachable at tier 5 given Platt squashing (separable toy data calibrates to only 0.68/0.32). | Medium | Strongly supported | unresolved design decision | SP W6, §7.2, D2; CR rows 2, 12 |
| S6 | Classifier has no abstention; `predict` is a fixed 0.5 argmax. The specialist's "OOD graph → p = 0.5, label = attack" was **rejected as a general claim** (artefact of a symmetric toy training set; with 10/4 class balance the same graph is 0.43/benign). The residual point — no reject option, class-prior-dependent tie-break — stands. | Low [was High] | Confirmed | methodological | SP §3.2, CR row 14 |
| S7 | `contains_adi = hits > 0 or label == "attack"` can be True on an auto-allowed call; `flagged` in `evaluation.py` is never defined relative to it → FPR/FNR are currently undefined. | Medium | Confirmed | implementation defect | SP D3, CR row 17 |
| S8 | `confidence` in `RiskAssessment` is a copy of `classifier_score`, not an independent evidence-quality measure. | Medium | Confirmed | unresolved design decision | SP D10 |
| S9 | md/dom scorers are not wired into the pipeline (reachable only from eval scripts); both also FP on benign text (`5 < 10 and x <b`, markdown autolinks, second numbered list). Matters only if non-JSON formats enter FYP-I claims. | Medium [was High] | Confirmed | coverage gap | SP D7, IA F-11, CR row 5 |
| S10 | The "artificial ASR improvement" hypothesis (ASR drops from accidental denials, not detection) is sound and **currently untestable from repo data**; the live sources are `None`-returns, `Key: value` text, no-reviewer denials and pre-hop denials — not unclassified tools (0/74 missing). Required control: per-case denial-reason breakdown alongside ASR. | Medium (hypothesis) | Research-dependent | methodological | SP §8.3, CR row 16 |

### 3.3 Implementation defects (confirmed by repro)

| # | Finding | Severity | Confidence | Primary evidence |
|---|---|---|---|---|
| I1 | Dual AgentDojo copies: pytest → vendored (JSON), scripts → pip (YAML, dict → Python `repr` → `invalid_json`). Even `dump_fn=json.dumps` leaves dict results as `repr` under pip. 38/82 files differ incl. `tool_execution.py`, `functions_runtime.py`. Decisions D1–D3 (`docs/tagging-design.md` §11.5) are the blocker. | High | Confirmed | AA F-01, IA F-3, PS D1, CR row 25 |
| I2 | Nested `extra="forbid"` schema violations are silently skipped (`structural.py:127-134`); `{"item": {"body": "hi", "role": "system"}}` → zero findings. Only affects explicitly-forbidding nested models (AgentDojo models default to ignore). Dead `except ValidationError` at `:104-110` is the lost original handling. | Medium [was High] | Confirmed | IA F-1, F-14; CR row 31 |
| I3 | `_STRUCTURED_TEXT` classifies `"Balance: 100"`, `"Error: -1"`, `"Status: true"` as `invalid_json`, which no schema can release; `"Balance is 100"` passes. Deliberate YAML-guard; prevalence unmeasured. | Medium [was High] | Confirmed | IA F-2, CR row 32 |
| I4 | **New (reviewer):** tools returning `None` (7/74 suite instances) format to `'None'` and are blocked `parser-untrusted`. Direct detector probe, not an end-to-end run. | Medium | Strongly supported | CR §(g) |
| I5 | Human-review callback runs inside the detector thread, which the core abandons after the default 2 s; a 2.3 s detector → `Blocked: detector unavailable`; the thread leaks and keeps running (confirmed `tvm-detector` alive after block). Timeout is configurable and no reviewer is wired anywhere, so a design smell today, a broken feature the day a reviewer is attached. | Medium [was High] | Confirmed | IA F-5, F-13; AA F-05; PS P3; CR row 34 |
| I6 | `graph.py:24-26` `split("#",1)[0]` attaches findings on `$.to#2` to `$.to` and isolates findings on keys containing a literal `#`. | Medium | Confirmed | IA F-7, AA F-15, SP D13 |
| I7 | Step-1.2 tagging (uncommitted-then-committed in `66fec89`): (a) `text`-format profile on a JSON-parsed payload tags only `$`, other fields get *no* tag; (b) pattern `$.content-type` never matches the parser's `$["content-type"]` and silently falls to EXTERNAL; (c) `FieldTag` lacks `depth` → `build_trust_graph(FieldTag list)` raises `AttributeError` (known WIP, no boundary test). | Medium | Confirmed | IA F-6, F-8, F-9 |
| I8 | `unexpected_key` finding order is hash-seed dependent (set difference) and leaks into ledger/evidence text. | Medium | Confirmed | IA F-10 |
| I9 | Lone UTF-16 surrogate in a result or argument → uncaught `UnicodeEncodeError` in `_payload_hash`, outside the detector's try/except; aborts the executor call. Narrow (JSON-formatted results are `ensure_ascii`-escaped; reaches only raw `str` tools / odd args). Availability only. | Medium [was High] | Confirmed | PS S1, CR row 43 |
| I10 | Legacy `risk_detector.py:46` tags post-hop result paths with argument-keyed `field_trust_classes`, so even a populated matrix would tag every result field UT. | High (part of M1) | Confirmed | AA F-03 |
| I11 | Ledger `detector_decision=False` recorded for allowed-but-unclassified tools; conflates detector and policy verdicts in any metric derived from the ledger. | Low | Confirmed | AA F-11 |
| I12 | Detector over-matching: `dom_flags` on `<https://…>` / `<admin@site.com>`; `md_flags` on a second numbered list; `kv_forgery` on `truest`/`nullify` (no `\b`). | Low–Medium | Confirmed | IA F-11 |

### 3.4 Architecture

| # | Finding | Severity | Confidence | Primary evidence |
|---|---|---|---|---|
| A1 | No composition module assembles clone → parser → tagging → graph → classifier → gate; the composed detector exists only in a test. | High (status) | Confirmed | AA F-02 |
| A2 | Two divergent Stage-1 orchestrations (`parser/stage1.analyze` self-declared entry point vs `pipeline/parser_analysis`), plus two more routing variants in eval scripts. | Medium | Confirmed | AA F-07 |
| A3 | `DetectorContext` carries no `run_id`, `interception_id` or user prompt; step-1.3 lineage cannot be wired without a clone-side contract change or a layering break. Not yet recorded as a decision. | Medium | Strongly supported | AA F-13 |
| A4 | No packaging (`pyproject.toml`), `requirements.txt` has 2 lines vs 84 packages in the venv, no lock file; mixed package/flat import identities (`parser` as module vs package — already broke once, commit `9244995`); root README points at a non-existent `llm-benchmark/.venv`. | Medium | Confirmed | AA F-09, PS D2 |
| A5 | `trust_graph.graph` imports its output type from `classifier.wl_svm` (downstream dependency); dev tooling lives inside the `parser` library package. | Low | Confirmed | AA F-08 |
| A6 | Evidence panel forwards raw untrusted strings verbatim to the reviewer — the one channel where attacker text reaches a human unmodified; denial text returned to the LLM is also an un-analysed channel. | Low | Confirmed | AA F-12, CR §(g) |

### 3.5 Testing and reproducibility

| # | Finding | Severity | Confidence | Primary evidence |
|---|---|---|---|---|
| T1 | `pytest.ini` omits `src/parser`: 107 passing parser tests are not in the default run (true total 416 passed / 1 failed). READMEs claim `pytest` runs "all tests". | Medium [was High] | Confirmed | TV F-02, AA F-06, CR row 36 |
| T2 | `tests/unit/test_parser.py`, `test_classifier.py`, `test_provenance.py` and `tests/fixtures/classifier_cases.json` are 0-byte files tracked in git. | Medium | Confirmed | TV F-03 |
| T3 | New tagging API has zero tests and no pipeline caller (acknowledged in commit message). | Medium [was High] | Confirmed | TV F-07 |
| T4 | Classifier never trained or evaluated on project data; `save/load`, `train.py` untested; the two WL-SVM tests fit a 12-graph toy with two shapes. | High | Confirmed | TV F-10 |
| T5 | No offline end-to-end test; the only full-path script needs `GROQ_API_KEY`; integration tests use a stub classifier returning 0.2. | High | Confirmed | TV F-12 |
| T6 | Validation artefacts not reproducible from committed state: `benchmarks/` empty; `experiments/results/phase1_run.json` git-ignored and stale (`cb0376f` vs HEAD); `graphs.jsonl` / `evaluation_cases.jsonl` named in README do not exist. | Medium [was High] | Confirmed | TV F-13 |
| T7 | Weak assertions where it matters: Phase-1 conformance asserts boolean `flagged` only, never `expected_untrusted_paths`; evidence-panel test never checks that raw content is withheld; threshold boundaries untested. | Medium | Confirmed | TV F-05, F-11 |
| T8 | E003: fixture expects `invalid_json`, parser returns `not_json` for plain prose — a fixture-vs-enum disagreement, pre-existing. | Low | Confirmed | TV F-01 |

### 3.6 Performance and security (overhead is a research constraint)

| # | Finding | Severity | Confidence | Headline numbers | Primary evidence |
|---|---|---|---|---|---|
| P1 | Ledger persistence rewrites all three JSONL files on every capture/transition (5–7× per tool call): per-call latency 31.7 ms → 331 ms over 200 calls; cumulative **34.5 s vs 0.51 s** in-memory (~68×, quadratic). `detector_latency_ms` excludes this entirely. Any latency figure from a run with `storage_dir` set measures the ledger, not the defense. | Medium [was High] | Confirmed | AA F-04, PS P1, CR row 42 |
| P2 | Full-chain overhead with in-memory ledger and parser-only detector: **~3–13 ms per tool call** for 1–100 KB results (~1.2 ms of it is two thread spawns); risk path adds ~0.3 ms (10 fields) to ~31 ms (1000 fields). Acceptable vs LLM round-trips. | Informational (positive) | Confirmed | PS §3.2 |
| P3 | Sub-1 MB parser bombs (150k duplicate keys; 60k embedded-JSON strings) take ~1.7 s ≈ 85% of the 2 s budget; `MAX_FIELDS` caps fields but not findings (100k `Finding` objects). On a slower CPU → timeout → blocked *and* thread keeps burning CPU. | Medium | Confirmed | PS S3 |
| P4 | ReDoS in `dom_flag._OK_PREFIX` (three adjacent whitespace quantifiers): 1000 leading spaces → 3.0 s, 2000 → >12 s. Eval path only today; High the day DOM is wired. All other hot-path regexes grew linearly. | Medium | Confirmed | PS S2 |
| P5 | Raw payloads retained in memory for process lifetime (~5 MB per 1 MB result hop); payload deep-copied 3–4× and canonically hashed per hop. | Medium | Confirmed | PS P4 |
| P6 | Hygiene positives: no secrets in tracked files; `.env` untracked, values empty; no eval/exec/pickle/yaml.load/shell=True in `src/`. `joblib.load` is pickle (code-owned artefacts only; document the trust boundary). joblib 1.6.0 is past CVE-2022-21797. | Informational | Confirmed | PS S5–S8, D3 |

---

## 4. Assessment of the structural policy and scoring methodology

This section answers the brief's central question — is the methodology conceptually sound? — using the specialist's reconstruction (`STRUCTURAL_POLICY_RESEARCH.md` §1–§9) as corrected by the reviewer (`CRITICAL_REVIEW.md` §(a), §(f), §(h)).

**What the policy actually is.** Five counted regex rules + `embedded_json` + `duplicate_key` + `unexpected_key`, each weight 1, scanned per string leaf and per key under two normalisation variants; `S = min(1, hits / boundaries)`. Non-OK parse statuses yield S = 0 and deny. There is **no threshold on S anywhere**; both detectors decide on `hit_count > 0`. The gate adds `risk = p × impact` with cut-points 1 and 5, and ORs in review for any hit, S > 0, or missing classifier; review without a reviewer is deny.

**Verdict on the structural detector:** sound and defensible. Deterministic, syntax-only, language-independent, immune to the over-defense failure of lexical detectors; in-sample 15/15 on delimiter forgeries, 2/54 FP. Keep it syntactic (do not add instruction-word rules).

**Verdict on S as a score:** not sound as a ranking or probability. It is a rule-match density that (a) falls as benign content is added, (b) counts the same forged substring up to four times, (c) scores a benign two-key payload with quoted JSON at 1.0, and (d) for NOT_JSON prose degenerates to a 0/1 flag because `boundary_count = 1`. The team already recognised (a) — that is *why* the proposal's `1-(1-S)(1-C)` fusion was abandoned (steelman, CR §(f).2) — so S is inert today. It must not be reported as a "structural score" in the thesis without redefinition (per-field max over deduplicated, reliability-weighted evidence).

**Verdict on the gate:** unvalidated arithmetic with one policy hole. The multiplication is the proposal's own NIST-style rule and the structural override preserves recall; but tier-1 = all read tools, so the classifier is excluded from precisely the post-hop path that carries injections. Thresholds {1,5} were designed for a different formula and never re-derived; given Platt squashing, the "high" tier is unreachable at tier 5.

**Verdict on the classifier:** cannot currently contribute evidence beyond the parser. Inputs lack provenance (M1), include the parser's own findings (M2), and there is no training data or model. Any ASR/utility figure from the composed path would be uninterpretable until provenance is wired and the two ablations (provenance-shuffle, finding-node removal) are run.

**Verdict on unknown handling:** fail-closed is a legitimate security posture and is auditable (labels are recorded); its cost was over-estimated by the specialists but is real for `None` returns, `Key: value` text and pip-copy dict formatting. The missing piece is not "allow unknown" — read tools are the injection carriers, so "UNKNOWN → allow read-only" would *raise ASR* and be mis-reported as a utility win (CR §(d)) — but an explicit indeterminate verdict carried into the metrics, with a measured rate, and a per-impact policy decided by the team.

**On the user's decomposition** (structural score / classifier score / confidence / final classification / ASR / benign utility as separate quantities): the audit supports it. The code already half-implements it (`review_reasons` tuple, S kept as evidence, `Provenance.UNKNOWN` and `LineageStatus.UNLINKED` in the new tagging). What is missing is to carry these as distinct fields into the decision *and the evaluation rows*, instead of collapsing into `risk_score` and `contains_adi`. Whether and how to fuse them is correctly treated as a research question with experiments (§13 of the structural report, as pruned in `IMPROVEMENT_ROADMAP.md`).

---

## 5. Implications for Attack Success Rate and Benign Utility

Definitions are correctly implemented in `src/pipeline/evaluation.py` and match AgentDojo §3.4 (verified). The threats are to *measurement*, not definition:

| Threat | Direction | Status | Control |
|---|---|---|---|
| Accidental denials (None returns, `Key: value` text, pip-copy dict formatting, no-reviewer denials, pre-hop denials) lower ASR without detecting anything | ASR looks better than the detector is | Hypothesis, strongly motivated; untestable until an LLM-free replay or live run exists | Per-case **denial-reason breakdown** reported with ASR; count only detection reasons as detection |
| Same denials zero benign tasks (task-level utility; one denied call in a 5-call task ≈ 18% task failure at 4% per-call FPR) | Benign utility looks worse than FPR suggests | Unmeasured; measurable now | LLM-free replay of ground-truth calls through the adapter in enforce mode, by reason |
| `flagged` undefined relative to `contains_adi` / decision; per-call vs per-task unspecified | FPR/FNR not comparable across runs | Confirmed | Define in `evaluation.py` docs before any run |
| Structural stage has 0% recall on AgentDojo's stock NL attacks by design | ASR reduction ≈ 0 on stock suites unless the ADI delimiter suite is used | Confirmed (Phase-1: 0/20 NL) | Report per attack family; use `data_only_syntactic` |
| Environment-dependent formatter (I1) | Any measured number may not reproduce | Confirmed | Pin one copy + explicit JSON formatter; record `agentdojo.__file__` per run |
| Denial text returned to the LLM changes agent trajectory (retries, re-issued calls) | Both metrics, direction unknown | Not analysed by any report | Log and report re-issue counts |
| Latency reported from runs with persistence on | Overhead over-stated by a run-length-dependent term | Confirmed | Report with persistence off; measure around `check_call`/`check_result` |

---

## 6. Recommendations (summary; full prioritised list in `IMPROVEMENT_ROADMAP.md`)

Order defended by the reviewer and adopted here:

1. **Pin one AgentDojo copy and make JSON the adapter's own formatter default**; record which copy ran in every results file. (Blocks everything measurable.)
2. **Measure the real benign denial rate without an LLM**: replay AgentDojo ground-truth calls (as `build_phase1_cases.py` already does) through the adapter in enforce mode; break down by reason. Neither specialist proposed this; it is the cheapest high-value experiment available.
3. **Wire real provenance into the graph** (step-1.2 tagging → `build_trust_graph`, profiles with SYSTEM/EXTERNAL result fields, `UNKNOWN` as its own label), fix the step-1.2 bugs (I7) and write `tests/unit/test_tagging.py`.
4. **Only then** train and evaluate the classifier — with provenance-shuffle and finding-node ablations; if AUC does not drop under shuffle, the classifier is not a provenance classifier and the thesis must say so.
5. **Define `flagged`**, separate detector verdict from policy verdict in the ledger, add an explicit indeterminate outcome, and report its rate (coverage) with ASR and utility together.
6. **Re-derive gate behaviour**: decide the tier-1/read-tool question explicitly; replace `p × impact ≥ 1` with per-impact thresholds only once calibration data exists; keep the structural override.
7. **Redefine S** as per-field max over deduplicated evidence before it is ever reported; keep the detector syntactic.
8. **Small confirmed fixes** (nested forbid, `Key: value` heuristic scope, `None` results, surrogate-safe hashing, `#` path handling, set-order determinism, `_OK_PREFIX`, findings cap, append-only ledger, `testpaths`, 0-byte files).
9. **Reframe the contribution** as a retrofit provenance monitor evaluated for the security/utility/reviewer-load trade-off; position against CaMeL/FIDES/Progent/MELON/Task Shield and read arXiv:2601.04795; verify the CaMeL-strict claim against the ADI paper's full text before repeating it.

What should **remain unchanged**: the structural rule set's syntactic scope; the decision to keep S out of the arithmetic fusion; fail-closed on detector error/timeout; the structural-hit override; the ledger hash chain; the design rule that tagging never imports `clone.adapters` or `agentdojo`.

---

## 7. Unresolved research questions (consolidated)

1. Operational definition of UNKNOWN per action class (read-only vs side-effecting, pre vs post) — and who owns the policy.
2. Can the WL-SVM detect provenance forgery once real provenance is present, given most result fields will be EXTERNAL and most arguments DERIVED/UNLINKED until lineage lands? Does the signal live in cross-message lineage, which the proposal's scope excludes?
3. Misclassification costs per impact tier — without them thresholds cannot be justified.
4. Should structural findings be graph features at all, or should Stage 1 and the classifier be fused only at the decision layer?
5. Per-suite non-JSON / `None` / dict share and the resulting benign denial rate (measurable now).
6. Is "block unclassified tool" a defended posture or an accident? (0/74 affected on stock suites, so this is about future suites.)
7. Target FPR, and on which benign corpus.
8. Are the self-authored delimiter templates representative of Choi et al.'s released attacks? (15/15 is in-sample.)
9. Should `embedded_json` remain a counted rule?
10. What does `flagged` mean, and how are review-tier denials without a reviewer labelled?
11. Argument trust: keep USER→T via lineage (design decision 2) or "untrusted unless the TVM says otherwise"? (Open from the tagging work; see `DECISIONS_REQUIRED.md`.)
12. Does the denial string returned to the agent itself act as an injection channel or trajectory distortion?

---

## 8. Hand-over checklist

| Check | Result |
|---|---|
| No source code or existing tests modified | `git status --short` → only `?? docs/project_audit/` |
| Only permitted documentation created | 10 files, all in `docs/project_audit/` |
| Branch unchanged | `zain/experimental`, HEAD `66fec89` |
| Every major finding has evidence and classification | yes; file:line citations and repro output in the specialist reports; severities reconciled in `CRITICAL_REVIEW.md` |
| Structural-policy report independently reviewed | yes (`CRITICAL_REVIEW.md` §(a) rows 1–17, §(d), §(f), §(h)) |
| Recommendations technically defensible | after pruning per `CRITICAL_REVIEW.md` §(d); distortion-prone proposals are marked as such in the roadmap |
| Live-model results claimed | none |
| Known limitations of this audit | no coverage/lint tooling; no provider-backed run; several papers checked by abstract only; `test_static.py` sampled not read in full; proposal numbers (ADI ASR 31–43%) not re-verified |

**What to do first when implementation resumes:** items 1 and 2 of §6 (pin the framework copy; measure the LLM-free denial rate). They need no research decision, unblock every metric, and will likely change the team's view of the fail-closed cost before any policy is redesigned.
