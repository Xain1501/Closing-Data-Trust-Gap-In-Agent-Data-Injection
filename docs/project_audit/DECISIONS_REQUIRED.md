# Decisions Required

Decisions the research team must take before the corresponding roadmap items (`IMPROVEMENT_ROADMAP.md`) can proceed. Each lists the alternatives found in the audit, their trade-offs, and what they imply for Attack Success Rate (ASR) and Benign Utility (BU). Where the audit has a recommendation it is stated and marked as such; the team decides. Date 2026-11-15, branch `zain/experimental`, HEAD `66fec89`.

Ordered roughly by how much they block.

---

## D-1 Which AgentDojo copy, and which result formatter (tagging design D1–D3)

**Why it blocks:** every post-hop payload the parser sees depends on it (I1). pytest and plain Python currently run different framework code (38/82 files differ). Under the pip copy dict results become Python `repr` even with `dump_fn=json.dumps` (18/74 tools return dicts).

| Option | Trade-off | ASR / BU implication |
|---|---|---|
| A. Vendored fork only (editable install; remove pip copy from the venv) | Keeps the ADI attack suite (`data_only_syntactic`, CaMeL bypass PoCs); diverges from upstream fixes | Required to measure ASR on ADI attacks at all |
| B. pip 0.1.35 only | Upstream-tracking; **loses the ADI attacks** the project is built on | Cannot evaluate the thesis threat model |
| C. Keep both, pin by `PYTHONPATH` discipline | Status quo; fragile; already produced an environment-dependent blocking behaviour | Any number is suspect until the copy is recorded per run |

In all cases: make the adapter's own default formatter JSON with an explicit dict branch (R1.1) and record `agentdojo.__file__` in every results file. **Audit recommendation:** A, plus R1.1.

## D-2 What does "unknown" do? (indeterminate verdict policy)

**Why it blocks:** R2.6, R2.7, R2.8. Today unknown = deny in five places with no indeterminate label visible to metrics (S3). The specialist's cost estimate was high; the reviewer showed stock suites resolve fully and schemas are registered, but `None` returns (7/74 tools), `Key: value` text and pip-copy dict formatting are real.

| Option | Trade-off | ASR / BU implication |
|---|---|---|
| A. Keep fail-closed, but **label** it: add `unknown` to `DetectorDecision`/`EvaluationCase`, report its rate (coverage) and reason, change no behaviour | Minimal; makes the cost visible; defensible security posture | BU unchanged; ASR measurement gains the reason breakdown |
| B. `unknown` → allow for read-only tools, review/deny for side-effecting | Raises BU | **Raises ASR**: read tools are the injection carriers (all 44 tier-1 tools are reads). Would be mis-reported as a utility win unless ASR and BU are reported together with and without it |
| C. `unknown` → review, with a reviewer stub in benchmarks | Honest middle; needs a reviewer model (D-11) | BU depends entirely on the stub's policy |
| D. Per-direction: post-hop unknown → release *with the content withheld from the agent* (evidence-only), pre-hop unknown → review | Closest to the proposal's "evidence-only" option; more plumbing | Caps ASR exposure while not zeroing the task |

Precondition for any choice: **measure the real benign denial rate by reason first** (R2.1, LLM-free). **Audit recommendation:** A immediately; decide between C and D after R2.1 numbers exist; treat B as an experimental variable, never a default.

## D-3 Should the classifier be allowed to gate tier-1 (read) tools?

**Why it blocks:** R2.7. `risk = p × impact` auto-allows every tier-1 call for p < 1.0; all 44 tier-1 tools are reads — the post-hop injection carriers. Inherited from the proposal's `confidence × impact`.

| Option | Trade-off | ASR / BU implication |
|---|---|---|
| A. Keep: tier-1 never reaches review via the classifier; structural override does the work; state it as a deliberate policy ("low-impact tools are never classifier-gated") | No change; honest; the classifier is then irrelevant to post-hop injected content by design | ASR on NL attacks ≈ unchanged from parser-only; thesis must say the classifier gates only side-effecting calls |
| B. Per-impact thresholds `t[impact]` with `t[1] < 1` | Lets the classifier review reads; **without a reviewer every read result above `t[1]` is denied** → BU collapses (CR §(d)) | Only viable with D-2 (C/D) or D-11 |
| C. Re-key post-hop risk on the *downstream* tool's tier (the action the content could trigger) rather than the read tool's tier | Semantically right; needs lineage / lookahead that does not exist (step 1.3+) | Future |

**Audit recommendation:** A for FYP-I measurements, documented as a design decision and reported as a limitation; B only as an experiment paired with D-2 C/D; C recorded for FYP-II. Also fix the inconsistent tiers (`get_unread_emails` tier 5 vs other mail reads tier 1).

## D-4 Decision representation: scalar risk or evidence vector?

**Why it blocks:** R2.8. Today `risk_score` and `contains_adi` collapse structural evidence, probability, impact and completeness; `confidence` is a copy of `classifier_score`.

| Option | Trade-off |
|---|---|
| A. Keep scalar `risk` + `review_reasons` tuple (status quo) | Simple to report; hides evidence quality; S inert |
| B. Evidence vector `(structural_evidence, p, margin/uncertainty, evidence_completeness, impact, direction)` with a policy table → `{allow, review, deny, unknown}`; scalar kept only for display | Cannot hide a critical violation behind benign mass; unknown first-class; policy table must be authored and justified; harder to summarise in one number (report per dimension) |

**Audit recommendation:** B, built incrementally on the existing `review_reasons` (it is already a proto-vector). This is the user's proposed decomposition and the audit found it supported.

## D-5 Do structural findings stay in the graph?

**Why it blocks:** R2.10, R4.2. `finding:*` nodes make the classifier re-learn Stage 1 (M2); any joint reporting double-counts.

| Option | Trade-off | Implication |
|---|---|---|
| A. Keep finding nodes; always run and report the finding-node ablation | Classifier may look good for the wrong reason; ablation exposes it | Must never report structural and classifier detection as independent |
| B. Remove finding nodes; fuse Stage 1 and classifier only at the decision layer | Clean independence; classifier must find its own signal (requires real provenance, D-8) | Honest test of the thesis hypothesis |

**Audit recommendation:** B for the hypothesis test; A acceptable as an engineering ensemble *if* reported as such.

## D-6 What does `flagged` mean?

**Why it blocks:** R2.2, R2.3; FPR/FNR are undefined until this is fixed (S7).

Choices to make explicitly: per call or per task; detector verdict, classifier label, or policy block; how review-tier denials without a reviewer are labelled; whether `contains_adi` (which can be True on an auto-allowed call) is renamed or aligned with the decision. **Audit recommendation:** `flagged` = "the system changed the agent's observed trajectory for this call" (deny or withhold), reported per call *and* aggregated per task; `contains_adi` renamed to `detector_signal`; a separate `denial_reason`.

## D-7 Target false-positive rate and the benign corpus it is measured on

Needed for R2.5 (rule weights), R4.7 (over-defense set) and for any claim about utility preservation. The Phase-2 log raises the base-rate concern; no target exists. **Audit recommendation:** state a per-call FPR target per format (JSON results; text results) measured on the hard-benign set plus replayed AgentDojo benign traffic (R2.1), and report task-level BU alongside.

## D-8 Contribution framing and scope

**Why it blocks:** R4.1, R4.3, R4.4; what the thesis claims.

Sub-decisions:
1. **Claim**: "no published defense separates content-trust from provenance-trust at field level" (overstated vs CaMeL/FIDES) → "a retrofit, framework-external provenance monitor evaluated on the security / utility / reviewer-load trade-off, plus a field-level graph classifier *if* shown to add information". Note the reviewer's point that "framework-external" alone is not distinctive (Progent, MELON, Task Shield, tool-filter baselines, arXiv:2601.04795 are also external monitors); the field-level graph is.
2. **Classifier claim** (proposal §6.5 "catches structurally clean but adversarial content"): currently unsupported by the representation (M1). Options: (a) keep the claim and enrich the graph (role, lineage, length buckets, cross-message edges) then test it; (b) scope the classifier to structural/flow anomalies and drop the claim.
3. **Scope**: the proposal excludes multi-hop / cross-call trust, but RunState lineage is exactly cross-call (M5). Admit it or keep per-message scope and drop downstream-harm claims.
4. **Threat model wording**: "tag forgery" → "forged content structure / untrusted-to-authority data flow" (M6).
5. **Citations to fix before reuse**: the CaMeL-strict-stops-ADI attribution is unsupported by the ADI abstract/README (verify in full text); arXiv:2602.11416 is mislabelled "PRUDENTIA"; cite Shervashidze et al. 2011 for WL; read arXiv:2601.04795.

**Audit recommendation:** 1 → reframe; 2 → (a) only if R4.2 shows signal, otherwise (b) with a clean negative result; 3 → admit cross-call lineage (it is what the design implements); 4 → reword; 5 → fix.

## D-9 Structural rule set questions

- **D-9a** Should `embedded_json` remain a counted rule? It is the dominant known FP source (benign quoted JSON scores 1.0) and a legitimate pattern in many tools; it also co-fires with `kv_forgery`. Options: counted / weak (logged) / counted only outside fields a profile marks as content. **Audit recommendation:** weak until per-field profiles exist.
- **D-9b** Argument trust (open from the tagging work): keep design decision 2 (USER→T by lineage match; DERIVED takes the worst source; UNLINKED → UT) or "every argument UT unless the TVM marks it trusted". Trade-off: the first keeps review load down for user-typed values but trusts substring lineage (evadable, L2); the second is TVM-only (a tool-level, not call-level, statement) and pushes every user-typed authority argument to review. **Audit recommendation:** keep decision 2 but *record* lineage status per argument so the thesis can report how often USER_MATCH was the reason for T.
- **D-9c** Redefine S (per-field max, deduplicated) before it is ever reported — yes/no. **Audit recommendation:** yes (R2.4); the current S must not appear as a "score" in the thesis.

## D-10 `RunState` / `DetectorContext` contract for step 1.3

**Why it blocks:** R3.2, lineage. Options: (A) extend the frozen `DetectorContext` with `run_id`, `interception_id`, optional `user_prompt` provider (defaults keep it backward-compatible; clone stays the single id owner); (B) give detectors ledger access (layering break); (C) caller-supplied RunState via closure in the detector factory (works today; ids still missing). **Audit recommendation:** A, with RunState per run inside the detector factory, cleared on run end. This is an additive clone change and falls under the Phase-2 rule (all clone tests must still pass).

## D-11 Human review: where it runs, and the protocol

**Why it blocks:** R3.5, R4.10, D-2 C. Today the reviewer callback runs inside a detector thread abandoned after 2 s; no reviewer exists; benchmarks will run without one, turning every review into a deny. Options: (A) detector returns `route=human_review`, executor suspends (architecture change); (B) long per-detector timeout, document it; plus a reviewer *stub policy* for benchmarks (always-allow, always-deny, evidence-only, or oracle) that is reported as a variable. Human Approval Accuracy needs N reviewers × M cases, blinding, with/without panel. **Audit recommendation:** A eventually; for FYP-I measurements, a declared stub policy and report "review-tier rate" instead of accuracy.

## D-12 Non-JSON, `None` and `Key: value` results

**Why it blocks:** R2.12. `"Balance: 100"` → `invalid_json` (never releasable); `None` → `'None'` → blocked; both are deliberate guards (YAML-ish text must not pass as prose). Options: narrow `_STRUCTURED_TEXT`; treat heuristic `INVALID_JSON` as `NOT_JSON` when a text schema is registered; special-case `None`/`NoneType` returns. Size it with R2.1 first. **Audit recommendation:** special-case `None` immediately; decide the heuristic after R2.1 numbers.

## D-13 DOM / Markdown formats in FYP-I?

**Why it blocks:** R2.11, R3.7, R1.9 priority. `md_flags`/`dom_flags` exist, are tested, FP on benign text, have a ReDoS, and are unreachable from the live pipeline; AgentDojo results are JSON/str, so they matter only for the ADI web benchmark the project does not run. Options: wire behind a format router with their own weights; or formally exclude from FYP-I claims and keep as FYP-II. **Audit recommendation:** exclude from FYP-I claims; fix the ReDoS anyway.

## D-14 E003: fixture or parser?

Plain prose: fixture says `invalid_json`, parser says `not_json`. The parser's taxonomy (`NOT_JSON` = prose, `INVALID_JSON` = looks structured but broken) is the more useful one and is what `usable` relies on. **Audit recommendation:** fix the fixture; keep the parser.

## D-15 Budget and credentials for provider-backed runs

R4.6 and R4.8 need API keys (local `.env` values are empty) and a cost estimate (97 user tasks; 629 security cases; several modes × detectors × models). Decide model(s), number of repeats (LLM nondeterminism), and which baselines to run. Without this, ASR and BU stay unmeasured; the LLM-free replay (R2.1) is the only metric-adjacent experiment available.

## D-16 Testing baseline

Add `src/parser` to `testpaths` (416 passed / 1 failed becomes the honest baseline) and commit or delete the 0-byte test files — trivial, but it changes what "all tests pass" means for the team. **Audit recommendation:** yes to both.
