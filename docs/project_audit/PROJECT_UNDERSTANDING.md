# PROJECT UNDERSTANDING — "Closing the Data Trust Gap in Agent Data Injection"

Read-only research audit, 2026-11-15, branch `zain/experimental` (HEAD `66fec89`).
Sources: `docs/FYP-I_Proposal.docx` (text extracted via stdlib zipfile), `docs/FYP_Defense_Deck .pptx`,
`docs/tagging-design.md`, `README.md`, `src/{clone,parser,pipeline}/README.md`, `PROGRESS_LOG.md`
(local untracked log), and direct reading of the source under `src/`.

Classification legend used throughout: **Severity** (Critical / High / Medium / Low / Informational),
**Confidence** (Confirmed / Strongly supported / Hypothesis / Research-dependent),
**Type** (implementation defect / architectural issue / methodological concern / testing gap /
research opportunity / unresolved design decision). "Observation" = seen in files; "Interpretation" =
my reading of it; "Recommendation" = suggested action.

---

## 1. Research problem and motivation

- **Problem (proposal §1–§3).** LLM agents process tool outputs (emails, web pages, API responses)
  as flat text and have no formal mechanism to separate trusted instructions from untrusted data.
  *Agent Data Injection (ADI)* — introduced by Choi et al., arXiv:2607.05120 — is a structural
  sub-category of indirect prompt injection (IPI): instead of embedding explicit instructions, the
  attacker embeds forged delimiters/structure ("probabilistic delimiter injection") inside data
  fields so the model mis-parses attacker values as trusted metadata. Reported numbers the proposal
  relies on: 31.3–43.3% ASR on JSON, 33.3–100% on web DOM across six models; against SOTA defenses,
  instruction injection is nearly neutralized (0–0.7% ASR) but ADI still succeeds up to 50%.
- **Claimed gap.** Existing defenses either (a) let the LLM judge trust (prompting defenses,
  LLM-as-judge → same probabilistic weakness), or (b) constrain which tools are reachable
  (IPIGuard) without validating the data inside an allowed call. The proposal's central
  distinction: **content-trust** ("does this field look adversarial?") vs **provenance-trust**
  ("is this field's trust label authentic?"), claiming no published defense separates them at
  field level with a non-LLM detector (proposal §3, deck slide 4).
- **Scope** (proposal §4.2, deck slide 7): JSON tool responses primary; provenance forgery and
  structural mimicry at the tool-call boundary. Explicitly out of scope: memory/cross-session
  injection, unstructured prose injection outside the tagged-field model, vision vectors,
  multi-hop injection across sequential calls, MCP transport (deferred to FYP-II).

## 2. Research questions (reconstructed)

The proposal states one core question explicitly (§1, §3) and implies others:

1. **RQ1 (explicit):** Can provenance-based, deterministic (non-LLM) detection catch ADI-specific
   forgery without degrading benign-task utility? ("whether the isolation of Trusted and Untrusted
   data maintains Utility or degrades it using non-LLM detector", §3)
2. **RQ2 (implicit):** Is a field-level trust-provenance graph + WL-kernel + SVM a sufficient
   classifier for the residual (non-syntactic) attack signal?
3. **RQ3 (implicit):** Does a risk gate (confidence × impact) with tiered human review hold ASR
   down while keeping FPR and reviewer load acceptable?
4. **RQ4 (deliverables §12):** Does the detector over-flag benign content containing imperative
   language (the InjecGuard "over-defense" failure mode)?

## 3. Proposed methodology (proposal §6, §8)

Pipeline (both directions, pre-hop call and post-hop response):

```
clone (TVM id mapping) -> deterministic JSON parser (structural score S)
  -> tagging (Trusted/Untrusted per field) -> field-level trust-provenance graph (<T>/<UT>)
  -> WL kernel + SVM (classifier score C, Platt-calibrated)
  -> risk gate: confidence = 1-(1-S)(1-C); risk = confidence × impact (impact ∈ {1,5,10}, NIST SP 800-30 tiers)
  -> 3-tier policy: <1 auto-allow; 1–4.99 human review (allow/deny/evidence-only); ≥5 review with Allow stripped
  -> deterministic (no-LLM) evidence panel -> decision log
```

Key stated properties: the agent loop is untouched; all trust metadata is stripped before content
reaches the LLM; the classifier runs on *every* call/response ("content can be structurally clean
and still adversarial conveying intent through plain language", §6.5); the classifier has routing
authority only, never resolution authority (§7.2).

**Theoretical foundations.**
- *Weisfeiler–Lehman kernel*: iterative neighborhood label refinement; explicit histogram feature
  vector (avoids kernel matrix at inference, CPU-viable). Proposal cites Kim & Oh 2024
  (arXiv:2412.02181) — a generalization paper, not the canonical WL-kernel reference
  (Shervashidze et al., JMLR 2011).
- *SVM + Platt scaling* for a calibrated attack probability.
- *Provenance / taint tracking*: system-issued provenance tags at ingestion; adapted from
  IPIGuard's Tool Dependency Graph (arXiv:2508.15310) but re-targeted from call-to-call
  reachability to field-level trust within a single call.

**Evaluation criteria (proposal §6.8).** Primary benchmark AgentDojo (97 user tasks ×
629 security cases), supporting InjecAgent, plus a hand-written probabilistic-delimiter suite.
Metrics: Attack Success Rate, Benign Utility, Utility Under Attack, FPR, FNR, Human Approval
Accuracy. In AgentDojo's definitions: *benign utility* = fraction of user tasks completed
correctly with no attack present; *utility under attack* = fraction of (user task, injection
task) pairs where the user task still completes; *targeted ASR* = fraction of injection cases
where the attacker's goal condition is met in the environment. `src/pipeline/evaluation.py:66-77`
implements exactly these ratios from per-case JSONL rows.

## 4. Intended architecture vs repository layout

| Proposal stage | Repo location | Notes |
|---|---|---|
| Clone / interception + TVM | `src/clone/` (`core.py`, `adapters/agentdojo.py`, `tvm.py`, `ledger.py`, `tool_matrix.json`) | modes off/passthrough/enforce; hash-chained ledger |
| Deterministic parser + S | `src/parser/` (`parser.py`, `structural.py`, `dom_flag.py`, `md_flags.py`, `stage1.py`) | S = min(1, counted hits / boundaries) |
| Tagging | `src/trust_graph/tagging.py` (+ design doc `docs/tagging-design.md`) | two coexisting APIs, see §6 |
| Provenance lineage / RunState | `src/provenance/` | **empty** (`__init__.py` only) |
| Trust-provenance graph | `src/trust_graph/graph.py` | builds `GraphSnapshot` |
| WL + SVM classifier | `src/classifier/` (`wl_svm.py`, `train.py`) | machinery only, no trained artifact |
| Risk gate + review + evaluation | `src/pipeline/` (`risk_gate.py`, `classifier_gate.py`, `risk_detector.py`, `evidence_panel.py`, `evaluation.py`) | opt-in composed path |
| Benchmark harness | vendored `agentdojo/` (compsec-snu ADI fork), `llm-benchmark/` | third-party |
| Benchmark adapters | `benchmarks/` | directory exists, **no tracked files** |
| Test data | `tests/fixtures/` (phase1 100-case set, hand-made case files) | |

## 5. Implementation status per stage (observation, Confirmed)

| Stage | Status | Evidence |
|---|---|---|
| Clone/interception | Implemented + statically tested | `src/clone/core.py`, `test_static.py`; README warns: **never validated against a live Groq/LLM run** (`src/clone/README.md:153`) |
| TVM | Implemented; **all 105 field classes `unclassified`**, impact tiers "policy default" (44×tier1, 13×tier5, 13×tier10 over 70 tools) | `src/clone/tool_matrix.json`, `tvm.py:39-55` (fallback) |
| Parser + structural flags | Implemented + best-tested component (~106 parser tests; 100-case phase-1 set; 0/40 FP on AgentDojo benign; 15/15 delimiter forgeries; **0/20 NL attacks by design**) | `src/parser/README.md:109-131`, `PROGRESS_LOG.md` Phase 1 |
| Tagging (design-doc v2) | **Partial (step 1.2 WIP)**: post-hop profile tagging + argument roles; no lineage; no tests (`tests/unit/test_tagging.py` does not exist); not wired into pipeline | `src/trust_graph/tagging.py:1-14`, commit `66fec89` message ("Not done yet: tests...") |
| Tagging (legacy, in live path) | Implemented: top-level TVM class else default UT → with the current matrix **every field tags UT** | `tagging.py:273-281`, `risk_detector.py:46` |
| Provenance lineage / RunState | **Not implemented** (design only, tagging-design.md §4; `tests/unit/test_provenance.py` is 0 bytes) | `src/provenance/__init__.py` |
| Trust graph | Implemented (small): nodes = fields labeled `{trust}:{value_type}:depth=N`, edges = parent/child, plus structural-finding nodes | `src/trust_graph/graph.py:18-27` |
| WL + SVM | Implemented machinery (deterministic WL features, linear SVC, sigmoid calibration, save/load) — **never trained**: no `graphs.jsonl`, no `.joblib` artifact anywhere in the repo; `tests/unit/test_classifier.py` and `tests/fixtures/classifier_cases.json` are 0 bytes | `src/classifier/wl_svm.py`, `train.py` |
| Risk gate | Implemented, **with a changed formula** (see §6) | `src/pipeline/risk_gate.py:52-71` |
| Evidence panel | Implemented as a deterministic JSON packet; no UI, no reviewer integration | `src/pipeline/evidence_panel.py`, `risk_detector.py:58-76` |
| Evaluation metrics | Implemented calculator; **no evaluation JSONL exists** — ASR/utility have never been computed | `src/pipeline/evaluation.py` |
| AgentDojo integration | Executor + parser-only detector wired and smoke-run offline (`scripts/live_clone_parser_smoke.py`); composed risk path opt-in and unused; commit log notes 1 known failing test ("E003 baseline", commit `66fec89`) | `src/pipeline/README.md:162-178` |
| InjecAgent | **No trace in the repo** | PROGRESS_LOG Phase 0 table |
| Human review | Callback hook only; absent callback ⇒ review-tier cases are denied | `risk_detector.py:78-81` |

## 6. Execution flow as actually implemented

Two detector paths exist (`src/pipeline/README.md:59-61`):

1. **Parser-only (default, the one ever exercised):** `TrustVerificationToolsExecutor` →
   `parser_detector` (`clone_parser_detector.py`) → `analyze_clone_payload` → allow iff parse
   usable ∧ schema valid ∧ zero counted structural hits. Plain prose without a registered schema
   is blocked as `parser-untrusted` (`parser_analysis.py:24-34`). No tagging, graph, classifier,
   risk or review runs on this path.
2. **Risk-composed (opt-in, requires a trained model that does not exist):**
   `make_risk_detector(classifier)` → parse → `tag_fields(parse_result, field_trust_classes)`
   (*legacy* API; `risk_detector.py:46`) → `build_trust_graph` → `classify_and_assess` →
   `assess_risk` → reviewer callback or deny. `assess_risk` sets
   `confidence = classifier_score` and `risk = (classifier or 0) × impact`
   (`risk_gate.py:52-53`); any structural hit or missing classifier forces human review
   (`risk_gate.py:55-58, 68`); auto-allow requires risk < 1 ∧ no hits ∧ classifier present.

## 7. Four-layer distinction and discrepancies

### (a) What the research proposes
Bidirectional provenance-aware detection; system-issued trust tags whose *authenticity* is the
object of defense; field-level trust graph; WL+SVM on every message catching "structurally clean
but adversarial" content; `confidence = 1-(1-S)(1-C)`, `risk = confidence × impact`; tiered human
review; evaluation on AgentDojo + InjecAgent across six metrics.

### (b) What the documentation specifies
The READMEs and `docs/tagging-design.md` already *revise* the proposal without the proposal being
updated: the risk gate "does not treat structural density S as a probability … computes
`risk = classifier_probability * impact`" (`src/pipeline/README.md:61`) — i.e. the proposal's
confidence formula was abandoned (defensibly: S is a density, not a probability, and dilutes with
message size — PROGRESS_LOG Phase 2, Part A). The tagging design doc specifies a much richer model
than the proposal (5 provenance classes, roles, lineage via RunState, tool profiles with review
status) and leaves D1–D3 (result formatter, which AgentDojo copy, text-tool profiles) explicitly
undecided (`tagging-design.md:§11.5`). The parser README documents that wording-only attacks are
out of Stage-1 scope and that no ASR/utility exists yet (`src/parser/README.md:123-131`).

### (c) What the implementation currently does
Parser-only enforcement over cloned AgentDojo traffic, offline; legacy all-UT tagging; an
untrained classifier skeleton; a risk gate whose auto-allow branch can never fire in practice
(no trained classifier ⇒ `classifier_unavailable` ⇒ review ⇒ deny without a reviewer); step-1.2
tagging implemented but not wired and untested; no lineage; no live LLM run; no InjecAgent; no
evaluation data.

### (d) What the implementation can actually demonstrate today
- Deterministic Stage-1 detection of *syntactic* ADI on offline fixtures: 400/400 generated
  syntactic attacks, 0/82 benign FP (generator-derived, near-duplicate caveat documented);
  phase-1 set: 15/15 delimiter forgeries, 0/40 benign FP, 0/20 natural-language attacks,
  0/5 attacker tool calls (`PROGRESS_LOG.md` Phase 1 results; `src/parser/README.md:109-121`).
- Interception lifecycle, ledger hash-chain, enforce/passthrough semantics via static tests.
- Chain latency ~1–2 ms median on replayed traffic (throw-away measurement, Phase 2).
- **Not demonstrable:** any ASR, any utility number, any classifier metric, any human-review
  accuracy, any claim about provenance-trust vs content-trust separation, any live-agent behavior.

### Discrepancy register

| # | Discrepancy | Severity | Confidence | Type |
|---|---|---|---|---|
| D1 | Proposal risk formula `1-(1-S)(1-C)` vs implemented `classifier×impact` with S as separate evidence (`risk_gate.py:52-57`) — proposal/deck not updated | Medium | Confirmed | unresolved design decision (documentation drift) |
| D2 | Proposal: classifier runs on *every* message; implementation: classifier path is opt-in and has never run (no model) | High | Confirmed | implementation gap vs claim |
| D3 | Proposal's tagging (system vs human fields) vs TVM reality: all 105 field classes `unclassified` ⇒ every field UT ⇒ trust labels carry no information in the live path (`tool_matrix.json`, `tagging.py:279`) | High | Confirmed | implementation defect / methodological concern |
| D4 | Two tagging APIs coexist; the designed one (FieldTag/provenance/roles) is not connected to graph or classifier; graph consumes legacy `TaggedField` only (`graph.py:4`, `tagging-design.md:§6` "Compatibility") | Medium | Confirmed | architectural issue (transitional) |
| D5 | `src/provenance/` empty while proposal centers on provenance; lineage (the mechanism that would make `DERIVED→UT` meaningful) unimplemented | High | Confirmed | implementation gap |
| D6 | Evaluation metrics implemented but zero evaluation data; headline metrics (ASR, utility) unmeasured; InjecAgent absent | High | Confirmed | testing gap |
| D7 | Vendored AgentDojo (ADI fork, JSON result default) vs pip agentdojo 0.1.35 (YAML default) disagree; which copy runs depends on invocation; D1–D3 decisions open (`tagging-design.md:§11`) | High | Confirmed | unresolved design decision / reproducibility risk |
| D8 | Root `README.md` concatenates the project README with the upstream ADI-benchmark README (lines 339-573), including the upstream citation block — unclear provenance for a reader/evaluator | Low | Confirmed | documentation defect |
| D9 | Proposal deliverable "tag forgery detection": tags are internal side-records never serialized into payloads (`tagging.py:102-105` "Never stored in a tag: the raw value", design doc §2.4), so there is no attacker-reachable tag to forge; what is actually detected is forged *content structure* | Medium | Strongly supported | methodological concern (threat-model mismatch) |
| D10 | Impact-tier scale: with risk = C×impact and C ≤ 1, tier-1 tools can never reach moderate risk (C×1 < 1 except exactly 1.0); escalation for low-impact tools rides entirely on the structural-hit override | Low | Confirmed | architectural quirk |
| D11 | `benchmarks/` adapters directory promised in README is empty; `scripts/calculate_metrics.py` etc. described in README do not exist (actual scripts differ) | Low | Confirmed | documentation drift |
| D12 | Known failing test acknowledged in commit `66fec89` ("309 passed, 1 failed (known E003 baseline)"); pipeline README flags a legacy prose-blocking assertion needing reconciliation (`src/pipeline/README.md:178`) | Low | Confirmed | testing gap |

## 8. Identified gaps (summary)

1. **No end-to-end run with an LLM.** Every security number so far is parser-offline. ASR and
   utility — the project's success criteria — are currently unmeasurable. (Critical, Confirmed,
   testing gap)
2. **No classifier training data and no defined data-generation plan in code.** `classifier.train`
   expects labeled graph JSONL "from labeled project/AgentDojo runs" that nothing produces yet.
   (Critical, Confirmed, testing gap)
3. **Trust labels are degenerate.** Until the TVM field classes or the step-1.3 lineage land,
   the graph's T/UT dimension is constant (all UT), which guts the core hypothesis' testability.
   (High, Confirmed, methodological concern)
4. **Environment/format fork (D7)** blocks per-field tagging of real AgentDojo results and
   threatens reproducibility of anything measured.
5. **Human-review loop** exists only as a callback type; Human Approval Accuracy needs a protocol
   (who reviews, blinded how, how many cases) that no document defines.
6. **Utility-collapse risk**: in the current gate, any counted structural hit or classifier
   absence forces review, and absent a reviewer the call is denied — under AgentDojo this will
   translate benign FPs and all plain-text results without schemas directly into utility loss.
   Needs measurement, not speculation. (High, Strongly supported, methodological concern)
