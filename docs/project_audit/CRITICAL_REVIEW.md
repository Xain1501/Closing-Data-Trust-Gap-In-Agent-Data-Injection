# Critical Review of the Six Audit Reports

Reviewer: independent critical reviewer. Date 2026-11-15. Branch `zain/experimental` (verified). Read-only: this is the only file created.
Reviewed: PROJECT_UNDERSTANDING (PU), RESEARCH_CRITIQUE (RC), STRUCTURAL_POLICY_RESEARCH (SP), ARCHITECTURE_AUDIT (AA), IMPLEMENTATION_AUDIT (IA), TESTING_AND_VALIDATION (TV), PERFORMANCE_AND_SECURITY_NOTES (PS).
Probes: scratch scripts `cr_probe1..6.py` in the session scratchpad (outside the repo), run with `.venv` Python, `sys.path` -> `src`. Verdict legend: UPHELD / UWC (upheld with correction) / DOWN (downgraded) / REJECTED.

Headline: the factual observations in the reports are overwhelmingly correct and reproducible. The problem is severity inflation (23 of 43 Critical/High rows are downgraded) and a few over-generalised or unsupported claims. Nothing was found to be fabricated, but one literature claim is unsupported (Sec. e).

## (a) Verdict table (Critical/High findings, plus all SP s4-s9 and s12 items)

| # | Report / id | Claim | Verdict | Evidence checked | Corrected severity |
|---|---|---|---|---|---|
| 1 | SP D1 (Critical) | S=0, clf=0.99, impact=1 -> auto_allow; tier-1 tools never reach review via classifier | UWC | Probe: `assess_risk(0,0.99,1)` -> risk 0.99, low, auto_allow, reasons (). `risk_gate.py:53,59,68`. With one structural hit -> human_review. Fact true. But (i) the same property follows from the proposal's own `confidence x impact` with NIST low tier, so it is inherited design, not a coding slip; (ii) composed path has never run, no model exists; (iii) the report UNDER-states the consequence: all 44 tier-1 tools are read tools (probe of `tool_matrix.json`: get_received_emails, read_inbox, get_webpage, read_channel_messages ...), i.e. exactly the injection-carrying post-hop results. The gate keys post-hop risk on the read tool's tier, so the classifier can never gate injected content. Also inconsistent tiers: `get_unread_emails` is tier 5, other mail reads tier 1. | High (design/methodology). Critical rating contradicts PU D10 (Low), AA F-14 (Low), IA F-21 (Info) |
| 2 | SP D2 (High) | Tier-10 auto-allows up to p=0.0999 | DOWN | Probe: 0.09*10=0.8999999999999999 allow; 0.1*10=1.0 review. This is a strict (conservative) cut, not a hole; "operating point unknown" is the real point and is a calibration/untuned-threshold issue | Medium |
| 3 | SP D4 / s3.2.3 / W4 (Critical); RC F1/A4/L1 (Critical); IA F-4 (High); AA F-03 (High); PU D3 | All fields tag UT, graph carries no provenance; WL-SVM sees only shape + finding nodes; NL-injected and benign messages give identical features | UWC | Probe cr_probe3: WL features of benign vs "ignore previous instructions..." email are IDENTICAL (True), also for a 5000-char body, both 0 hits. `graph.py:18`, `tagging.py:273-281`, matrix 105/105 "unclassified" (reports' count). Correct and the single most important finding. Correction: it is the known WIP step 1.2/1.3 (commit 66fec89, design doc), so "implementation defect" is wrong framing; the Critical applies to the claim-vs-mechanism gap (proposal s6.5 says the classifier catches structurally clean attacks), not to the code state. Seven report entries share this root cause | Critical for RC A4 claim-level; High as implementation status |
| 4 | SP D6 (High) | One forged string counted 4x, S diluted | DOWN | Reproduced (4 hits). But SP s2.2 itself states S magnitude never affects a decision (`risk_gate.py:57`, `clone_parser_detector.py:43-48`), and README says S is not combined. Inert today | Medium (latent) |
| 5 | SP D7 (High) | md/dom scorers not wired | DOWN | True (AA F-07). AgentDojo suite results are JSON/str; DOM/markdown matter only for the ADI web benchmark, which the project does not run | Medium |
| 6 | SP D8 (High for utility) | Unclassified tool blocked after detector allow | DOWN | `core.py:122-126` as described. But probe cr_probe4: all 74 tool instances in vendored AgentDojo v1.2.1 suites resolve in the matrix (0 missing). Only matters for future/other suites | Low |
| 7 | SP D9 (Medium) | 0.199999*5 allows, 0.2*5 reviews | DOWN | Reproduced (0.999995 vs 1.0). Every threshold is discontinuous; p resolution 1e-6 is irrelevant | Informational |
| 8 | SP W1 (High) | S measures density, not evidence | DOWN | Dilution reproduced (my payload: 0.50 alone, 0.056 in 10 emails, 0.011 in 50; SP's 0.0755/0.0158 depend on payload). Valid, but inert for decisions (row 4). Note this is the very reason the team replaced `1-(1-S)(1-C)`; SP gives that little credit | Medium |
| 9 | SP W2 (High) | One scalar conflates forgery / unreadable / no profile | UPHELD | `structural.py:141-143` S=0 for non-OK statuses; all map to deny | High (keep; design-level) |
| 10 | SP W3 (High) | Zero-tolerance, unweighted rules | DOWN | True; measured FP only 2/54 (SP's own number). `embedded_json` as dominant FP: reproduced (benign `{"note":"{\"a\":1}"}` -> S=1.0, 2 hits) | Medium |
| 11 | SP W5 (High) | Finding nodes in graph make classifier circular with Stage 1 | UPHELD | `graph.py:21-26` adds `finding:*` nodes; duplicates RC M1 | High (conditional on a trained model) |
| 12 | SP W6 (High) | Impact tiers are "policy fiction" | DOWN | Loader requires `"policy default"` (`tvm.py:72-73` per SP) -- this is an honesty guard, not a defect. Tiers unvalidated, yes | Medium |
| 13 | SP W7 / s9.2 item 1 (High) | 13% non-JSON benign traffic is blocked unless the adapter passes str schemas -> utility ceiling | DOWN | `adapters/agentdojo.py:95,131` ALREADY passes `definition.parameters` / `definition.return_type`. Probe: `get_webpage`, str schema, "Welcome to Zurich ..." -> allowed. Blocked: "Balance: 100", "Error: -1" (INVALID_JSON), and (new, see Sec. g) None-returning tools. Open question SP 14.5 is partly answered by the code. 13% (PROGRESS_LOG.md:338, verified exists) is a non-JSON share, not a denial rate | Medium; actual denial rate unmeasured |
| 14 | SP s3.2 "OOD graph -> p=0.5000 label=attack, no abstain" | Classifier calls unknown graphs attack | REJECTED (as stated) | Reproduced 0.5/attack only on SP's symmetric 6/6 toy set. With 10 benign/4 attack: OOD p=0.43 benign; 4/10: 0.57 attack. It is the class prior plus an argmax tie-break at exactly 0.5. The valid residual point "no abstain option" stands | Low |
| 15 | SP s1.8 dilution probes | S: 0.50 vs 0.0755 etc.; prose forged S=1.0 | UPHELD | Direction reproduced; absolute numbers differ by payload; SP "hits=2" for prose vs my 4 for the same string (unreproduced) | n/a |
| 16 | SP s8.3 "artificial improvement" hypothesis | ASR drop may come from accidental denials | UWC | Sound as hypothesis and the reason-breakdown test is the right control. Correction: the "unclassified tool" source is ~0 for stock suites (row 6); the live sources are parser-untrusted (None-return, "Key: value" text), no-reviewer denials and pre-hop denials | Medium (hypothesis) |
| 17 | SP D3 (Medium) | `contains_adi` disagrees with decision | UPHELD | `risk_detector.py:107` | Medium |
| 18 | RC A1 / F6 (High) | Contribution overstates gap vs CaMeL/FIDES | UWC | CaMeL/FIDES real (Sec. e). Fair on the "no published defense" wording. Correction: RC states the ADI paper reports CaMeL-strict fully stops ADI; neither the arXiv abstract (it says ADI "easily bypasses existing IPI defenses") nor the vendored README (`README.md:504` only lists `camel_secpol_strict`) supports it | Medium |
| 19 | RC A2 / F7 (High) | "Tag forgery" threat model mismatched | DOWN | Tags are side records (design doc 2.4, `tagging.py` per RC). Fair semantic critique, but the ADI paper's threat ("data disguised as trusted") is what the parser addresses; a wording/framing issue | Medium |
| 20 | RC A4 / F1 / L1 (Critical) | Graph cannot separate NL attack from benign | UPHELD | Empirically confirmed (row 3) | Critical (claim-level) |
| 21 | RC A5/F4 (High) | TVM classes all unclassified | UPHELD | duplicate of row 3 | High |
| 22 | RC F2 (Critical) | ASR/utility never measured | DOWN | True but a project-status fact at a WIP commit, not a defect. Note SP s8 correctly defines the metrics | High |
| 23 | RC F3 (Critical) | No training data, artifact, 0-byte tests | DOWN | True (TV s2.4); status | High |
| 24 | RC F5 (High) | Lineage unimplemented | UPHELD | `src/provenance` empty; planned step 1.3 | High (status) |
| 25 | RC F8/M7; AA F-01; PS D1; PU D7; IA F-3 (High) | Dual AgentDojo copies decide formatter | UWC | pip default: `tool_result_to_str({"balance":100})` -> Python repr (probe). Correction 1: PS says "64 of 82 files differ"; after CRLF normalisation I get 38 differ / 30 same / 14 missing (probe cr_probe6). Correction 2: IA says the smoke script is safe because it passes `dump_fn=json.dumps`; under the pip copy `tool_result_to_str({"balance":100}, dump_fn=json.dumps)` STILL returns `"{'balance': 100}"` (no dict branch), and 18 of 74 suite tools return `dict[...]` | High |
| 26 | RC F9/L4 (High) | Fail-closed utility loss | DOWN | See row 13 | Medium |
| 27 | RC F10/M1/M2 (High) | Label leakage / contamination | UPHELD | conditional on a classifier existing | High (conditional) |
| 28 | RC L2 (High) | Lineage v1 = substring matching | DOWN | documented limitation of an unimplemented v1 | Medium |
| 29 | RC L3 (High) | Single-message graphs vs excluded multi-hop scope | UPHELD | genuine internal contradiction of scope | High |
| 30 | RC L7 (High) | No adaptive attacker | DOWN | future-work item, not a defect | Medium |
| 31 | IA F-1 (High) | Nested extra=forbid dropped | DOWN | Reproduced: `check_schema` -> [] for nested forbid; top-level -> unexpected_key. But pydantic default (extra ignore) also yields [], and AgentDojo models are default; only explicitly-forbidding nested models are affected | Medium |
| 32 | IA F-2 (High) | "Balance: 100" -> invalid_json | DOWN | Reproduced for 'Balance: 100', 'Note:', 'Error: -1', 'Status: true'. Real, but prevalence unmeasured, and `_STRUCTURED_TEXT` is a deliberate guard for YAML-ish output (see Sec. f) | Medium |
| 33 | IA F-3 (High) | pip copy -> repr/unparseable | UWC | see row 25 | High |
| 34 | IA F-5 (High) | Review callback inside 2 s detector thread | DOWN | Default 2.0 confirmed; but `detector_timeout_s` is a constructor argument and no reviewer is wired anywhere. Design smell, not a broken feature | Medium |
| 35 | AA F-02 (High) | Pipeline never assembled | UPHELD | `risk_detector` used only by tests | High (status) |
| 36 | AA F-06 / TV F-02 (High) | 107 parser tests not collected | DOWN | Config drift; tests pass when run (107 passed per baseline). Correct finding, over-rated | Medium |
| 37 | TV F-06 (High) | `src/detector`, `src/provenance` empty | UPHELD (dup of row 24) | | High (status) |
| 38 | TV F-07 (High) | New tagging API untested | DOWN | Team states "not done yet" in commit message | Medium |
| 39 | TV F-10 (High) | Classifier never trained/evaluated | UPHELD (dup of row 23) | | High |
| 40 | TV F-12 (High) | No offline end-to-end test | UPHELD | | High |
| 41 | TV F-13 (High) | Stale ignored results file, empty benchmarks/ | DOWN | `phase1_run.json` is a git-ignored local artefact | Medium |
| 42 | PS P1 (High) | Ledger persistence O(n^2) | DOWN | Mechanism clear (`ledger.py:334-352`); only with `storage_dir`; affects overhead reporting, not security or metrics validity. Good point re `detector_latency_ms` scope kept | Medium |
| 43 | PS S1 (High) | Lone surrogate crashes executor | DOWN | Reproduced (`UnicodeEncodeError` from `check_result`). Narrow: post-hop JSON-formatted results are `ensure_ascii` escaped, so only raw `str`-returning tools or odd args reach it. Availability only, nothing released | Medium |

Counts: UPHELD 13, UWC 6, DOWN 23, REJECTED 1 (total 43; multi-report duplicates counted once).

## (b) Duplicates to merge

1. All-UT / provenance-constant: SP D4, s3.2.3, W4; RC A4, A5, F1, F4, L1; IA F-4; AA F-03; PU D3, D4. One finding (the NL-identical-graph probe is the proof).
2. Dual AgentDojo copy: RC F8, M7; AA F-01; PS D1; IA F-3; PU D7; TV F-09. One finding.
3. Parser tests not collected + 0-byte test files: AA F-06; TV F-02, F-03; IA F-12.
4. Review callback in detector thread / thread leak / timeout: IA F-5, F-13; AA F-05; PS P3, S3. Two aspects (human latency vs leak) of one design.
5. Ledger quadratic persistence: AA F-04; IA F-20; PS P1.
6. No end-to-end / no training data / no metrics: RC F2, F3; TV F-10, F-12, F-13; AA F-02; PU D2, D6, Gaps 1-2.
7. Lineage unimplemented: RC F5; TV F-06; PU D5.
8. Risk formula change / tier-1 behaviour: RC M3, F11; PU D1, D10; AA F-14; IA F-21; SP D1, D2, D9, D10.
9. S dilution: SP D6, W1, 1.8; PU Phase-2 refs.
10. Fail-closed utility: RC L4, F9; SP W7, D8, 9.2; PU Gap 6.
11. WL cited via Kim & Oh: PU s3 and RC F17.
12. Dead `except ValidationError`: SP D5 = IA F-14 (and IA F-1 shows the same lost nested handling).
13. Duplicate-key finding path / graph attachment: SP D13, AA F-15, IA F-7.

## (c) Contradictions and resolutions

| Topic | Conflict | Resolution |
|---|---|---|
| Severity of tier-1 behaviour | SP Critical; PU "Low"; AA "Low"; IA "Informational" | Same code fact. High (design). The reports that rated it low missed that tier-1 = all read tools (post-hop carriers); SP missed that it is inherited from the proposal formula. |
| Any Critical? | IA: "Nothing was rated Critical"; SP/RC list several | IA is right for implementation defects; the Critical items are claim-level (RC A4) or status. |
| Smoke script safe? | IA F-3 says safe with `json.dumps`; AA F-01 says the smoke script "mitigates" | Wrong for dict returns under pip copy (probe). |
| AgentDojo copy diff size | PS: 64 of 82 differ | 38 differ after line-ending normalisation (PS did normalise only three files). |
| Non-JSON handling | SP s9.2 "denied unless adapter passes str schema" vs IA/AA stating adapter passes schemas | The adapter passes `return_type` (`agentdojo.py:131`); SP is incomplete. |
| Test baseline | TV "416 passed"; baseline 309+1 | Compatible (310 + 107 = 417 tests). |
| Parser test count | TV "106 vs 107" doc drift | Immaterial. |
| S in gate | SP s1.6/2.2 ("no threshold on S") vs SP W1 High | SP's own s2.2 shows S is inert, so W1 cannot be High. |
| Plain prose | SP README contradiction 3 not rechecked by me | Unverified. |

## (d) Challenge to recommendations (SP s10-s13, RC s5-s7)

**Defensible and low-distortion**: SP 12.1 (wire real provenance first), 12.4/10.1 (dedupe, per-field max: no ASR effect), 12.6 (define `flagged`), 8.3/13.6 denial-reason breakdown (the best idea in the set; it directly protects ASR from accidental-denial inflation), calibration with held-out split, provenance-shuffle ablation (13.3), structural-node ablation (circularity).

**Distortion risks**
- 11.3.2 `t[1] < 1` (review tier-1): every read tool then routes to review; with no reviewer = deny. Benign utility collapses unless a reviewer model exists. SP's table says "slight down"; that is under-stated.
- 11.3.3 "UNKNOWN -> allow read-only": read-only tools are the injection carriers (row 1), so this raises ASR and would be cited as a utility win. Any UNKNOWN policy must report ASR and utility with and without it.
- 10.3 per-tool conformal thresholds: AgentDojo has 97 user tasks across 4 suites, so a handful of benign results per tool; exchangeability across tasks is dubious; calibrating on the same tasks later used for utility is leakage. Infeasible at tool granularity; per-format at best.
- 11.3.4 stacking / 11.3.5 Bayesian priors: need end-to-end labelled runs and an agreed prior; neither exists. 10.6 Dempster-Shafer adds concept load with arbitrary masses; poor value for an FYP.
- 11.2 cost-sensitive thresholds: SP admits no costs exist; recommendation is not actionable without inventing them (new arbitrary constants replacing old ones).
- 10.4 per-field relaxation: SP flags the attack-surface opening; fine, but it needs a benign corpus per field that does not exist.
- RC s5.1 (EXTERNAL -> AUTHORITY_ARG => review): AgentDojo user tasks legitimately flow email/web content into arguments (e.g. "reply to the sender", "book the hotel named in the file"); this rule will heavily deny benign tasks and rests on substring lineage, which RC L2 itself calls evadable. Not discussed.
- RC E4 (compare vs CaMeL/Progent/IsolateGPT in-repo): "cheap" is wrong; needs paid LLM API runs.

**Feasibility of the validation plan**: SP 13.1-13.5, 13.7 (offline parts), 13.8 and 13.9 are feasible with existing fixtures. 13.6 and RC E0/E3/E4/E6/E7 need provider-backed runs; `.env` keys are empty (PS S7), `benchmarks/` is empty, no trained model, and 629 security cases x model cost is non-trivial. A feasible intermediate that neither report proposes: replay AgentDojo ground-truth calls (as `build_phase1_cases.py` does) through the adapter in enforce mode with no LLM to measure the real benign denial rate by reason.

**"Overstates the gap" fairness**: Largely fair on wording ("no published defense separates ...": CaMeL/FIDES attach provenance/integrity labels per value). RC does acknowledge the retrofit angle and recommends it as the defensible claim, so it is not ignored. But RC treats retrofit as clearly novel; Progent, MELON, Task Shield, tool-filter baselines, and the tool-result-parsing paper (arXiv:2601.04795) are also external/retrofit monitors, so "framework-external" alone is not distinctive; the field-level graph classifier is. RC also lists the sources of its CaMeL-strict claim as "README and third-party summaries" while neither says it (Sec. e).

## (e) Citation check

| Cite | Result |
|---|---|
| arXiv:2601.04795 | EXISTS. "Defense Against Indirect Prompt Injection via Tool Result Parsing", Yu, Cheng, Liu, 8 Jan 2026. It proposes parsing tool results to give the LLM precise data and filter injected content, claims lowest ASR among compared methods; abstract describes LLM-facing parsing, not delimiter/structure forgery detection. Plausible prior art for the "parse tool results" idea; relation to the structural rule set unproven (full text not read). RC F16 "Research-dependent" is correctly hedged. |
| 2607.05120 | EXISTS. "Agent Data Injection Attacks are Realistic Threats to AI Agents", Choi et al., 6 Jul 2026. Abstract: ADI bypasses existing IPI defenses; recommends separating trusted/untrusted data; does NOT name CaMeL-strict as stopping ADI. RC's "ADI paper reports CaMeL-strict fully prevented ADI" is UNSUPPORTED by what I could verify (could be in the full text; not shown by README/abstract). Also PU/RC quote ASR numbers (31-43%, 50%) I did not verify. |
| 2505.23643 | EXISTS. FIDES, "Securing AI Agents with Information-Flow Control", Costa et al.; evaluated on AgentDojo. |
| 2406.13352 | EXISTS. AgentDojo. ar5iv s3.4 confirms: benign utility = "fraction of user tasks the model solves in the absence of any attacks"; utility under attack = fraction of security cases where user task solved; targeted ASR = "fraction of security cases where the attacker's goal is met". SP/RC definitions correct (arXiv abs page itself does not define them; primary PDF not machine-readable here). |
| 2604.23374 | EXISTS: NeuroTaint, "Ghost in the Agent", Cai et al. |
| 2607.24625 | EXISTS: APPA, recoverable IFC, Kravchenko et al. |
| 2602.11416 | EXISTS but MISLABELLED: it is "Optimizing Agent Planning for Security and Autonomy" (Kolluri et al.); RC calls it "PRUDENTIA". The name may be a system name inside the paper; unverified. |
| 2412.02181 | EXISTS: Kim & Oh, "Generalizing WL Kernels to Subgraphs"; RC/PU correct that it is not the canonical WL reference. |
| Others (2503.18813, 2506.08837, 2508.15310, 2502.05174, 2412.16682, 2403.14720, 2403.04960, 2410.22770) | Not fetched; IDs match papers I know; not verified here. |
| SP secondary links (emergentmind, alphaxiv) | Not checked; used only as locators by SP. |
| SP/PS CVE links | Not checked. |

No fabricated citations found; one unsupported attribution and one mislabel.

## (f) Steelman of the three most-criticised decisions

1. **Fail-closed on unknown.** In a security gate whose positive claim is "no injection reached the agent", an unreadable or unprofiled payload is exactly where a bypass hides (the parser bomb and the opaque-node design exist for this). `NOT_JSON`+schema acceptance and `_STRUCTURED_TEXT` are deliberate: a YAML-ish "key: value" body must not pass as prose. The ledger records labels (`parser-untrusted`, `unclassified`), so accidental denials are auditable rather than hidden. Reports gave this fair coverage of costs but little weight to the safety rationale; and they over-stated the cost (rows 6, 13: stock suites resolve fully, adapter registers return schemas).
2. **`risk = p x impact` replacing `1-(1-S)(1-C)`.** S is a density that provably dilutes with benign content (SP's own probe); feeding it into an arithmetic fusion would let a 50-email inbox hide a forged delimiter. The team's fix is the correct one: S never touches the number, and any hit independently forces review (`risk_gate.py:57`). Multiplying by impact is the proposal's NIST-style definition, and the classifier has "routing authority only" by design. SP D1/D2 treat the multiplication as a defect without crediting that it is the proposal's own and that the override preserves recall on the structural class. What reports rightly add: tier-1 exemption on read tools (row 1).
3. **Content-blind graph labels.** "Instruction words are never used" (`structural.py:4`) keeps the system deterministic, language-independent and immune to the over-defense failure of lexical detectors (InjecGuard), which is the project's differentiator and RQ4. Provenance in the graph is meant to come from tagging/lineage (step 1.2/1.3), not content. RC A4 correctly shows the current graph cannot separate NL attacks, but it presents a deliberate scoping plus WIP as "the single most important flaw in the research design"; it is a flaw in the claim (proposal s6.5), not in the stated design direction.

## (g) Audit coverage gaps

- **New finding (reviewer probe, cr_probe5):** tools returning `None` (7 of 74 suite tool instances, e.g. state-changing tools) format to the string `'None'`; with `return_type` NoneType or None the detector blocks the result (`parser-untrusted`), also for 'Balance: 100'-style text. Not in any report. Medium; confidence moderate (direct detector probe, not an end-to-end adapter run).
- No one measured the real benign denial rate by replaying ground-truth calls through the adapter without an LLM.
- No analysis of how a denial string returned to the LLM changes agent trajectory (retries, re-issuing calls), which affects both ASR and utility and is a measurement distortion in itself.
- Pre-hop vs post-hop impact semantics: tier belongs to the tool being called, but post-hop risk is about downstream actions; only touched indirectly.
- Reviewer-injection risk was noted (AA F-12); no analysis of denial text as an injection channel.
- The proposal .docx and PROGRESS_LOG.md were treated as sources without independent re-reading by the audits; SP relies on unrerun Phase-1/2 numbers (flagged as such).
- Vendored-fork specifics (ADI attacks, `data_only_syntactic`) never executed; no statement on ASR baseline.
- No license/data governance, no Windows-specific path issues, no concurrency test of the ledger under parallel suites.
- `.env` empty means any live-run plan needs credentials/cost estimates; none given.
- Severity method: reports use Critical/High loosely; no rubric tying severity to impact on the two research metrics.

## (h) Independent assessment of the structural policy / scoring methodology (<=300 words)

The structural stage is the one defensible, working piece: a deterministic, syntax-only detector with in-sample recall on delimiter forgeries, a small measured false-positive rate and no lexical features. Its weakness is the score, not the detector. S is a diluted rule-match count; the team already recognised this and decoupled it, so decisions currently rest on "at least one counted hit", a zero-tolerance rule. That is acceptable for a first measurement, provided S is never reported as a probability or a ranking.

The gate (`p x impact`, thresholds 1 and 5) is unvalidated arithmetic. Its worst property is not a bug but a policy gap: all 44 tier-1 tools are read tools, which are the carriers of injected content, so the classifier cannot influence the post-hop path at all. With no trained model, no real provenance labels (NL-injected and benign graphs have identical WL features, which I confirmed), and finding nodes feeding the classifier, the classifier layer cannot currently contribute evidence beyond the parser. Claims about ASR or utility from the composed path would be uninterpretable.

On the metrics: ASR and benign utility are correctly defined (AgentDojo s3.4). Their main threat is accidental denials, which the proposed denial-reason breakdown would expose. Fail-closed costs were somewhat over-estimated by the audits (stock suites fully mapped, return schemas registered) but real in specific places (None-returning tools, "Key: value" text, dict formatting under the pip copy).

Priority order I would defend: pin one AgentDojo copy and JSON formatter; run an LLM-free replay in enforce mode to measure the real denial rate by reason; wire real provenance; only then train and evaluate the classifier with provenance-shuffle and finding-node ablations; define `flagged`; treat UNKNOWN policies as experimental variables reported with ASR and utility together, not as improvements.
