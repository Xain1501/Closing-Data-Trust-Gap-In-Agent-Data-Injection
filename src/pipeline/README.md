# Pipeline: detector-stage integration and handoff

`src/pipeline` is the integration space for detector stages. It connects the framework-neutral cloned traffic supplied by `src/clone` to parser analysis and future tagging/classification stages. Keep stage orchestration and shared stage state here; keep framework interception and audit behavior in `src/clone`.

## Current implementation

Today this folder contains:

- `clone_parser_detector.py`: a detector callback that receives a cloned payload and `DetectorContext`, creates the parser's `ToolTraffic`, runs `parse()` and `structural_flags()`, and returns a `DetectorDecision`.
- `test_clone_parser_detector.py`: focused tests for the current bridge behavior. Check these tests when changing parser policy; an older expectation that plain prose is blocked may need reconciliation with `ParseStatus.NOT_JSON`.

The bridge currently returns only the final decision fields (`allowed`, `label`, structural `score`, `reason`, and `contains_adi`). It does **not** expose its `ParseResult` or `StructuralReport` to a subsequent stage, nor does it assemble a multi-stage detector.

The structural score is a deterministic heuristic, not a probability or SVM score:

```text
min(1, counted_structural_findings / parser_boundary_count)
```

The parser reports parse status separately. Plain prose with no counted structural finding is `NOT_JSON`, score `0`, and allowed by the current bridge. Malformed object/array JSON is `INVALID_JSON`, score `0`, and blocked as `parser-untrusted` without being labeled ADI. Valid structured payloads are scanned for counted structural findings; prose containing such findings is blocked as `adi-detected`.

## How clone supplies traffic

The AgentDojo executor in `src/clone/adapters/agentdojo.py` intercepts each call/result and invokes `InterceptionCore`. Core holds the original until the detector decision and passes the detector a deep copy:

- **Pre-hop:** normalized `{"tool": tool_name, "args": args}` dict, where the adapter has applied `_framework_args`.
- **Post-hop:** the exact formatted tool-result string.

The parser bridge receives that clone as its `payload` argument. The `DetectorContext` identifies `"pre"`/`"post"`, tool name, call ID, and matrix entry. TVM/ledger are for mapping, trace, and audit; parser scoring currently does not consume them. The ledger keeps its own raw-payload snapshot, which is separate from the detector's working copy.

Wire the current parser bridge into the AgentDojo executor as follows:

```python
from clone import InterceptionLedger, TrustVerificationToolsExecutor, load_tool_matrix
from pipeline.clone_parser_detector import parser_detector

ledger = InterceptionLedger()
executor = TrustVerificationToolsExecutor(
    parser_detector,
    ledger=ledger,
    tool_matrix=load_tool_matrix(),
    mode="enforce",
)
```

The bridge requires context; calling `parser_detector(payload)` without it raises `ValueError`. Existing one-argument detectors remain supported by clone, but this parser bridge specifically needs the contextual callback form.

## Next stage: field-by-field tagging

The next detector stage is tagging. Its input should be the **cloned pre/post payload**, not a replacement payload reconstructed from ledger state. The parser's structural score is an output of parser analysis that the pipeline can pass to later stages. Per the intended interface, tagging should inspect/tag each field of the cloned call/result and may consume the parser score, but it should not require the TVM/ledger or depend on a `ParseResult` being passed as its primary input.

The current callback does not yet implement that handoff: it parses the cloned payload internally, computes the score, and returns a single `DetectorDecision`. Before adding tagging to the full detector path, define a pipeline-owned result/state contract that carries at least:

1. **Clone input:** the deep-copied pre-hop dict or post-hop string plus `DetectorContext`.
2. **Parser stage output:** parse status, structural findings/report, and score.
3. **Tagging stage output:** field-level tags produced from the cloned traffic, associated with stable field paths and direction.
4. **Later analysis:** tool-dependency graph, WL-kernel representation, and SVM/classifier outputs.
5. **Final decision:** allowed/blocked, label, score(s), ADI result, and a reason that clone can record and enforce.

Keep this shared multi-stage state in `src/pipeline`, not `InterceptionCore`. Do not put parsed results, tags, graph state, or classifier implementation into the clone ledger. The ledger is the audit trail; the pipeline owns intermediate detector artifacts.

Suggested implementation sequence for the next contributor/agent:

1. Specify and test a pipeline `StageState`/result contract without changing clone's payload or detector callback semantics.
2. Add a tagging stage that consumes the cloned payload and parser score and emits field-level tags with path/direction metadata.
3. Add composition tests proving the same cloned traffic is passed through the stages and that the original stays held until the final decision.
4. Add graph/WL/SVM stages behind the same pipeline interface as they become available.
5. Add provider-backed AgentDojo integration tests after local fake/static tests pass.

## Testing and validation

Run from the repository root:

```powershell
python -m pytest -q --durations=5 src\clone\test_static.py
python -m pytest -q --durations=5 src\parser
python -m pytest -q --durations=5 src\pipeline\test_clone_parser_detector.py
```

The clone static tests cover interception lifecycle, ledger/hash behavior, matrix lookups, import isolation, and a fake/local AgentDojo runtime. Parser tests use fixed fixtures. These are **static/local tests only**: the integration has **not been tested with Groq** or a live Groq-backed AgentDojo pipeline. A Groq-backed run must still validate pre/post call behavior, model-visible observations, detector latency/timeouts, and `off`/`passthrough`/`enforce` outcomes.

The pipeline bridge test command may currently fail if its legacy assertion still expects ordinary prose to be blocked. Under the current `NOT_JSON` policy, clean prose is allowed. Update that expectation only when the test is reviewed against the intended parser policy; do not hide the mismatch by skipping the test.

## Handoff rules for AI agents and teammates

- Read `src/clone/README.md` for the interception API, mode behavior, hashes, TVM, ledger, and exports.
- Extend detector stages under `src/pipeline`; avoid coupling tagging to AgentDojo or clone internals.
- Treat the cloned payload as the detector's traffic input. The parser score is an analysis result; the ledger is audit-only for tagging.
- Preserve direction, tool name, call ID, and stable parser field paths through stages.
- A missing score/tag/classifier output means “not produced,” not “clean.”
- Do not claim live-provider compatibility until a Groq-backed AgentDojo integration run has passed.
