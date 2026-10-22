# Clone: tool-call capture, hold, and release

This module captures an agent's proposed tool calls and tool observations before they are released. It gives a detector a copy to inspect, holds the original while the decision is pending, and then lets the AgentDojo adapter release the original unchanged or return a denial.

The clone is the source of detector payloads. The TVM and ledger provide classification context and audit records; they are not substitutes for the cloned payload and are not currently used by the parser to determine its structural score.

## What is implemented

- `core.py` is framework-agnostic. It handles capture, detector invocation with a timeout, enforcement modes, and release/block decisions.
- `adapters/agentdojo.py` is the AgentDojo adapter. It translates AgentDojo tool messages to core calls and translates verdicts back to tool result messages.
- `interceptor.py` preserves the old import path by re-exporting adapter/core names.
- `tvm.py` loads the read-only tool matrix. A lookup returns tool metadata, or a logged `unclassified` fallback for a missing tool/schema.
- `ledger.py` stores interception records, state-change events, raw payload snapshots, optional run metadata, and hash-chain fields.
- The parser bridge currently lives at `src/pipeline/clone_parser_detector.py`; pipeline stages and their handoff are described in [the pipeline README](../pipeline/README.md).

The clone package can be imported without loading AgentDojo. The AgentDojo executor is loaded lazily when `TrustVerificationToolsExecutor` is requested.

## Payloads and lifecycle

Each assistant message's calls are processed one at a time in framework order. A denial of one call does not skip later calls in that batch.

### Pre-hop: agent to tool

The adapter receives an AgentDojo `FunctionCall`, copies and normalizes its arguments with `_framework_args`, and asks the core to inspect the call. The normalized detector payload is:

```python
{"tool": "tool_name", "args": {"argument": "value"}}
```

The core resolves the tool against the matrix, captures the payload and canonical-JSON SHA-256 in the ledger, then passes a deep copy and frozen `DetectorContext` to the detector. The original call is held from tool execution until the detector decision returns. On allow, the adapter runs the original normalized arguments through AgentDojo's `FunctionsRuntime`; on block, it does not execute the tool and supplies a denial observation.

### Post-hop: tool to agent

The adapter formats the tool result as a string and asks the core to inspect it before returning it to the model. The ledger captures the exact string and hashes its UTF-8 bytes. The detector receives a copy; strings are immutable, so copying a string need not allocate another string object. The original observation is released unchanged only when permitted. Otherwise the adapter returns the denial observation.

`DetectorContext` contains direction (`"pre"` or `"post"`), tool name, tool-call ID, and the immutable matrix entry. It is trace/policy context; the parser bridge currently uses direction, tool name, and call ID, but does not use the matrix entry for schema validation or scoring.

## Detector contract

Both legacy one-argument detectors and context-aware detectors are supported:

```python
def legacy_detector(payload):
    return True

def contextual_detector(payload, context):
    # payload is a detector-owned deep copy
    # context.direction is "pre" or "post"
    return DetectorDecision(
        allowed=True,
        label="inspected",
        score=0.0,
        contains_adi=False,
    )
```

Detectors may return `True`, `False`, or `DetectorDecision`. A boolean maps to labels `"allow"`/`"block"` and does not report a score or ADI flag. `score=None` and `contains_adi=None` mean “not reported,” never “clean.” A detector requiring three positional arguments is rejected during core construction. Detector exceptions and timeouts fail closed in enforce mode; the model receives the generic text `Blocked: detector unavailable`, while the exception detail stays in the ledger.

## Modes

- `off`: bypass detector capture and ledger work; the AgentDojo adapter delegates to the original executor behavior.
- `passthrough`: run capture and detection but release calls/results regardless of the detector decision. Use for behavior-parity runs, not enforcement.
- `enforce`: release only allowed calls/results. Detector errors and unclassified tools fail closed.

## Matrix, ledger, and hashes

Load the matrix with `load_tool_matrix()`. The matrix records tool names, internal IDs, impact tiers, argument metadata, and expected keys. The checked-in tiers are policy defaults. A missing tool or schema gets an `unclassified` fallback and is blocked in enforce mode. Matrix metadata is included in detector context and records, but currently does not determine the parser score.

The ledger distinguishes:

- `sha256`: immutable hash of the payload captured at that interception. Pre-hop hashes use canonical JSON of the normalized `{"tool", "args"}` payload after `_framework_args`; post-hop hashes use the exact UTF-8 result string.
- `delivered_sha256`: hash of the observation actually delivered to the model. For released observations it equals `sha256`; for blocked post-hop observations or pre-hop denial-delivery records it hashes the denial text. It is `None` before delivery.
- `entry_sha256` / `prev_entry_sha256`: hashes linking ordered ledger state-change events. `verify_chain()` checks the in-memory chain; `import_ledger(path)` restores exported events for verification after reload.

Raw payloads and run metadata are exported separately from the event ledger:

```python
ledger.export_ledger("tvm-ledger.jsonl")
ledger.export_raw_payloads("tvm-payloads.jsonl")
ledger.export_run_metadata("tvm-run-metadata.jsonl")
assert ledger.verify_chain()
```

Run metadata can be supplied to the AgentDojo executor through `extra_args["_clone_tvm_run_meta"]`, for example suite, task, or attack identifiers. It is stored separately and is not passed to the detector. Raw payload exports may contain sensitive tool arguments and results; handle them accordingly.

## Use with AgentDojo

Run commands from the repository root. The project uses the benchmark virtual environment for AgentDojo integration:

```powershell
& .\llm-benchmark\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
& .\llm-benchmark\.venv\Scripts\python.exe -m pip install --no-deps -e .\agentdojo
```

Create and pass an explicit ledger and matrix:

```python
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop

from clone import InterceptionLedger, TrustVerificationToolsExecutor, load_tool_matrix
from pipeline.clone_parser_detector import parser_detector

ledger = InterceptionLedger()
executor = TrustVerificationToolsExecutor(
    parser_detector,
    ledger=ledger,
    tool_matrix=load_tool_matrix(),
    mode="enforce",
    detector_timeout_s=2.0,
)
pipeline = AgentPipeline(
    [
        SystemMessage("You are a helpful assistant."),
        InitQuery(),
        llm,
        ToolsExecutionLoop([executor, llm]),
    ]
)
```

The parser bridge is only the current detector callback. It does not yet assemble tagging, dependency-graph, WL-kernel, SVM, or human-review stages. See [the pipeline handoff](../pipeline/README.md) before implementing the next stage.

## Tests and validation

From the repository root, run the clone static suite:

```powershell
python -m pytest -q --durations=5 src\clone\test_static.py
```

Use `-s` to print the static tool-call comparison and ledger output:

```powershell
python -m pytest -s -q src\clone\test_static.py
```

Run parser unit tests separately:

```powershell
python -m pytest -q --durations=5 src\parser
```

These checks exercise static/local runtimes and parser fixtures. **The clone/parser integration has not been validated against Groq or a live Groq-backed AgentDojo run.** A live provider run, including parity and enforce-mode checks, is still required. The separate parser-bridge test module may also contain an older prose-policy expectation; reconcile it with `ParseStatus.NOT_JSON` before treating that module as green.

## Guidance for the next contributor or coding agent

1. Keep `core.py` framework-neutral; put AgentDojo-specific message/runtime handling in `adapters/agentdojo.py`.
2. Treat the detector payload as the cloned call/result to analyze. Do not substitute the ledger's audit snapshot or matrix entry for that payload.
3. Keep run metadata, TVM fields, and ledger internals out of detector payloads. Pass per-interception metadata only through `DetectorContext`.
4. Add detector stages in `src/pipeline`, not in clone core. Keep audit/hash updates additive and preserve the existing callback contract.
5. Before relying on provider behavior, add and run a Groq-backed AgentDojo integration test; static tests alone do not establish live-provider compatibility.
