# AgentDojo trust-verification interception

`TrustVerificationToolsExecutor` is an AgentDojo `ToolsExecutor` replacement. It intercepts each tool call before execution and each resulting observation before it is returned to the model. Multiple calls in one assistant message are processed in AgentDojo order.

From the repository root, install the test dependency and the local AgentDojo package into the benchmark venv:

```powershell
& .\llm-benchmark\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
& .\llm-benchmark\.venv\Scripts\python.exe -m pip install --no-deps -e .\agentdojo
```

Wire the executor into the normal AgentDojo pipeline:

```python
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from clone import DetectorDecision, TrustVerificationToolsExecutor

def detector(payload):
    # Inspect the supplied copy. Return True/False or DetectorDecision.
    return DetectorDecision(allowed=True, label="safe", score=1.0)

executor = TrustVerificationToolsExecutor(
    detector,
    mode="enforce",
    detector_timeout_s=2.0,
)
pipeline = AgentPipeline(
    [SystemMessage("You are a helpful assistant."), InitQuery(), llm,
     ToolsExecutionLoop([executor, llm])]
)
```

From the repository root, run the static checks in the benchmark virtual environment. `-s` displays the tool-call comparison, TVM records, and state-change ledger in the terminal:

```powershell
& .\llm-benchmark\.venv\Scripts\python.exe -m pytest -s -q src\clone\test_static.py
```

Modes:

- `off`: delegates directly to AgentDojo's original `ToolsExecutor`, without TVM records.
- `passthrough`: records both hops and calls the detector, but always releases the original observation (useful for parity runs).
- `enforce`: releases only allowed payloads; detector errors, missing decisions, and timeouts fail closed with a denial observation.

The process-global `TVM` holds metadata/state-change records and separately captures raw detector inputs. Each ledger line includes the state, hash, decision, label, and call linkage; export explicitly to keep raw data out of the ledger:

```python
from clone import TVM

TVM.export_ledger("tvm-ledger.jsonl")
TVM.export_raw_payloads("tvm-payloads.jsonl")
```

The raw payload export may contain sensitive tool arguments and outputs; protect it accordingly.
