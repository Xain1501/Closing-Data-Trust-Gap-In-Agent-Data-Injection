from importlib import import_module
from typing import Any

from .core import DetectorContext, DetectorDecision, InterceptionCore, InterceptionVerdict
from .ledger import InterceptionLedger, InterceptionRecord, LedgerEntry, RawPayload
from .tvm import ToolMatrixEntry, TrustMatrix, load_tool_matrix

__all__ = [
    "DetectorDecision",
    "DetectorContext",
    "InterceptionLedger",
    "InterceptionCore",
    "InterceptionVerdict",
    "InterceptionRecord",
    "LedgerEntry",
    "RawPayload",
    "TrustVerificationToolsExecutor",
    "ToolMatrixEntry",
    "TrustMatrix",
    "load_tool_matrix",
]


def __getattr__(name: str) -> Any:
    if name == "TrustVerificationToolsExecutor":
        adapter = import_module(".adapters.agentdojo", __name__)
        executor = adapter.TrustVerificationToolsExecutor
        globals()[name] = executor
        return executor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
