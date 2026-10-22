"""Explicit per-tool schemas for optional Stage 1 contract validation.

Schemas are keyed by tool name and traffic direction because a tool's request
arguments and response can have different shapes. No schema is inferred from
untrusted traffic; callers register trusted, code-owned Pydantic models or
types at startup.
"""
from __future__ import annotations

from typing import Any

try:
    from .models import ToolTraffic
    from .structural import check_schema
except ImportError:  # flat-folder layout
    from models import ToolTraffic
    from structural import check_schema


class ToolSchemaRegistry:
    """Registry of trusted schemas indexed by ``(tool_name, direction)``."""

    def __init__(self) -> None:
        self._schemas: dict[tuple[str, str], Any] = {}

    def register(self, tool_name: str, direction: str, schema: Any) -> None:
        if not tool_name.strip():
            raise ValueError("tool_name must not be empty")
        if direction not in {"pre_hop", "post_hop"}:
            raise ValueError("direction must be 'pre_hop' or 'post_hop'")
        key = (tool_name, direction)
        if key in self._schemas:
            raise ValueError(f"schema already registered for {tool_name!r} ({direction})")
        self._schemas[key] = schema

    def get(self, tool_name: str, direction: str) -> Any | None:
        return self._schemas.get((tool_name, direction))

    def validate(self, traffic: ToolTraffic):
        """Return structural schema findings, or an empty list if unregistered."""
        schema = self.get(traffic.tool_name, traffic.direction.value)
        return check_schema(traffic, schema) if schema is not None else []
