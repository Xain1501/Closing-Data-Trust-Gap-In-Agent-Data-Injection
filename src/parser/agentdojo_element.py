"""AgentDojo glue (SKELETON). Verified against agentdojo's BasePipelineElement:
    query(query, runtime, env, messages, extra_args) -> same 5-tuple.

Place this element TWICE in the pipeline:
    ... LLM -> [DetectorElement(PRE_HOP)] -> ToolsExecutor -> [DetectorElement(POST_HOP)] -> LLM
AgentDojo's default tool output is YAML, so build the executor with a JSON formatter:
    ToolsExecutor(tool_output_formatter=lambda r: tool_result_to_str(r, dump_fn=json.dumps))
"""
from __future__ import annotations

from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement

from models import DecisionLogRecord, Direction, ToolTraffic
from parser import parse
from structural import structural_flags


class DetectorElement(BasePipelineElement):
    def __init__(self, direction: Direction, log: list[DecisionLogRecord] | None = None) -> None:
        self.direction = direction
        self.name = f"detector_{direction.value}"
        self.log = log if log is not None else []

    def _process(self, traffic: ToolTraffic) -> None:
        result = parse(traffic)
        report = structural_flags(result)
        self.log.append(DecisionLogRecord(traffic=traffic, parse=result, structural=report))
        # TODO(Members 2/3): tag -> graph -> classifier -> risk gate -> human review

    def query(self, query, runtime, env=None, messages: Sequence = (), extra_args: dict | None = None):
        extra_args = extra_args or {}
        if not messages:
            return query, runtime, env, messages, extra_args

        if self.direction is Direction.PRE_HOP:
            last = messages[-1]
            if last["role"] == "assistant" and last.get("tool_calls"):
                for call in last["tool_calls"]:                      # clone, don't mutate
                    self._process(ToolTraffic(direction=self.direction, tool_name=call.function,
                                              tool_call_id=call.id, payload=dict(call.args)))
        else:
            for msg in reversed(messages):                           # trailing tool messages
                if msg["role"] != "tool":
                    break
                text = "".join(b["content"] for b in msg["content"] if b["type"] == "text")
                self._process(ToolTraffic(direction=self.direction, tool_name=msg["tool_call"].function,
                                          tool_call_id=msg["tool_call_id"], payload=text))

        return query, runtime, env, messages, extra_args   # original stays untouched (8.7)
