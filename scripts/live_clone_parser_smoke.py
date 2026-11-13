"""Run one real Groq-backed AgentDojo task through the Clone -> Parser bridge."""
from __future__ import annotations

import json
import os
import argparse
from datetime import datetime, timezone
from functools import partial
from hashlib import sha256
from pathlib import Path

from dotenv import load_dotenv

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

from clone import InterceptionLedger, TrustVerificationToolsExecutor, load_tool_matrix
from pipeline.clone_parser_detector import parser_detector


def main() -> None:
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument("--attack", action="store_true", help="Use the official workspace task 0 syntactic injection")
    args = arg_parser.parse_args()
    load_dotenv(".env", override=False)
    if not os.getenv("GROQ_API_KEY"):
        raise SystemExit("GROQ_API_KEY is missing from the environment/.env")

    model = "openai/gpt-oss-120b"
    suite = get_suites("v1.2.1")["workspace"]
    task = suite.user_tasks["user_task_0"]
    injections = task.INJECTED_DATA_SYNTACTIC[0] if args.attack else {}
    environment = task.init_environment(suite.load_and_inject_default_environment(injections))
    runtime = FunctionsRuntime(suite.tools)

    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_name = "attack_workspace_user_task_0_syntactic" if args.attack else "clean_workspace_user_task_0"
    storage_dir = Path("runs") / "live_clone_parser_smoke" / f"{run_stamp}_{run_name}"
    ledger = InterceptionLedger(storage_dir=storage_dir)
    formatter = partial(tool_result_to_str, dump_fn=json.dumps)
    llm = get_llm("groq", model, None, "tool")
    executor = TrustVerificationToolsExecutor(
        parser_detector,
        ledger=ledger,
        tool_matrix=load_tool_matrix(),
        mode="enforce",
        tool_output_formatter=formatter,
    )
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            llm,
            ToolsExecutionLoop([executor, llm]),
        ]
    )

    _, _, _, messages, _ = pipeline.query(task.PROMPT, runtime, environment)
    records = ledger.records
    restored = InterceptionLedger.import_ledger(storage_dir / "ledger.jsonl")
    persisted_raw = [
        json.loads(line)
        for line in (storage_dir / "raw-payloads.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    raw_post = {row["interception_id"]: row["payload"] for row in persisted_raw if row["phase"] == "post"}
    post_records = [row for row in records if row.phase == "post"]
    post_payloads_match_hashes = all(
        isinstance(raw_post.get(row.interception_id), str)
        and sha256(raw_post[row.interception_id].encode("utf-8")).hexdigest() == row.sha256
        for row in post_records
    )
    if not restored.verify_chain() or len(raw_post) != len(post_records) or not post_payloads_match_hashes:
        raise RuntimeError("Persisted post-hop payloads or reloaded ledger failed integrity checks.")
    summary = {
        "provider": "groq",
        "model": model,
        "suite": suite.name,
        "task": task.ID,
        "scenario": "official_data_only_syntactic_attack" if args.attack else "clean_baseline",
        "injection_vectors": sorted(injections),
        "mode": "enforce",
        "tool_interceptions": len(records),
        "pre_hop": sum(row.phase == "pre" for row in records),
        "post_hop": sum(row.phase == "post" for row in records),
        "persisted_post_hop_payloads": len(raw_post),
        "post_hop_payload_hashes_match": post_payloads_match_hashes,
        "durable_ledger_chain_valid_after_reload": restored.verify_chain(),
        "storage_dir": str(storage_dir),
        "decisions": [
            {
                "phase": row.phase,
                "internal_tool_id": row.internal_tool_id,
                "allowed": row.detector_decision,
                "label": row.label,
                "parser_score": row.score,
                "contains_adi": row.contains_adi,
                "error": row.error,
            }
            for row in records
        ],
        "final_assistant_message_present": bool(messages and messages[-1]["role"] == "assistant"),
        "ledger_chain_valid": ledger.verify_chain(),
    }
    (storage_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
