import json
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suites


SUITE_VERSION = "v1.2"
SUITE_NAME = "workspace"

OUTPUT = Path(__file__).parent / "dataset" / "raw" / "agentdojo_candidates.json"


def main():
    suite = get_suites(SUITE_VERSION)[SUITE_NAME]

    print(f"Suite: {SUITE_NAME}")
    print(f"User tasks: {len(suite.user_tasks)}")
    print(f"Injection tasks: {len(suite.injection_tasks)}")
    print()

    vectors = suite.get_injection_vector_defaults()

    results = []

    for user_task_id, user_task in suite.user_tasks.items():

        try:
            # Uses AgentDojo's own mechanism for determining
            # which injection fields are actually visible
            # during correct execution of this user task.
            candidates = []

            # We reproduce the important logic here without
            # generating/running an attack.
            from agentdojo.attacks.base_attacks import BaseAttack

            # BaseAttack requires a target pipeline, so instead
            # temporarily use the underlying logic directly.
            from agentdojo.agent_pipeline.base_pipeline_element import (
                BasePipelineElement,
            )

            class InspectionAttack(BaseAttack):
                name = "inspection"

                def attack(self, user_task, injection_task):
                    return {}

            attack = InspectionAttack(suite, None)

            try:
                candidates = attack.get_injection_candidates(user_task)
            except Exception as e:
                print(f"[SKIP] {user_task_id}: {e}")
                continue

            if not candidates:
                continue

            entry = {
                "user_task_id": user_task_id,
                "user_task_prompt": user_task.PROMPT,
                "injection_vectors": [],
            }

            for vector_id in candidates:
                entry["injection_vectors"].append(
                    {
                        "vector_id": vector_id,
                        "default_value": vectors.get(vector_id, ""),
                    }
                )

            results.append(entry)

            print(f"[FOUND] {user_task_id}")
            for vector_id in candidates:
                print(f"    -> {vector_id}")

        except Exception as e:
            print(f"[ERROR] {user_task_id}: {type(e).__name__}: {e}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "agentdojo_version": SUITE_VERSION,
                "suite": SUITE_NAME,
                "user_task_count": len(suite.user_tasks),
                "injection_task_count": len(suite.injection_tasks),
                "results": results,
            },
            f,
            indent=2,
        )

    print()
    print("=" * 60)
    print(f"Injectable user tasks: {len(results)}")
    print(f"Saved to: {OUTPUT}")


if __name__ == "__main__":
    main()