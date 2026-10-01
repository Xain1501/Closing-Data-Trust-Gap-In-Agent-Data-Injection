"""Apply defenses to benchmark instances.

This module provides functionality to transform benchmark instances
with defense mechanisms like random key obfuscation.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..bench_types import Instance, Format
from .random_key import RandomKeyDefense, apply_random_key_defense


def apply_defense_to_instance(
    instance: Instance,
    defense_type: str = "random_key",
    defense_params: Optional[Dict[str, Any]] = None,
) -> Instance:
    """Apply a defense mechanism to a single instance.

    Args:
        instance: Original benchmark instance
        defense_type: Type of defense to apply
        defense_params: Defense-specific parameters

    Returns:
        New instance with defense applied
    """
    if defense_type != "random_key":
        raise ValueError(f"Unknown defense type: {defense_type}")

    # Only apply to JSON format
    if instance.format != Format.JSON.value and instance.format != Format.JSON:
        return instance

    params = defense_params or {}
    random_id_length = params.get("random_id_length", 8)

    # Apply random key defense
    transformed_input, returned_prompt, defense_info = apply_random_key_defense(
        input_data=instance.input,
        task_prompt=instance.task_prompt,
        random_id_length=random_id_length,
    )

    # Create new instance with defense applied
    defended_instance = Instance(
        instance_id=f"{instance.instance_id}_defended_{defense_type}",
        category=instance.category,
        format=instance.format,
        seed_file=instance.seed_file,
        subcategory=instance.subcategory,
        test_type=instance.test_type,
        input=transformed_input,
        tool_info=instance.tool_info,
        task_type=instance.task_type,
        task_prompt=returned_prompt,
        target_field=instance.target_field,
        groundtruth_output=instance.groundtruth_output,
        targeted_output=instance.targeted_output,
        attack_type=instance.attack_type,
        attack_params=instance.attack_params,
        comparison_method=instance.comparison_method,
        # Defense metadata - just store random_id
        defense_type=defense_type,
        defense_params=defense_info,
        original_input=instance.input,
        original_task_prompt=instance.task_prompt,
    )

    return defended_instance


def apply_defense_to_instances(
    instances: List[Instance],
    defense_type: str = "random_key",
    defense_params: Optional[Dict[str, Any]] = None,
) -> List[Instance]:
    """Apply a defense mechanism to multiple instances.

    Args:
        instances: List of benchmark instances
        defense_type: Type of defense to apply
        defense_params: Defense-specific parameters

    Returns:
        List of defended instances
    """
    defended = []
    for instance in instances:
        try:
            defended_instance = apply_defense_to_instance(
                instance, defense_type, defense_params
            )
            defended.append(defended_instance)
        except Exception as e:
            print(f"Warning: Failed to apply defense to {instance.instance_id}: {e}")
            defended.append(instance)  # Keep original on failure

    return defended


def generate_defended_dataset(
    input_file: Path,
    output_file: Path,
    defense_type: str = "random_key",
    defense_params: Optional[Dict[str, Any]] = None,
) -> int:
    """Generate a defended version of a benchmark dataset.

    Args:
        input_file: Path to input instances JSON file
        output_file: Path to output defended instances file
        defense_type: Type of defense to apply
        defense_params: Defense-specific parameters

    Returns:
        Number of instances processed
    """
    # Load instances
    with open(input_file, encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data, list):
            instances = [Instance(**inst) for inst in data]
        else:
            instances = [Instance(**data)]

    print(f"Loaded {len(instances)} instances from {input_file}")

    # Apply defense
    defended_instances = apply_defense_to_instances(
        instances, defense_type, defense_params
    )

    # Save defended instances
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        instances_data = [inst.model_dump() for inst in defended_instances]
        json.dump(instances_data, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(defended_instances)} defended instances to {output_file}")

    # Print statistics
    json_count = sum(
        1 for inst in defended_instances
        if inst.format == Format.JSON.value or inst.format == Format.JSON
    )
    defended_count = sum(1 for inst in defended_instances if inst.defense_type)
    print(f"  JSON instances: {json_count}")
    print(f"  Defended instances: {defended_count}")

    return len(defended_instances)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Apply defense to benchmark instances"
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Input instances JSON file",
    )
    parser.add_argument(
        "output_file",
        type=Path,
        help="Output defended instances file",
    )
    parser.add_argument(
        "--defense",
        type=str,
        default="random_key",
        help="Defense type (default: random_key)",
    )
    parser.add_argument(
        "--key-prefix",
        type=str,
        default="key_",
        help="Key prefix for random_key defense",
    )
    parser.add_argument(
        "--random-id-length",
        type=int,
        default=8,
        help="Random ID length for random_key defense",
    )

    args = parser.parse_args()

    defense_params = {
        "key_prefix": args.key_prefix,
        "random_id_length": args.random_id_length,
    }

    generate_defended_dataset(
        input_file=args.input_file,
        output_file=args.output_file,
        defense_type=args.defense,
        defense_params=defense_params,
    )
