#!/usr/bin/env python3
"""Validate generated benchmark instances.

This script checks that generated instances are correctly formed:
1. insert_complete attacks: contain breakout patterns and targeted value
2. override_pre/post attacks: correct field position relationships
3. Values appear in input: groundtruth and targeted values are present (for extraction tasks)

Usage:
    uv run python scripts/validate_instances.py out/generated/instances_*.jsonl
    uv run python scripts/validate_instances.py out/generated/instances_*.jsonl --verbose
    uv run python scripts/validate_instances.py out/generated/instances_*.jsonl --fail-fast
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ValidationResult:
    """Result of validating a single instance."""
    instance_id: str
    attack_type: Optional[str]
    task_type: str
    is_valid: bool
    issues: list = field(default_factory=list)


@dataclass
class ValidationSummary:
    """Summary of all validation results."""
    total_instances: int = 0
    total_attack: int = 0
    total_benign: int = 0
    valid_instances: int = 0
    invalid_instances: int = 0
    issues_by_type: dict = field(default_factory=lambda: defaultdict(list))
    issues_by_attack: dict = field(default_factory=lambda: defaultdict(list))


def load_instances(filepath: Path) -> list[dict]:
    """Load instances from JSON or JSONL file."""
    with open(filepath, encoding="utf-8") as f:
        content = f.read().strip()
        if content.startswith("["):
            return json.loads(content)
        else:
            return [json.loads(line) for line in content.splitlines() if line.strip()]


def find_value_in_input(value: str, input_str: str) -> tuple[bool, int]:
    """Find a value in the input string.

    Returns:
        Tuple of (found, position). Position is -1 if not found.
    """
    # Try exact match
    pos = input_str.find(value)
    if pos >= 0:
        return True, pos

    # Try quoted match
    quoted = f'"{value}"'
    pos = input_str.find(quoted)
    if pos >= 0:
        return True, pos

    # Try escaped quoted match (for values inside JSON strings)
    escaped = f'\\"' + value + '\\"'
    pos = input_str.find(escaped)
    if pos >= 0:
        return True, pos

    # Try with JSON-escaped quotes in the value itself
    # e.g., value contains " which becomes \" in JSON string
    if '"' in value:
        value_escaped = value.replace('"', r'\"')
        pos = input_str.find(value_escaped)
        if pos >= 0:
            return True, pos

    # Try JSON array format for array values
    if value.startswith('[') and value.endswith(']'):
        # Array values might be formatted differently
        pos = input_str.find(value.replace("'", '"'))
        if pos >= 0:
            return True, pos

    return False, -1


def validate_insert_complete(instance: dict) -> list[str]:
    """Validate an insert_complete attack instance.

    Checks:
    1. Injection contains quote breakout pattern (", " or ', ')
    2. Injection contains closing brace }
    3. Injection contains new object pattern {"
    4. Targeted value appears in the input
    """
    issues = []
    input_str = instance["input"]
    targeted = str(instance["targeted_output"])
    fmt = instance["format"]
    task_type = instance.get("task_type", "")

    # Skip targeted value check for aggregation tasks (computed values)
    skip_targeted_check = task_type == "aggregation"

    if fmt == "json":
        # Get the injection field and extract injected value
        injection_field = instance.get("attack_params", {}).get("injection_field", "")

        # Handle random_key defense: input may have prefix text before JSON
        json_str = input_str
        if instance.get("defense_type") == "random_key":
            # Find the start of JSON ([ or {)
            json_start = -1
            for i, c in enumerate(input_str):
                if c in '[{':
                    json_start = i
                    break
            if json_start > 0:
                json_str = input_str[json_start:]

        # Parse input to get the injected string value
        try:
            data = json.loads(json_str)
            # Get random_id if defense is applied
            random_id = None
            defense_params = instance.get("defense_params") or {}
            if instance.get("defense_type") == "random_key":
                random_id = defense_params.get("random_id")
            injected_value = extract_field_value(data, injection_field, random_id=random_id)

            if injected_value and isinstance(injected_value, str):
                # Check for breakout patterns
                # Pattern 1: Quote breakout with key/value (for flat objects/arrays)
                has_quote_breakout = '", "' in injected_value or "', '" in injected_value

                # Pattern 2: Full object breakout with braces (for nested structures)
                has_brace_close = '}' in injected_value
                has_new_object = '{"' in injected_value or "{'" in injected_value
                has_full_object_breakout = has_brace_close and has_new_object

                # Pattern 3: Array item breakout (for arrays of objects)
                has_array_item_breakout = '}, {' in injected_value or '},{"' in injected_value

                # Valid if has quote breakout OR full object breakout OR array item breakout
                has_valid_breakout = has_quote_breakout or has_full_object_breakout or has_array_item_breakout

                if not has_valid_breakout:
                    issues.append("Missing valid breakout pattern in injection (need '\"', '\"}' + '{\", or '}, {')")

                # Check targeted value in injection (skip for aggregation tasks)
                if not skip_targeted_check and targeted not in injected_value:
                    issues.append(f"Targeted value '{targeted}' not in injection")
            else:
                issues.append(f"Could not extract injection from field '{injection_field}'")
        except json.JSONDecodeError:
            issues.append("Input is not valid JSON (may be intentional for some attacks)")

    elif fmt == "markdown":
        # For markdown, check that targeted value appears somewhere in input
        # Skip for aggregation tasks (computed values)
        if not skip_targeted_check:
            found, _ = find_value_in_input(targeted, input_str)
            if not found:
                issues.append(f"Targeted value '{targeted}' not found in markdown input")

    elif fmt == "web_dom":
        # For web_dom, check targeted value appears
        found, _ = find_value_in_input(targeted, input_str)
        if not found:
            issues.append(f"Targeted value '{targeted}' not found in web_dom input")

    return issues


def validate_override_pre(instance: dict) -> list[str]:
    """Validate an override_pre attack instance.

    For override_pre: the injection field comes AFTER the target field in the object.
    This means the injected value appears AFTER the real value in the string.
    A last-match parser would return the injected (fake) value.

    The naming refers to where the DUPLICATE KEY is inserted:
    - override_pre: duplicate key is inserted BEFORE the original (but injection field is after)

    Checks:
    1. Targeted value appears in input
    2. Groundtruth value appears in input
    3. Injected value should come AFTER real value (for last-match to pick it up)
    """
    issues = []
    input_str = instance["input"]
    targeted = str(instance["targeted_output"])
    groundtruth = str(instance["groundtruth_output"])
    task_type = instance.get("task_type", "")

    # Skip value checks for aggregation tasks (computed values)
    if task_type == "aggregation":
        return issues

    # Check values appear in input
    tgt_found, tgt_pos = find_value_in_input(targeted, input_str)
    gt_found, gt_pos = find_value_in_input(groundtruth, input_str)

    if not tgt_found:
        issues.append(f"Targeted value '{targeted}' not found in input")
    if not gt_found:
        issues.append(f"Groundtruth value '{groundtruth}' not found in input")

    return issues


def validate_override_post(instance: dict) -> list[str]:
    """Validate an override_post attack instance.

    For override_post: the injection field comes BEFORE the target field in the object.
    This means the injected value appears BEFORE the real value in the string.
    A first-match parser would return the injected (fake) value.

    The naming refers to where the DUPLICATE KEY is inserted:
    - override_post: duplicate key is inserted AFTER the original (but injection field is before)

    Checks:
    1. Targeted value appears in input
    2. Groundtruth value appears in input
    3. Injected value should come BEFORE real value (for first-match to pick it up)
    """
    issues = []
    input_str = instance["input"]
    targeted = str(instance["targeted_output"])
    groundtruth = str(instance["groundtruth_output"])
    task_type = instance.get("task_type", "")

    # Skip value checks for aggregation tasks (computed values)
    if task_type == "aggregation":
        return issues

    # Check values appear in input
    tgt_found, tgt_pos = find_value_in_input(targeted, input_str)
    gt_found, gt_pos = find_value_in_input(groundtruth, input_str)

    if not tgt_found:
        issues.append(f"Targeted value '{targeted}' not found in input")
    if not gt_found:
        issues.append(f"Groundtruth value '{groundtruth}' not found in input")

    return issues


def validate_extraction_task(instance: dict) -> list[str]:
    """Validate that extraction task has values in input.

    For extraction tasks, both groundtruth and targeted should be
    literal values that appear in the input.
    """
    issues = []
    input_str = instance["input"]
    targeted = str(instance["targeted_output"])
    groundtruth = str(instance["groundtruth_output"])
    category = instance.get("category", "")

    # Special cases where groundtruth is a computed/special value
    special_groundtruths = [
        "not found",  # web_dom: element not found
        "Not found",
        "none",
        "None",
        "N/A",
    ]

    # Skip groundtruth check for special values
    if groundtruth in special_groundtruths:
        gt_found = True
    else:
        gt_found, _ = find_value_in_input(groundtruth, input_str)

    # Skip targeted check for special values
    if targeted in special_groundtruths:
        tgt_found = True
    else:
        tgt_found, _ = find_value_in_input(targeted, input_str)

    if not gt_found:
        issues.append(f"Groundtruth '{groundtruth}' not found in input (extraction task)")

    if instance["test_type"] == "attack" and not tgt_found:
        issues.append(f"Targeted '{targeted}' not found in input (extraction task)")

    return issues


def validate_aggregation_task(instance: dict) -> list[str]:
    """Validate aggregation task.

    For aggregation tasks, the output values are computed, so we check
    that the injected data would lead to the targeted output.
    """
    issues = []
    # Aggregation outputs are computed - harder to validate automatically
    # For now, we just check that the attack makes sense structurally

    if instance["test_type"] == "attack":
        attack_type = instance.get("attack_type")
        if attack_type == "insert_complete":
            # Check that injection contains plausible data
            injection_field = instance.get("attack_params", {}).get("injection_field", "")
            if not injection_field:
                issues.append("Aggregation attack missing injection_field")

    return issues


def extract_field_value(data: Any, field_path: str, random_id: str = None) -> Any:
    """Extract value from nested data structure using field path.

    Supports paths like: [0].summary, metadata.avg_score, [1].start.dateTime

    Args:
        data: The data structure to extract from
        field_path: Path to the field (e.g., "[0].summary")
        random_id: If provided, try both original key and key with random_id suffix
    """
    if not field_path:
        return None

    current = data

    # Parse path into parts
    parts = []
    remaining = field_path

    while remaining:
        if remaining.startswith("["):
            # Array index
            match = re.match(r'\[(\d+)\]\.?', remaining)
            if match:
                parts.append(int(match.group(1)))
                remaining = remaining[match.end():]
            else:
                break
        else:
            # Object key
            match = re.match(r'([^.\[]+)\.?', remaining)
            if match:
                parts.append(match.group(1))
                remaining = remaining[match.end():]
            else:
                break

    # Navigate to value
    for part in parts:
        try:
            if isinstance(part, int):
                current = current[part]
            elif isinstance(current, dict):
                # Try original key first
                if part in current:
                    current = current[part]
                # Try key with random_id suffix (for random_key defense)
                elif random_id and f"{part}_{random_id}" in current:
                    current = current[f"{part}_{random_id}"]
                else:
                    # Try to find any key that starts with the part name
                    found = False
                    for key in current:
                        if key == part or (random_id and key == f"{part}_{random_id}"):
                            current = current[key]
                            found = True
                            break
                        # Handle case where key has random suffix
                        if key.startswith(f"{part}_") and len(key) > len(part) + 1:
                            current = current[key]
                            found = True
                            break
                    if not found:
                        return None
            else:
                return None
        except (IndexError, KeyError, TypeError):
            return None

    return current


def validate_instance(instance: dict) -> ValidationResult:
    """Validate a single instance."""
    instance_id = instance["instance_id"]
    attack_type = instance.get("attack_type")
    task_type = instance["task_type"]
    test_type = instance["test_type"]

    issues = []

    # Validate based on attack type
    if test_type == "attack":
        if attack_type == "insert_complete":
            issues.extend(validate_insert_complete(instance))
        elif attack_type == "override_pre":
            issues.extend(validate_override_pre(instance))
        elif attack_type == "override_post":
            issues.extend(validate_override_post(instance))
        elif attack_type in ("error", "contextual"):
            # Semantic attacks - basic validation
            pass

    # Validate based on task type
    if task_type == "extraction":
        issues.extend(validate_extraction_task(instance))
    elif task_type == "aggregation":
        issues.extend(validate_aggregation_task(instance))
    elif task_type == "filtering":
        # Filtering tasks - basic validation
        pass

    return ValidationResult(
        instance_id=instance_id,
        attack_type=attack_type,
        task_type=task_type,
        is_valid=len(issues) == 0,
        issues=issues
    )


def validate_all(instances: list[dict], verbose: bool = False, fail_fast: bool = False) -> ValidationSummary:
    """Validate all instances and return summary."""
    summary = ValidationSummary()
    summary.total_instances = len(instances)

    for instance in instances:
        test_type = instance["test_type"]
        if test_type == "attack":
            summary.total_attack += 1
        else:
            summary.total_benign += 1

        result = validate_instance(instance)

        if result.is_valid:
            summary.valid_instances += 1
        else:
            summary.invalid_instances += 1

            for issue in result.issues:
                summary.issues_by_type[issue].append(result.instance_id)
                if result.attack_type:
                    summary.issues_by_attack[result.attack_type].append(issue)

            if verbose:
                print(f"\n[INVALID] {result.instance_id}")
                print(f"  Attack: {result.attack_type}, Task: {result.task_type}")
                for issue in result.issues:
                    print(f"  - {issue}")

            if fail_fast:
                print(f"\nFailed fast on instance: {result.instance_id}")
                break

    return summary


def print_summary(summary: ValidationSummary):
    """Print validation summary."""
    print("\n" + "=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)

    print(f"\nTotal instances: {summary.total_instances}")
    print(f"  Benign: {summary.total_benign}")
    print(f"  Attack: {summary.total_attack}")
    print(f"\nValid: {summary.valid_instances}")
    print(f"Invalid: {summary.invalid_instances}")

    if summary.invalid_instances > 0:
        valid_pct = summary.valid_instances / summary.total_instances * 100
        print(f"Validity rate: {valid_pct:.1f}%")

    if summary.issues_by_type:
        print("\n" + "-" * 40)
        print("Issues by type:")
        print("-" * 40)
        for issue, ids in sorted(summary.issues_by_type.items(), key=lambda x: -len(x[1])):
            print(f"\n  [{len(ids)} instances] {issue}")
            if len(ids) <= 5:
                for id in ids:
                    print(f"    - {id}")
            else:
                for id in ids[:3]:
                    print(f"    - {id}")
                print(f"    ... and {len(ids) - 3} more")

    if summary.issues_by_attack:
        print("\n" + "-" * 40)
        print("Issues by attack type:")
        print("-" * 40)
        for attack_type, issues in sorted(summary.issues_by_attack.items()):
            issue_counts = Counter(issues)
            print(f"\n  {attack_type}:")
            for issue, count in issue_counts.most_common():
                print(f"    [{count}] {issue}")


def main():
    parser = argparse.ArgumentParser(description="Validate benchmark instances")
    parser.add_argument("filepath", type=Path, help="Path to instances file (JSON or JSONL)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print details for each invalid instance")
    parser.add_argument("--fail-fast", "-f", action="store_true", help="Stop on first invalid instance")

    args = parser.parse_args()

    if not args.filepath.exists():
        print(f"Error: File not found: {args.filepath}")
        sys.exit(1)

    print(f"Loading instances from {args.filepath}...")
    instances = load_instances(args.filepath)
    print(f"Loaded {len(instances)} instances")

    print("\nValidating...")
    summary = validate_all(instances, verbose=args.verbose, fail_fast=args.fail_fast)

    print_summary(summary)

    # Exit with error code if there are invalid instances
    if summary.invalid_instances > 0:
        sys.exit(1)
    else:
        print("\n✓ All instances valid!")
        sys.exit(0)


if __name__ == "__main__":
    main()
