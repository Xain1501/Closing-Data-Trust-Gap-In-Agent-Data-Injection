"""Reporting utilities to aggregate evaluation results."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..bench_types import Instance


@dataclass
class ParsedResult:
    """Result record with joined instance metadata."""

    result: Dict
    instance: Optional[Instance]
    test_type: str
    attack_type: Optional[str]
    category: Optional[str]
    task_type: Optional[str]
    format: Optional[str]
    defense_type: Optional[str] = None
    subcategory: Optional[str] = None


def _parse_results_filename(path: Path) -> Optional[Tuple[str, str]]:
    """Extract model name and timestamp from a results file name."""
    stem = path.stem  # results_gpt-4o_20260111_203500
    prefix = "results_"
    if not stem.startswith(prefix):
        return None

    body = stem[len(prefix) :]
    parts = body.rsplit("_", 2)
    if len(parts) < 3:
        return None

    model = parts[0]
    timestamp = f"{parts[1]}_{parts[2]}"
    return model, timestamp


def find_latest_results(results_dir: Path) -> Dict[str, Path]:
    """Find the latest results file for each model in a directory."""
    latest: Dict[str, Tuple[str, Path]] = {}

    for path in results_dir.glob("results_*.jsonl"):
        parsed = _parse_results_filename(path)
        if not parsed:
            continue
        model, timestamp = parsed

        current = latest.get(model)
        if current is None or timestamp > current[0]:
            latest[model] = (timestamp, path)

    return {model: info[1] for model, info in latest.items()}


def load_instances_map(dataset_path: Path) -> Dict[str, Instance]:
    """Load instances and return a lookup by instance_id."""
    with dataset_path.open(encoding="utf-8") as f:
        data = json.load(f)

    instances = [Instance(**item) for item in data] if isinstance(data, list) else [Instance(**data)]
    return {inst.instance_id: inst for inst in instances}


def load_results(path: Path) -> List[Dict]:
    """Load evaluation results from a JSONL file."""
    records: List[Dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def join_results_with_instances(
    results: Iterable[Dict],
    instance_map: Dict[str, Instance],
) -> List[ParsedResult]:
    """Attach instance metadata to results."""
    joined: List[ParsedResult] = []
    for res in results:
        instance_id = res.get("instance_id")
        inst = instance_map.get(instance_id)

        # Use result fields first, fallback to instance metadata
        test_type = res.get("test_type") or getattr(inst, "test_type", None) or ("benign" if instance_id and instance_id.endswith("_benign") else "attack")
        attack_type = res.get("attack_type") or getattr(inst, "attack_type", None)
        category = res.get("category") or getattr(inst, "category", None)
        task_type = res.get("task_type") or getattr(inst, "task_type", None)
        fmt = res.get("format") or getattr(inst, "format", None)
        defense_type = res.get("defense_type") or getattr(inst, "defense_type", None)
        subcategory = res.get("subcategory") or getattr(inst, "subcategory", None)

        joined.append(
            ParsedResult(
                result=res,
                instance=inst,
                test_type=test_type,
                attack_type=attack_type,
                category=category,
                task_type=task_type,
                format=fmt,
                defense_type=defense_type,
                subcategory=subcategory,
            )
        )
    return joined


def _accumulate(metrics: Dict[str, Dict[str, int]], key: str, test_type: str, benign_correct: bool, attack_success: bool):
    """Update counts for a grouping key."""
    bucket = metrics.setdefault(key, {"benign_total": 0, "benign_correct": 0, "attack_total": 0, "attack_success": 0})
    if test_type == "benign":
        bucket["benign_total"] += 1
        if benign_correct:
            bucket["benign_correct"] += 1
    else:
        bucket["attack_total"] += 1
        if attack_success:
            bucket["attack_success"] += 1


def _get_web_dom_defense_from_subcategory(subcategory: Optional[str]) -> Tuple[Optional[str], Optional[bool]]:
    """Extract defense info from web_dom subcategory.

    For web_dom category, the method is encoded in subcategory:
    - dom_id: no defense (uses [index] format)
    - dom_id-pos: no defense (uses position format)
    - dom_id-rand: random_key defense, attacker guessed correctly
    - dom_id-rand-wrong: random_key defense, attacker guessed wrong
    - dom_id-ref: no defense (uses ref format)

    Returns:
        tuple: (defense_type, guess_key_match)
    """
    if not subcategory or not subcategory.startswith("dom_"):
        return None, None

    method = subcategory[4:]  # Remove "dom_" prefix

    if method == "id-rand":
        return "random_key", True  # Attacker guessed correctly
    elif method == "id-rand-wrong":
        return "random_key", False  # Attacker guessed wrong
    else:
        # id, id-pos, id-ref are all "no defense" variants
        return None, None


def _get_expanded_defense_keys(
    defense_type: Optional[str],
    attack_params: Optional[Dict],
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
) -> list:
    """Get expanded defense keys for a result.

    For random_key defense, returns multiple keys:
    - random_key (all)
    - random_key (no guess) / random_key (guess correct) / random_key (guess wrong)

    For web_dom category, defense is determined by subcategory:
    - dom_id, dom_id-pos, dom_id-ref: no defense
    - dom_id-rand: random_key (guess correct)
    - dom_id-rand-wrong: random_key (guess wrong)

    For other defenses, returns single key.
    """
    # Special handling for web_dom category
    if category == "web_dom" and subcategory:
        web_dom_defense, web_dom_guess = _get_web_dom_defense_from_subcategory(subcategory)

        if web_dom_defense == "random_key":
            keys = ["random_key (all)"]
            if web_dom_guess is True:
                keys.append("random_key (guess correct)")
            elif web_dom_guess is False:
                keys.append("random_key (guess wrong)")
            return keys
        else:
            return ["none"]

    # Standard handling for other categories
    defense = defense_type if defense_type else "none"

    if defense != "random_key":
        return [defense]

    # For random_key, expand based on guess_key_match
    keys = ["random_key (all)"]
    params = attack_params or {}
    guess_key_match = params.get("guess_key_match")

    if guess_key_match is None:
        keys.append("random_key (no guess)")
    elif guess_key_match:
        keys.append("random_key (guess correct)")
    else:
        keys.append("random_key (guess wrong)")

    return keys


def summarize(joined: List[ParsedResult]) -> Dict:
    """Compute aggregate metrics for a collection of results."""
    totals = {"benign_total": 0, "benign_correct": 0, "attack_total": 0, "attack_success": 0}
    by_attack: Dict[str, Dict[str, int]] = {}
    by_category: Dict[str, Dict[str, int]] = {}
    by_task: Dict[str, Dict[str, int]] = {}
    by_format: Dict[str, Dict[str, int]] = {}
    by_defense: Dict[str, Dict[str, int]] = {}  # Expanded defense keys
    by_category_defense: Dict[str, Dict[str, int]] = {}  # "category|defense" -> metrics (expanded)

    for item in joined:
        res = item.result
        benign_correct = bool(res.get("benign_correct"))
        attack_success = bool(res.get("attack_successful"))
        test_type = item.test_type

        if test_type == "benign":
            totals["benign_total"] += 1
            if benign_correct:
                totals["benign_correct"] += 1
        else:
            totals["attack_total"] += 1
            if attack_success:
                totals["attack_success"] += 1

        if item.attack_type:
            _accumulate(by_attack, item.attack_type, test_type, benign_correct, attack_success)
        if item.category:
            _accumulate(by_category, item.category, test_type, benign_correct, attack_success)
        if item.task_type:
            _accumulate(by_task, item.task_type, test_type, benign_correct, attack_success)
        if item.format:
            _accumulate(by_format, item.format, test_type, benign_correct, attack_success)

        # Get expanded defense keys
        attack_params = res.get("attack_params")
        expanded_defense_keys = _get_expanded_defense_keys(
            item.defense_type, attack_params, item.category, item.subcategory
        )

        # Track by defense status (with expanded keys)
        for defense_key in expanded_defense_keys:
            _accumulate(by_defense, defense_key, test_type, benign_correct, attack_success)

        # Track category x defense (with expanded keys)
        if item.category:
            for defense_key in expanded_defense_keys:
                cat_def_key = f"{item.category}|{defense_key}"
                _accumulate(by_category_defense, cat_def_key, test_type, benign_correct, attack_success)

    return {
        "totals": totals,
        "by_attack": by_attack,
        "by_category": by_category,
        "by_task": by_task,
        "by_format": by_format,
        "by_defense": by_defense,
        "by_category_defense": by_category_defense,
    }


def _rate(numerator: int, denominator: int) -> float:
    return (numerator / denominator) if denominator else 0.0


def _format_bucket_line(name: str, bucket: Dict[str, int]) -> str:
    benign_total = bucket["benign_total"]
    benign_correct = bucket["benign_correct"]
    attack_total = bucket["attack_total"]
    attack_success = bucket["attack_success"]

    benign_rate = _rate(benign_correct, benign_total)
    attack_rate = _rate(attack_success, attack_total)
    return (
        f"- {name}: utility {benign_correct}/{benign_total} ({benign_rate:.1%}), "
        f"ASR {attack_success}/{attack_total} ({attack_rate:.1%})"
    )


def _format_composition_line(name: str, bucket: Dict[str, int]) -> str:
    """Format a task composition line."""
    benign_total = bucket["benign_total"]
    attack_total = bucket["attack_total"]
    total = benign_total + attack_total
    return f"- {name}: {benign_total} benign, {attack_total} attack ({total} total)"


def render_text_report(
    model_name: str,
    results_path: Path,
    summary: Dict,
) -> str:
    """Render a human-readable markdown report."""
    totals = summary["totals"]
    benign_rate = _rate(totals["benign_correct"], totals["benign_total"])
    attack_rate = _rate(totals["attack_success"], totals["attack_total"])

    lines: List[str] = []
    lines.append(f"## Model: {model_name}")
    lines.append(f"- Source file: `{results_path}`")
    lines.append(f"- Benign utility: {totals['benign_correct']}/{totals['benign_total']} ({benign_rate:.1%})")
    lines.append(f"- Attack success (ASR): {totals['attack_success']}/{totals['attack_total']} ({attack_rate:.1%})")

    # Task Composition section
    lines.append("\n### Task Composition")

    if summary["by_category"]:
        lines.append("\n**By category:**")
        for name, bucket in sorted(summary["by_category"].items()):
            lines.append(_format_composition_line(name, bucket))

    if summary["by_task"]:
        lines.append("\n**By task type:**")
        for name, bucket in sorted(summary["by_task"].items()):
            lines.append(_format_composition_line(name, bucket))

    if summary.get("by_defense"):
        lines.append("\n**By defense:**")
        for name, bucket in sorted(summary["by_defense"].items()):
            display_name = "No defense" if name == "none" else name
            lines.append(_format_composition_line(display_name, bucket))

    if summary["by_format"]:
        lines.append("\n**By format:**")
        for name, bucket in sorted(summary["by_format"].items()):
            lines.append(_format_composition_line(name, bucket))

    # Results section
    if summary["by_attack"]:
        lines.append("\n### By attack type")
        for name, bucket in sorted(summary["by_attack"].items()):
            lines.append(_format_bucket_line(name, bucket))

    if summary["by_category"]:
        lines.append("\n### By category")
        for name, bucket in sorted(summary["by_category"].items()):
            lines.append(_format_bucket_line(name, bucket))

    if summary["by_task"]:
        lines.append("\n### By task type")
        for name, bucket in sorted(summary["by_task"].items()):
            lines.append(_format_bucket_line(name, bucket))

    if summary["by_format"]:
        lines.append("\n### By format")
        for name, bucket in sorted(summary["by_format"].items()):
            lines.append(_format_bucket_line(name, bucket))

    if summary.get("by_defense"):
        lines.append("\n### By defense")
        for name, bucket in sorted(summary["by_defense"].items()):
            display_name = "No defense" if name == "none" else f"Defense: {name}"
            lines.append(_format_bucket_line(display_name, bucket))

    return "\n".join(lines)


def generate_report(
    results_dir: Path,
    dataset_path: Path,
    output_path: Optional[Path] = None,
) -> Tuple[str, Optional[Path]]:
    """Generate report text and optionally save it.

    Returns:
        Tuple of (combined report text, output path if saved)
    """
    instance_map = load_instances_map(dataset_path)
    latest_files = find_latest_results(results_dir)

    if not latest_files:
        raise FileNotFoundError(f"No results files found in {results_dir}")

    combined_lines: List[str] = []
    table_rows: List[Tuple[str, str, str, str]] = []
    attack_table_rows: List[Tuple[str, str, str]] = []
    task_table_rows: List[Tuple[str, str, str, str]] = []  # (task_type, model, utility, asr)
    defense_table_rows: List[Tuple[str, str, str, str]] = []  # (defense, model, utility, asr) - expanded keys
    category_defense_rows: List[Tuple[str, str, str, str, str]] = []  # (category, defense, model, utility, asr) - expanded
    for model_name, path in sorted(latest_files.items()):
        raw_results = load_results(path)
        joined = join_results_with_instances(raw_results, instance_map)
        summary = summarize(joined)
        combined_lines.append(render_text_report(model_name, path, summary))

        totals = summary["totals"]
        benign_rate = _rate(totals["benign_correct"], totals["benign_total"])
        attack_rate = _rate(totals["attack_success"], totals["attack_total"])
        table_rows.append(
            (
                model_name,
                f"{benign_rate:.1%} ({totals['benign_correct']}/{totals['benign_total']})",
                f"{attack_rate:.1%} ({totals['attack_success']}/{totals['attack_total']})",
                str(path),
            )
        )

        # Capture per-attack stats for comparison table
        for attack_name, bucket in summary["by_attack"].items():
            attack_total = bucket["attack_total"]
            attack_success = bucket["attack_success"]
            attack_rate = _rate(attack_success, attack_total)
            attack_table_rows.append(
                (
                    attack_name,
                    model_name,
                    f"{attack_rate:.1%} ({attack_success}/{attack_total})",
                )
            )

        # Capture per-task-type stats for comparison table
        for task_name, bucket in summary.get("by_task", {}).items():
            benign_total = bucket["benign_total"]
            benign_correct = bucket["benign_correct"]
            attack_total = bucket["attack_total"]
            attack_success = bucket["attack_success"]
            benign_rate = _rate(benign_correct, benign_total)
            attack_rate = _rate(attack_success, attack_total)
            task_table_rows.append(
                (
                    task_name,
                    model_name,
                    f"{benign_rate:.1%} ({benign_correct}/{benign_total})",
                    f"{attack_rate:.1%} ({attack_success}/{attack_total})",
                )
            )

        # Capture per-category x defense stats for comparison table
        for cat_def_key, bucket in summary.get("by_category_defense", {}).items():
            category_name, defense_name = cat_def_key.split("|", 1)
            display_defense = "No defense" if defense_name == "none" else defense_name
            benign_total = bucket["benign_total"]
            benign_correct = bucket["benign_correct"]
            attack_total = bucket["attack_total"]
            attack_success = bucket["attack_success"]
            benign_rate = _rate(benign_correct, benign_total)
            attack_rate = _rate(attack_success, attack_total)
            category_defense_rows.append(
                (
                    category_name,
                    display_defense,
                    model_name,
                    f"{benign_rate:.1%} ({benign_correct}/{benign_total})",
                    f"{attack_rate:.1%} ({attack_success}/{attack_total})",
                )
            )

        # Capture per-defense stats for comparison table (already expanded)
        for defense_name, bucket in summary.get("by_defense", {}).items():
            display_name = "No defense" if defense_name == "none" else f"{defense_name}"
            benign_total = bucket["benign_total"]
            benign_correct = bucket["benign_correct"]
            attack_total = bucket["attack_total"]
            attack_success = bucket["attack_success"]
            benign_rate = _rate(benign_correct, benign_total)
            attack_rate = _rate(attack_success, attack_total)
            defense_table_rows.append(
                (
                    display_name,
                    model_name,
                    f"{benign_rate:.1%} ({benign_correct}/{benign_total})",
                    f"{attack_rate:.1%} ({attack_success}/{attack_total})",
                )
            )
        combined_lines.append("\n---\n")

    if table_rows:
        combined_lines.append("## Model Comparison\n")
        combined_lines.append("| Model | Benign Utility | ASR | Source |")
        combined_lines.append("| --- | --- | --- | --- |")
        for row in table_rows:
            combined_lines.append(f"| {row[0]} | {row[1]} | {row[2]} | `{row[3]}` |")

    if attack_table_rows:
        combined_lines.append("\n## Attack Type Comparison\n")
        combined_lines.append("| Attack Type | Model | ASR |")
        combined_lines.append("| --- | --- | --- |")
        for attack_name, model_name, asr_str in sorted(attack_table_rows):
            combined_lines.append(f"| {attack_name} | {model_name} | {asr_str} |")

    if task_table_rows:
        combined_lines.append("\n## Task Type Comparison\n")
        combined_lines.append("| Task Type | Model | Utility | ASR |")
        combined_lines.append("| --- | --- | --- | --- |")
        for task_name, model_name, utility_str, asr_str in sorted(task_table_rows):
            combined_lines.append(f"| {task_name} | {model_name} | {utility_str} | {asr_str} |")

    if defense_table_rows:
        combined_lines.append("\n## Defense Comparison\n")
        combined_lines.append("| Defense | Model | Utility | ASR |")
        combined_lines.append("| --- | --- | --- | --- |")
        for defense_name, model_name, utility_str, asr_str in sorted(defense_table_rows):
            combined_lines.append(f"| {defense_name} | {model_name} | {utility_str} | {asr_str} |")

    if category_defense_rows:
        combined_lines.append("\n## Category x Defense\n")
        combined_lines.append("| Category | Defense | Model | Utility | ASR |")
        combined_lines.append("| --- | --- | --- | --- | --- |")
        for category_name, defense_name, model_name, utility_str, asr_str in sorted(category_defense_rows):
            combined_lines.append(f"| {category_name} | {defense_name} | {model_name} | {utility_str} | {asr_str} |")

    report_text = "\n".join(combined_lines).rstrip()

    output_file = output_path
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = results_dir / "reports" / f"report_{timestamp}.md"

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(report_text, encoding="utf-8")

    return report_text, output_file
