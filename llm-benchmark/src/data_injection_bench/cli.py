#!/usr/bin/env python3
"""Command-line interface for the Data Injection Benchmark."""

import sys
from pathlib import Path
from typing import Callable, List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from data_injection_bench.bench_types import BenchmarkConfig, Category, Format
from data_injection_bench.parsers import FormatTransformer

app = typer.Typer(
    name="dib",
    help="Data Injection Benchmark - Evaluate LLM parsing under adversarial settings",
    add_completion=False,
)

console = Console()


# =============================================================================
# Generate Command
# =============================================================================


@app.command()
def generate(
    category: Optional[Category] = typer.Option(
        None,
        "--category",
        "-C",
        help="Category to generate (defaults to auto-detection from seed path or github_issue)",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to benchmark configuration file",
    ),
    output: Path = typer.Option(
        "out/generated/instances.jsonl",
        "--output",
        "-o",
        help="Output file for generated instances",
    ),
    seed_limit: Optional[int] = typer.Option(
        None,
        "--seed-limit",
        "-n",
        help="Maximum number of seeds per category (for testing)",
    ),
    formats: List[Format] = typer.Option(
        [Format.JSON],
        "--format",
        "-f",
        help="Output formats to generate (repeat for multiple). Example: --format json --format markdown",
    ),
    seed_file: Optional[str] = typer.Option(
        None,
        "--seed-file",
        "-s",
        help="Specific seed file to use (within category directory)",
    ),
    defense: str = typer.Option(
        "random_key",
        "--defense",
        "-d",
        help="Defense to apply (random_key). Default: random_key",
    ),
    defense_only: bool = typer.Option(
        False,
        "--defense-only",
        help="Only generate defended instances (skip undefended)",
    ),
    no_defense: bool = typer.Option(
        False,
        "--no-defense",
        help="Only generate undefended instances (skip defended)",
    ),
    random_id_length: int = typer.Option(
        8,
        "--random-id-length",
        help="Length of random ID suffix for random_key defense",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
):
    """
    Generate benchmark dataset from seed samples.

    Reads seed tool outputs, applies format transformations, injects attacks,
    and creates benchmark instances with groundtruth and targeted outputs.

    By default, generates BOTH defended and undefended instances.
    Use --defense-only to only generate defended instances.
    Use --no-defense to only generate undefended instances.
    """
    console.print(f"[bold blue]Generating benchmark dataset...[/bold blue]")
    console.print(f"Output: {output}")

    if seed_limit:
        console.print(f"Seed limit: {seed_limit} per category")

    # Determine which instances to generate
    generate_undefended = not defense_only
    generate_defended = not no_defense

    if defense_only and no_defense:
        console.print("[red]Cannot use both --defense-only and --no-defense[/red]")
        raise typer.Exit(1)

    try:
        from data_injection_bench.generator import DatasetGenerator
        from data_injection_bench.bench_types import Category, Format

        def _infer_category_from_seed(seed_path: Optional[str]) -> Optional[Category]:
            if not seed_path:
                return None
            path = Path(seed_path)
            for parent in [path] + list(path.parents):
                for cat in Category:
                    if parent.name == cat.value:
                        return cat
            return None

        effective_category = category or _infer_category_from_seed(seed_file)

        if category is None and effective_category is None:
            console.print(f"[yellow]Detected category '{effective_category.value}' from seed path[/yellow]")
        elif effective_category is None:
            console.print(f"[yellow]No category specified. Terminating.[/yellow]")
            raise typer.Exit(1)
        else:
            console.print(f"Category: {effective_category.value}")

        generator = DatasetGenerator()
        defense_params = {
            "random_id_length": random_id_length,
        }

        all_instances = []

        # Generate undefended instances
        if generate_undefended:
            console.print("\n[cyan]Generating undefended instances...[/cyan]")
            undefended_instances = generator.generate_instances(
                category=effective_category,
                formats=formats,
                seed_limit=seed_limit,
                seed_file=seed_file,
                defense_type=None,
                defense_params=None,
            )
            all_instances.extend(undefended_instances)
            console.print(f"[green]  ✓ Generated {len(undefended_instances)} undefended instances[/green]")

        # Generate defended instances
        if generate_defended:
            console.print(f"\n[cyan]Generating defended instances (defense={defense})...[/cyan]")
            defended_instances = generator.generate_instances(
                category=effective_category,
                formats=formats,
                seed_limit=seed_limit,
                seed_file=seed_file,
                defense_type=defense,
                defense_params=defense_params,
            )
            all_instances.extend(defended_instances)
            console.print(f"[green]  ✓ Generated {len(defended_instances)} defended instances[/green]")

        # Save all instances to the output file
        generator.save_instances(all_instances, output)

        console.print(f"\n[bold green]✓ Total: {len(all_instances)} instances generated[/bold green]")
        console.print(f"[green]Saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[bold red]✗ Error generating dataset:[/bold red]")
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


# =============================================================================
# Evaluate Command
# =============================================================================


@app.command()
def evaluate(
    dataset: Path = typer.Argument(
        ...,
        help="Path to dataset file (instances.jsonl)",
        exists=True,
    ),
    model: str = typer.Option(
        ...,
        "--model",
        "-m",
        help="Model identifier (e.g., gpt-4-turbo, claude-3-opus)",
    ),
    provider: str = typer.Option(
        "openai",
        "--provider",
        "-p",
        help="Provider name (openai, anthropic, custom)",
    ),
    tool_access: str = typer.Option(
        "none",
        "--tool-access",
        "-t",
        help="Tool access mode (none, python)",
    ),
    output_dir: Path = typer.Option(
        "out/runs",
        "--output-dir",
        "-o",
        help="Output directory for evaluation results",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-n",
        help="Limit number of instances to evaluate (for testing)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
):
    """
    Evaluate LLM on benchmark dataset.

    Runs the specified LLM on each instance in the dataset,
    compares outputs to groundtruth and targeted outputs,
    and saves evaluation results.
    """
    console.print(f"[bold blue]Evaluating model: {model}[/bold blue]")
    console.print(f"Dataset: {dataset}")
    console.print(f"Provider: {provider}")
    console.print(f"Tool access: {tool_access}")

    if limit:
        console.print(f"Limit: {limit} instances")

    try:
        from data_injection_bench.generator import DatasetGenerator
        from data_injection_bench.eval import OpenAIProvider, AnthropicProvider, GoogleProvider, ModelRunner, Scorer, print_evaluation_summary
        from data_injection_bench.bench_types import ToolAccessMode
        import json
        from datetime import datetime

        # Load instances
        console.print("\n[cyan]Loading dataset...[/cyan]")
        generator = DatasetGenerator()
        instances = generator.load_instances(dataset)

        if limit:
            instances = instances[:limit]

        console.print(f"Loaded {len(instances)} instances")

        # Initialize provider
        console.print(f"\n[cyan]Initializing {provider} provider...[/cyan]")
        if provider == "openai":
            llm_provider = OpenAIProvider(model_name=model)
        elif provider == "anthropic":
            llm_provider = AnthropicProvider(model_name=model)
        elif provider == "google":
            llm_provider = GoogleProvider(model_name=model)
        else:
            console.print(f"[red]Provider '{provider}' not yet implemented[/red]")
            raise typer.Exit(1)

        # Initialize runner
        tool_mode = ToolAccessMode.PYTHON if tool_access == "python" else ToolAccessMode.NONE
        runner = ModelRunner(llm_provider, tool_access_mode=tool_mode)

        # Run evaluation
        console.print(f"\n[cyan]Running evaluation ({len(instances)} instances)...[/cyan]")
        results = runner.run_instances(instances, verbose=True)

        # Score results
        console.print(f"\n[cyan]Scoring results...[/cyan]")
        scorer = Scorer()
        scored_results = scorer.score_results(instances, results, verbose=True)

        # Print summary
        print_evaluation_summary(scored_results, model, instances)

        # Save results
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = output_dir / f"results_{model.replace('/', '_')}_{timestamp}.jsonl"

        with open(results_file, "w", encoding="utf-8") as f:
            for result in scored_results:
                f.write(result.model_dump_json() + "\n")

        console.print(f"\n[bold green]✓ Evaluation complete[/bold green]")
        console.print(f"[green]Results saved to: {results_file}[/green]")

    except Exception as e:
        console.print(f"\n[bold red]✗ Error during evaluation:[/bold red]")
        console.print(f"[red]{e}[/red]")
        import traceback
        if verbose:
            console.print(traceback.format_exc())
        raise typer.Exit(1)


# =============================================================================
# Transform Seeds Command
# =============================================================================


@app.command("transform")
def transform_seeds(
    category: Category = typer.Option(
        Category.GITHUB_ISSUE,
        "--category",
        "-c",
        help="Category to transform seeds for",
    ),
    input_dir: Path = typer.Option(
        Path("data/seeds/github_issue"),
        "--input-dir",
        "-i",
        exists=True,
        file_okay=False,
        readable=True,
        help="Directory containing seed JSON files",
    ),
    output_dir: Path = typer.Option(
        Path("out/transformed"),
        "--output-dir",
        "-o",
        help="Directory to write transformed files",
    ),
    target_format: Format = typer.Option(
        Format.MARKDOWN,
        "--target-format",
        "-t",
        help="Output format (markdown, csv, text)",
    ),
    subcategory: Optional[str] = typer.Option(
        None,
        "--subcategory",
        "-s",
        help="Force subcategory (e.g., issue, comments). If omitted, inferred when possible.",
    ),
):
    """
    Transform JSON seed files for a category into a different format.

    Uses category configuration (e.g., configs/categories/github_issue.yaml) to pick
    the correct schema templates. Defaults to Markdown output.
    """
    import json
    import yaml

    if target_format != Format.MARKDOWN:
        console.print(f"[red]Target format {target_format.value} is not supported. Only 'markdown' is supported.[/red]")
        raise typer.Exit(1)

    config_path = Path(f"configs/categories/{category.value}.yaml")
    category_config = {}
    if config_path.exists():
        with config_path.open() as f:
            category_config = yaml.safe_load(f) or {}
    else:
        console.print(f"[yellow]Warning: Category config not found at {config_path}, using generic transformer.[/yellow]")

    def infer_subcategory(path: Path) -> Optional[str]:
        if subcategory:
            return subcategory
        schemas = category_config.get("schemas", {})
        if category == Category.GITHUB_ISSUE:
            return "comments" if "comment" in path.stem else "issue"
        if len(schemas) == 1:
            return next(iter(schemas.keys()))
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(input_dir.glob("*.json"))
    if not files:
        console.print(f"[yellow]No JSON files found in {input_dir}[/yellow]")
        raise typer.Exit(0)

    method_name = "json_to_markdown"
    extension = ".md"
    transform_fn = getattr(FormatTransformer, method_name)

    console.print(f"[cyan]Transforming {len(files)} files from {input_dir} to {output_dir} ({target_format.value})[/cyan]")

    for path in files:
        with path.open() as f:
            data = json.load(f)

        subcat = infer_subcategory(path)
        transformed = transform_fn(
            data,
            category_config=category_config,
            subcategory=subcat,
        )

        out_path = output_dir / f"{path.stem}{extension}"
        out_path.write_text(transformed, encoding="utf-8")
        console.print(f"[green]Wrote {out_path}[/green]")

    console.print(f"[bold green]✓ Transformation complete[/bold green]")


# =============================================================================
# Report Command
# =============================================================================


@app.command()
def report(
    results_file: Path = typer.Argument(
        ...,
        help="Path to evaluation results file (.jsonl)",
        exists=True,
    ),
    dataset: Optional[Path] = typer.Option(
        None,
        "--dataset",
        "-d",
        help="Path to dataset file (optional, for defense info lookup)",
    ),
    output_dir: Path = typer.Option(
        Path("out/reports"),
        "--output",
        "-o",
        help="Output directory for report file",
    ),
    csv_dir: Optional[Path] = typer.Option(
        None,
        "--csv",
        "-c",
        help="Output directory for CSV tables (optional)",
    ),
):
    """
    Show evaluation summary and generate report for a results file.

    Displays utility, attack success rate, and breakdown by defense status.
    Also saves a markdown report to the output directory.

    Example:
        uv run dib report out/runs/results_gpt-4o-mini_20260127_110037.jsonl
    """
    import json
    from datetime import datetime
    from data_injection_bench.bench_types import Instance, EvaluationResult
    from data_injection_bench.eval.score import print_evaluation_summary

    console.print(f"[bold blue]Loading results from {results_file}...[/bold blue]")

    # Load results
    results = []
    raw_results = []
    with open(results_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data = json.loads(line)
                raw_results.append(data)
                results.append(EvaluationResult(**data))

    # Load instances (optional, for defense info lookup)
    instances = []
    instance_map = {}
    if dataset and dataset.exists():
        with open(dataset, encoding="utf-8") as f:
            content = f.read().strip()
            # Handle both JSON array and JSONL formats
            if content.startswith("["):
                data = json.loads(content)
            else:
                data = [json.loads(line) for line in content.splitlines() if line.strip()]
            instances = [Instance(**item) for item in data]
            instance_map = {inst.instance_id: inst for inst in instances}
        console.print(f"[dim]Loaded {len(instances)} instances from {dataset}[/dim]")

    # Extract model name from filename
    model_name = results_file.stem.replace("results_", "").rsplit("_", 2)[0]

    # Print summary to console
    print_evaluation_summary(results, model_name, instances if instances else None)

    # Generate and save markdown report
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = output_dir / f"report_{model_name}_{timestamp}.md"

    report_lines = _generate_markdown_report(model_name, results, raw_results, instance_map, csv_output_dir=csv_dir)
    report_file.write_text("\n".join(report_lines), encoding="utf-8")

    console.print(f"\n[bold green]✓ Report saved to {report_file}[/bold green]")
    if csv_dir:
        console.print(f"[green]CSV tables saved to {csv_dir}[/green]")


def _generate_markdown_report(
    model_name: str,
    results: list,
    raw_results: list,
    instance_map: dict,
    csv_output_dir: Optional[Path] = None,
) -> list:
    """Generate markdown report lines.

    Args:
        model_name: Name of the model
        results: List of EvaluationResult objects
        raw_results: List of raw result dictionaries
        instance_map: Mapping of instance_id to Instance objects
        csv_output_dir: Optional directory to save CSV tables
    """
    import re
    import csv
    from collections import defaultdict
    from datetime import datetime

    def get_defense_type(instance_id: str) -> str:
        if instance_id in instance_map:
            dt = getattr(instance_map[instance_id], "defense_type", None)
            return dt if dt else "none"
        if "_random_key" in instance_id:
            return "random_key"
        return "none"

    def parse_attack_type_from_id(instance_id: str) -> str:
        """Parse attack type from instance_id.
        Format: s000_t0_field_ins_v0[_gk1][_random_key]
        """
        from data_injection_bench.bench_types import ATTACK_TYPE_ABBREV

        # Extract 3-char attack type abbreviation
        # Pattern: _t{digit}_{field}_{attack_type}_v{digit}
        new_match = re.search(r'_t\d+_[^_]+_([a-z]{3})_v\d+', instance_id)
        if new_match:
            abbrev = new_match.group(1)
            return ATTACK_TYPE_ABBREV.get(abbrev, abbrev)
        return "unknown"

    def parse_category_from_id(instance_id: str) -> str:
        """Parse category from instance_id prefix."""
        # Common prefixes that indicate category
        if instance_id.startswith("api_"):
            return "github_api"
        elif instance_id.startswith("issue_"):
            return "github_issue"
        elif instance_id.startswith("email_"):
            return "email"
        elif instance_id.startswith("cycle"):
            return "reference_json"
        # Extract first part before _task_ as category hint
        match = re.match(r'^([a-z]+)', instance_id)
        if match:
            return match.group(1)
        return "unknown"

    def get_test_type(r) -> str:
        """Get test_type from result or look up from instances."""
        if r.test_type:
            return r.test_type
        # Fallback to instance lookup for old results without test_type
        if r.instance_id in instance_map:
            return instance_map[r.instance_id].test_type
        raise ValueError(f"Result {r.instance_id} has no test_type and instance not found. Re-run evaluation or provide matching dataset.")

    def is_attack_result(r) -> bool:
        """Determine if result is from an attack instance based on test_type."""
        return get_test_type(r) == "attack"


    def get_result_attr(r, attr: str, default=None):
        """Get attribute from result first, then fall back to instance lookup."""
        # First try to get from result itself (new format)
        val = getattr(r, attr, None)
        if val is not None:
            return val
        # Fall back to instance lookup (old format)
        if r.instance_id in instance_map:
            val = getattr(instance_map[r.instance_id], attr, default)
            if val is not None:
                return val
        # Special case: infer defense_type from instance_id
        if attr == "defense_type" and "_random_key" in r.instance_id:
            return "random_key"
        return default

    def _get_web_dom_defense_from_subcategory(subcategory: str) -> tuple:
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

    def get_expanded_defense_keys(r) -> list:
        """Get expanded defense keys for a result.

        For web_dom category: returns simple ["none"] or ["random_key"]
        (web_dom only tests random_key with correct guess, no breakdown needed)

        For other categories with random_key defense, returns multiple keys:
        - random_key (all)
        - random_key (no guess) / random_key (guess correct) / random_key (guess wrong)

        For other defenses, returns single key.
        """
        category = get_result_attr(r, "category", "")
        subcategory = get_result_attr(r, "subcategory", "")

        # Special handling for web_dom category
        # web_dom with random_key tests attacker with correct guess only
        if category == "web_dom":
            defense = get_result_attr(r, "defense_type", None)
            if defense == "random_key":
                return ["random_key (all)", "random_key (guess correct)"]
            else:
                return ["none"]

        # Standard handling for other categories
        defense = get_result_attr(r, "defense_type", None) or "none"

        if defense != "random_key":
            return [defense]

        # For random_key, expand based on guess_key_match
        keys = ["random_key (all)"]
        params = get_result_attr(r, "attack_params", {}) or {}
        guess_key_match = params.get("guess_key_match")

        if guess_key_match is None:
            keys.append("random_key (no guess)")
        elif guess_key_match:
            keys.append("random_key (guess correct)")
        else:
            keys.append("random_key (guess wrong)")

        return keys

    def save_csv(filename: str, headers: list, rows: list):
        """Save data to CSV file if csv_output_dir is specified."""
        if csv_output_dir is None:
            return
        csv_output_dir.mkdir(parents=True, exist_ok=True)
        filepath = csv_output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        console.print(f"  [dim]Saved CSV: {filepath}[/dim]")

    # Map attack types: merge override_pre and override_post into insert_incomplete
    def get_attack_type_label(at: str) -> str:
        if at in ("override_pre", "override_post"):
            return "insert_incomplete"
        return at

    lines = []
    lines.append(f"# Evaluation Report: {model_name}")
    lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Separate results based on attack_type
    benign_results = [r for r in results if not is_attack_result(r)]
    attack_results = [r for r in results if is_attack_result(r)]
    # Filter to insert_complete only for main ASR metrics
    insert_complete_results = [r for r in attack_results if get_result_attr(r, "attack_type", "") == "insert_complete"]

    # Overall stats
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total instances**: {len(results)}")

    if benign_results:
        benign_correct = sum(1 for r in benign_results if r.benign_correct)
        benign_pct = benign_correct / len(benign_results) * 100
        lines.append(f"- **Benign Utility**: {benign_correct}/{len(benign_results)} ({benign_pct:.1f}%)")

    if insert_complete_results:
        attack_success = sum(1 for r in insert_complete_results if r.attack_successful)
        attack_pct = attack_success / len(insert_complete_results) * 100
        lines.append(f"- **Attack Success Rate (ASR)**: {attack_success}/{len(insert_complete_results)} ({attack_pct:.1f}%) *(insert_complete only)*")

    # Task Composition
    lines.append("")
    lines.append("## Task Composition")
    lines.append("")

    # By Category composition
    comp_by_category = defaultdict(lambda: {"benign": 0, "attack": 0})
    for r in results:
        category = get_result_attr(r, "category", "unknown")
        if is_attack_result(r):
            comp_by_category[category]["attack"] += 1
        else:
            comp_by_category[category]["benign"] += 1

    lines.append("### By Category")
    lines.append("")
    lines.append("| Category | Benign | Attack | Total |")
    lines.append("| --- | --- | --- | --- |")
    for category in sorted(comp_by_category.keys()):
        b = comp_by_category[category]["benign"]
        a = comp_by_category[category]["attack"]
        lines.append(f"| {category} | {b} | {a} | {b + a} |")

    # By Task Type composition
    comp_by_task = defaultdict(lambda: {"benign": 0, "attack": 0})
    for r in results:
        task_type = get_result_attr(r, "task_type", "unknown")
        if is_attack_result(r):
            comp_by_task[task_type]["attack"] += 1
        else:
            comp_by_task[task_type]["benign"] += 1

    lines.append("")
    lines.append("### By Task Type")
    lines.append("")
    lines.append("| Task Type | Benign | Attack | Total |")
    lines.append("| --- | --- | --- | --- |")
    for task_type in sorted(comp_by_task.keys()):
        b = comp_by_task[task_type]["benign"]
        a = comp_by_task[task_type]["attack"]
        lines.append(f"| {task_type} | {b} | {a} | {b + a} |")

    # By Defense composition
    comp_by_defense = defaultdict(lambda: {"benign": 0, "attack": 0})
    for r in results:
        for defense_key in get_expanded_defense_keys(r):
            if is_attack_result(r):
                comp_by_defense[defense_key]["attack"] += 1
            else:
                comp_by_defense[defense_key]["benign"] += 1

    lines.append("")
    lines.append("### By Defense")
    lines.append("")
    lines.append("| Defense | Benign | Attack | Total |")
    lines.append("| --- | --- | --- | --- |")
    for defense in sorted(comp_by_defense.keys()):
        b = comp_by_defense[defense]["benign"]
        a = comp_by_defense[defense]["attack"]
        lines.append(f"| {defense} | {b} | {a} | {b + a} |")

    # By Format composition
    comp_by_format = defaultdict(lambda: {"benign": 0, "attack": 0})
    for r in results:
        fmt = get_result_attr(r, "format", "unknown")
        if is_attack_result(r):
            comp_by_format[fmt]["attack"] += 1
        else:
            comp_by_format[fmt]["benign"] += 1

    lines.append("")
    lines.append("### By Format")
    lines.append("")
    lines.append("| Format | Benign | Attack | Total |")
    lines.append("| --- | --- | --- | --- |")
    for fmt in sorted(comp_by_format.keys()):
        b = comp_by_format[fmt]["benign"]
        a = comp_by_format[fmt]["attack"]
        lines.append(f"| {fmt} | {b} | {a} | {b + a} |")

    # Defense breakdown (insert_complete only)
    if insert_complete_results:
        defended = [r for r in insert_complete_results if get_defense_type(r.instance_id) != "none"]
        undefended = [r for r in insert_complete_results if get_defense_type(r.instance_id) == "none"]

        if defended and undefended:
            lines.append("")
            lines.append("## Defense Comparison")
            lines.append("")
            lines.append("| Defense | Attack Total | Attack Success | ASR |")
            lines.append("| --- | --- | --- | --- |")

            undef_success = sum(1 for r in undefended if r.attack_successful)
            undef_pct = undef_success / len(undefended) * 100 if undefended else 0
            lines.append(f"| No defense | {len(undefended)} | {undef_success} | {undef_pct:.1f}% |")

            def_success = sum(1 for r in defended if r.attack_successful)
            def_pct = def_success / len(defended) * 100 if defended else 0
            defense_name = get_defense_type(defended[0].instance_id) if defended else "defended"
            lines.append(f"| {defense_name} | {len(defended)} | {def_success} | {def_pct:.1f}% |")

    # By Attack Type (merge override_pre/post into insert_incomplete)
    if attack_results:
        by_attack = defaultdict(list)
        for r in attack_results:
            attack_type = get_result_attr(r, "attack_type", "unknown")
            attack_label = get_attack_type_label(attack_type)
            by_attack[attack_label].append(r)

        if by_attack:
            lines.append("")
            lines.append("## By Attack Type")
            lines.append("")
            lines.append("| Attack Type | Total | Success | ASR |")
            lines.append("| --- | --- | --- | --- |")
            for attack_type, attack_list in sorted(by_attack.items()):
                success = sum(1 for r in attack_list if r.attack_successful)
                pct = success / len(attack_list) * 100 if attack_list else 0
                lines.append(f"| {attack_type} | {len(attack_list)} | {success} | {pct:.1f}% |")

    # By Defense Status (with expanded random_key variants, insert_complete only)
    if insert_complete_results:
        by_defense = defaultdict(list)
        for r in insert_complete_results:
            for defense_key in get_expanded_defense_keys(r):
                by_defense[defense_key].append(r)

        if len(by_defense) > 0:
            lines.append("")
            lines.append("## By Defense Status")
            lines.append("")
            lines.append("| Defense | Total | Success | ASR |")
            lines.append("| --- | --- | --- | --- |")
            csv_rows = []
            for defense, defense_list in sorted(by_defense.items()):
                success = sum(1 for r in defense_list if r.attack_successful)
                pct = success / len(defense_list) * 100 if defense_list else 0
                lines.append(f"| {defense} | {len(defense_list)} | {success} | {pct:.1f}% |")
                csv_rows.append([defense, len(defense_list), success, f"{pct:.1f}"])

            save_csv("by_defense.csv", ["defense", "total", "success", "asr"], csv_rows)

    if attack_results:
        # Build matrix: attack_type_label -> format -> defense -> results
        attack_format_defense_matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for r in attack_results:
            attack_type = get_result_attr(r, "attack_type", "unknown")
            attack_label = get_attack_type_label(attack_type)
            fmt = get_result_attr(r, "format", "unknown")
            for defense_key in get_expanded_defense_keys(r):
                attack_format_defense_matrix[attack_label][fmt][defense_key].append(r)

        # Also build aggregate (all formats combined)
        attack_defense_matrix = defaultdict(lambda: defaultdict(list))
        for r in attack_results:
            attack_type = get_result_attr(r, "attack_type", "unknown")
            attack_label = get_attack_type_label(attack_type)
            for defense_key in get_expanded_defense_keys(r):
                attack_defense_matrix[attack_label][defense_key].append(r)

        # Collect all expanded defense keys
        all_defense_keys = set()
        for r in attack_results:
            all_defense_keys.update(get_expanded_defense_keys(r))
        defenses = sorted(all_defense_keys)

        # Collect all formats
        all_formats = sorted(set(get_result_attr(r, "format", "unknown") for r in attack_results))

        if len(defenses) > 1 or defenses != ["none"]:
            lines.append("")
            lines.append("## Attack Type × Defense")
            lines.append("")
            header = "| Attack Type | " + " | ".join(defenses) + " |"
            lines.append(header)
            lines.append("| --- | " + " | ".join(["---"] * len(defenses)) + " |")

            for attack_label in sorted(attack_defense_matrix.keys()):
                # Total row for this attack type
                row = f"| {attack_label} |"
                for defense in defenses:
                    results_list = attack_defense_matrix[attack_label][defense]
                    if results_list:
                        success = sum(1 for r in results_list if r.attack_successful)
                        pct = success / len(results_list) * 100
                        row += f" {success}/{len(results_list)} ({pct:.0f}%) |"
                    else:
                        row += " - |"
                lines.append(row)

                # Sub-rows by format
                for fmt in all_formats:
                    row = f"| - {fmt} |"
                    for defense in defenses:
                        results_list = attack_format_defense_matrix[attack_label][fmt][defense]
                        if results_list:
                            success = sum(1 for r in results_list if r.attack_successful)
                            pct = success / len(results_list) * 100
                            row += f" {success}/{len(results_list)} ({pct:.0f}%) |"
                        else:
                            row += " - |"
                    lines.append(row)

    # Task Type × Defense Matrix (with expanded random_key variants, insert_complete only)
    if insert_complete_results:
        task_defense_matrix = defaultdict(lambda: defaultdict(list))
        for r in insert_complete_results:
            task_type = get_result_attr(r, "task_type", "unknown")
            for defense_key in get_expanded_defense_keys(r):
                task_defense_matrix[task_type][defense_key].append(r)

        # Collect all expanded defense keys
        all_defense_keys = set()
        for r in insert_complete_results:
            all_defense_keys.update(get_expanded_defense_keys(r))
        defenses = sorted(all_defense_keys)

        if len(defenses) > 1 or defenses != ["none"]:
            lines.append("")
            lines.append("## Task Type × Defense")
            lines.append("")
            header = "| Task Type | " + " | ".join(defenses) + " |"
            lines.append(header)
            lines.append("| --- | " + " | ".join(["---"] * len(defenses)) + " |")

            for task_type in sorted(task_defense_matrix.keys()):
                row = f"| {task_type} |"
                for defense in defenses:
                    results_list = task_defense_matrix[task_type][defense]
                    if results_list:
                        success = sum(1 for r in results_list if r.attack_successful)
                        pct = success / len(results_list) * 100
                        row += f" {success}/{len(results_list)} ({pct:.0f}%) |"
                    else:
                        row += " - |"
                lines.append(row)

    # By Attack Parameters (insert_complete only)
    if insert_complete_results:
        # Group by key parameters: quote_style, guess_key_match
        by_quote_style = defaultdict(list)
        by_guess_key = defaultdict(list)

        for r in insert_complete_results:
            params = get_result_attr(r, "attack_params", {}) or {}
            quote_style = params.get("quote_style")
            guess_key_match = params.get("guess_key_match")

            if quote_style:
                by_quote_style[quote_style].append(r)
            if guess_key_match is not None:
                key = "correct" if guess_key_match else "incorrect"
                by_guess_key[key].append(r)

        if by_quote_style or by_guess_key:
            lines.append("")
            lines.append("## By Attack Parameters")
            lines.append("")
            lines.append("| Parameter | Total | Success | ASR |")
            lines.append("| --- | --- | --- | --- |")

            for param_val, param_list in sorted(by_quote_style.items()):
                success = sum(1 for r in param_list if r.attack_successful)
                pct = success / len(param_list) * 100 if param_list else 0
                lines.append(f"| quote_style={param_val} | {len(param_list)} | {success} | {pct:.1f}% |")

            for param_val, param_list in sorted(by_guess_key.items()):
                success = sum(1 for r in param_list if r.attack_successful)
                pct = success / len(param_list) * 100 if param_list else 0
                lines.append(f"| guess_key={param_val} | {len(param_list)} | {success} | {pct:.1f}% |")

    # By Category (insert_complete only for ASR)
    by_category = defaultdict(lambda: {"benign": [], "attack": []})
    for r in results:
        category = get_result_attr(r, "category", "unknown")
        if is_attack_result(r):
            # Only include insert_complete for ASR
            if get_result_attr(r, "attack_type", "") == "insert_complete":
                by_category[category]["attack"].append(r)
        else:
            by_category[category]["benign"].append(r)

    if by_category:
        lines.append("")
        lines.append("## By Category")
        lines.append("")
        lines.append("| Category | Benign (Utility) | Attack (ASR) |")
        lines.append("| --- | --- | --- |")
        for category, data in sorted(by_category.items()):
            benign_list = data["benign"]
            attack_list = data["attack"]

            if benign_list:
                b_correct = sum(1 for r in benign_list if r.benign_correct)
                b_pct = b_correct / len(benign_list) * 100
                benign_str = f"{b_correct}/{len(benign_list)} ({b_pct:.1f}%)"
            else:
                benign_str = "-"

            if attack_list:
                a_success = sum(1 for r in attack_list if r.attack_successful)
                a_pct = a_success / len(attack_list) * 100
                attack_str = f"{a_success}/{len(attack_list)} ({a_pct:.1f}%)"
            else:
                attack_str = "-"

            lines.append(f"| {category} | {benign_str} | {attack_str} |")

    # Category × Defense Matrix - split into two tables (web_dom has different defense columns)
    # Uses insert_complete only
    if insert_complete_results:
        # Separate web_dom from other categories
        web_dom_results = [r for r in insert_complete_results if get_result_attr(r, "category", "") == "web_dom"]
        other_results = [r for r in insert_complete_results if get_result_attr(r, "category", "") != "web_dom"]

        # Table 1: Other categories (with expanded random_key variants)
        if other_results:
            category_defense_matrix = defaultdict(lambda: defaultdict(list))
            for r in other_results:
                category = get_result_attr(r, "category", "unknown")
                for defense_key in get_expanded_defense_keys(r):
                    category_defense_matrix[category][defense_key].append(r)

            # Collect defense keys for non-web_dom
            all_defense_keys = set()
            for r in other_results:
                all_defense_keys.update(get_expanded_defense_keys(r))
            defenses = sorted(all_defense_keys)

            if len(defenses) > 1 or defenses != ["none"]:
                lines.append("")
                lines.append("## Category × Defense")
                lines.append("")
                header = "| Category | " + " | ".join(defenses) + " |"
                lines.append(header)
                lines.append("| --- | " + " | ".join(["---"] * len(defenses)) + " |")

                csv_rows = []
                for category in sorted(category_defense_matrix.keys()):
                    row = f"| {category} |"
                    csv_row = [category]
                    for defense in defenses:
                        results_list = category_defense_matrix[category][defense]
                        if results_list:
                            success = sum(1 for r in results_list if r.attack_successful)
                            pct = success / len(results_list) * 100
                            row += f" {success}/{len(results_list)} ({pct:.0f}%) |"
                            csv_row.extend([len(results_list), success, f"{pct:.1f}"])
                        else:
                            row += " - |"
                            csv_row.extend([0, 0, ""])
                    lines.append(row)
                    csv_rows.append(csv_row)

                csv_headers = ["category"]
                for defense in defenses:
                    csv_headers.extend([f"{defense}_total", f"{defense}_success", f"{defense}_asr"])
                save_csv("category_x_defense.csv", csv_headers, csv_rows)

        # Table 2: web_dom (simple none/random_key columns)
        if web_dom_results:
            web_dom_defense_matrix = defaultdict(list)
            for r in web_dom_results:
                for defense_key in get_expanded_defense_keys(r):
                    web_dom_defense_matrix[defense_key].append(r)

            web_dom_defenses = sorted(web_dom_defense_matrix.keys())

            # Display names for web_dom defense columns
            web_dom_defense_display = {
                "none": "id",
                "random_key": "random_id (correct)",
            }

            if web_dom_defenses:
                lines.append("")
                lines.append("## Category × Defense (web_dom)")
                lines.append("")
                lines.append("*Note: web_dom uses element ID randomization; only tests attacker with correct key guess.*")
                lines.append("")
                header_names = [web_dom_defense_display.get(d, d) for d in web_dom_defenses]
                header = "| Category | " + " | ".join(header_names) + " |"
                lines.append(header)
                lines.append("| --- | " + " | ".join(["---"] * len(web_dom_defenses)) + " |")

                row = "| web_dom |"
                csv_row = ["web_dom"]
                for defense in web_dom_defenses:
                    results_list = web_dom_defense_matrix[defense]
                    if results_list:
                        success = sum(1 for r in results_list if r.attack_successful)
                        pct = success / len(results_list) * 100
                        row += f" {success}/{len(results_list)} ({pct:.0f}%) |"
                        csv_row.extend([len(results_list), success, f"{pct:.1f}"])
                    else:
                        row += " - |"
                        csv_row.extend([0, 0, ""])
                lines.append(row)

                csv_headers = ["category"]
                for defense in web_dom_defenses:
                    csv_headers.extend([f"{defense}_total", f"{defense}_success", f"{defense}_asr"])
                save_csv("category_x_defense_web_dom.csv", csv_headers, [csv_row])

    # By Format
    by_format = defaultdict(lambda: {"benign": [], "attack": []})
    for r in results:
        fmt = get_result_attr(r, "format", "unknown")
        if is_attack_result(r):
            by_format[fmt]["attack"].append(r)
        else:
            by_format[fmt]["benign"].append(r)

    if by_format:
        lines.append("")
        lines.append("## By Format")
        lines.append("")
        lines.append("| Format | Benign (Utility) | Attack (ASR) |")
        lines.append("| --- | --- | --- |")
        for fmt, data in sorted(by_format.items()):
            benign_list = data["benign"]
            attack_list = data["attack"]

            if benign_list:
                b_correct = sum(1 for r in benign_list if r.benign_correct)
                b_pct = b_correct / len(benign_list) * 100
                benign_str = f"{b_correct}/{len(benign_list)} ({b_pct:.1f}%)"
            else:
                benign_str = "-"

            if attack_list:
                a_success = sum(1 for r in attack_list if r.attack_successful)
                a_pct = a_success / len(attack_list) * 100
                attack_str = f"{a_success}/{len(attack_list)} ({a_pct:.1f}%)"
            else:
                attack_str = "-"

            lines.append(f"| {fmt} | {benign_str} | {attack_str} |")

    # By Task Type
    by_task_type = defaultdict(lambda: {"benign": [], "attack": []})
    for r in results:
        task_type = get_result_attr(r, "task_type", "unknown")
        if is_attack_result(r):
            by_task_type[task_type]["attack"].append(r)
        else:
            by_task_type[task_type]["benign"].append(r)

    if by_task_type:
        lines.append("")
        lines.append("## By Task Type")
        lines.append("")
        lines.append("| Task Type | Benign (Utility) | Attack (ASR) |")
        lines.append("| --- | --- | --- |")
        for task_type, data in sorted(by_task_type.items()):
            benign_list = data["benign"]
            attack_list = data["attack"]

            if benign_list:
                b_correct = sum(1 for r in benign_list if r.benign_correct)
                b_pct = b_correct / len(benign_list) * 100
                benign_str = f"{b_correct}/{len(benign_list)} ({b_pct:.1f}%)"
            else:
                benign_str = "-"

            if attack_list:
                a_success = sum(1 for r in attack_list if r.attack_successful)
                a_pct = a_success / len(attack_list) * 100
                attack_str = f"{a_success}/{len(attack_list)} ({a_pct:.1f}%)"
            else:
                attack_str = "-"

            lines.append(f"| {task_type} | {benign_str} | {attack_str} |")

    # All Results
    lines.append("")
    lines.append("## All Results")
    lines.append("")
    lines.append("| Category | Instance ID | Type | Correct | Attack Success | Output |")
    lines.append("| --- | --- | --- | --- | --- | --- |")

    for r in results:
        category = get_result_attr(r, "category", "unknown")
        instance_id = r.instance_id
        test_type = get_test_type(r)

        correct = "✓" if r.benign_correct else "✗"
        attack_success = "⚠" if r.attack_successful else "-"

        # Truncate output for display
        output = str(r.model_output or "")[:80].replace("|", "\\|").replace("\n", " ")
        if len(str(r.model_output or "")) > 80:
            output += "..."

        lines.append(f"| {category} | {instance_id} | {test_type} | {correct} | {attack_success} | {output} |")

    lines.append("")
    return lines


def _generate_comparison_report(
    results_files: list,
    csv_output_dir: Optional[Path] = None,
) -> list:
    """Generate cross-model comparison report lines.

    Args:
        results_files: List of Path objects to result files
        csv_output_dir: Optional directory to save CSV tables

    Returns:
        List of markdown lines
    """
    import json
    import csv
    from datetime import datetime
    from collections import defaultdict
    from data_injection_bench.bench_types import EvaluationResult

    def save_csv(filename: str, headers: list, rows: list):
        if csv_output_dir is None:
            return
        csv_output_dir.mkdir(parents=True, exist_ok=True)
        filepath = csv_output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

    # Load all results
    all_results = {}
    for results_file in results_files:
        results = []
        with open(results_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    results.append(EvaluationResult(**data))

        if results:
            model_name = results[0].model_name
            if model_name in all_results:
                model_name = f"{model_name} ({results_file.stem})"
            all_results[model_name] = results

    models = sorted(all_results.keys())

    lines = []
    lines.append("# Cross-Model Comparison Report")
    lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"\nModels compared: {len(models)}")
    for model in models:
        lines.append(f"- {model}")
    lines.append("")

    # Overall Summary
    lines.append("## Overall Summary")
    lines.append("")
    lines.append("| Model | Instances | Benign Utility | Attack ASR |")
    lines.append("| --- | ---: | ---: | ---: |")

    csv_rows = []
    for model in models:
        results = all_results[model]
        benign = [r for r in results if r.test_type == "benign"]
        attack = [r for r in results if r.test_type == "attack"]

        benign_correct = sum(1 for r in benign if r.benign_correct)
        benign_pct = benign_correct / len(benign) * 100 if benign else 0

        attack_success = sum(1 for r in attack if r.attack_successful)
        attack_pct = attack_success / len(attack) * 100 if attack else 0

        lines.append(f"| {model} | {len(results)} | {benign_correct}/{len(benign)} ({benign_pct:.1f}%) | {attack_success}/{len(attack)} ({attack_pct:.1f}%) |")
        csv_rows.append([model, len(results), len(benign), benign_correct, f"{benign_pct:.1f}", len(attack), attack_success, f"{attack_pct:.1f}"])

    save_csv("comparison_summary.csv", ["model", "total", "benign_total", "benign_correct", "utility_pct", "attack_total", "attack_success", "asr_pct"], csv_rows)

    # By Attack Type
    all_attack_types = set()
    for results in all_results.values():
        for r in results:
            if r.test_type == "attack" and r.attack_type:
                all_attack_types.add(r.attack_type)
    attack_types = sorted(all_attack_types)

    if attack_types:
        lines.append("")
        lines.append("## ASR by Attack Type")
        lines.append("")
        header = "| Model | " + " | ".join(attack_types) + " |"
        lines.append(header)
        lines.append("| --- | " + " | ".join(["---:"] * len(attack_types)) + " |")

        csv_rows = []
        for model in models:
            results = all_results[model]
            row = f"| {model} |"
            csv_row = [model]
            for at in attack_types:
                at_results = [r for r in results if r.test_type == "attack" and r.attack_type == at]
                if at_results:
                    success = sum(1 for r in at_results if r.attack_successful)
                    pct = success / len(at_results) * 100
                    row += f" {success}/{len(at_results)} ({pct:.0f}%) |"
                    csv_row.append(f"{pct:.1f}")
                else:
                    row += " - |"
                    csv_row.append("")
            lines.append(row)
            csv_rows.append(csv_row)

        save_csv("comparison_by_attack_type.csv", ["model"] + attack_types, csv_rows)

    # By Defense
    lines.append("")
    lines.append("## ASR by Defense Status")
    lines.append("")
    defense_types = ["none", "random_key"]
    header = "| Model | " + " | ".join(defense_types) + " |"
    lines.append(header)
    lines.append("| --- | " + " | ".join(["---:"] * len(defense_types)) + " |")

    csv_rows = []
    for model in models:
        results = all_results[model]
        row = f"| {model} |"
        csv_row = [model]
        for defense in defense_types:
            if defense == "none":
                def_results = [r for r in results if r.test_type == "attack" and not r.defense_type]
            else:
                def_results = [r for r in results if r.test_type == "attack" and r.defense_type == defense]
            if def_results:
                success = sum(1 for r in def_results if r.attack_successful)
                pct = success / len(def_results) * 100
                row += f" {success}/{len(def_results)} ({pct:.0f}%) |"
                csv_row.append(f"{pct:.1f}")
            else:
                row += " - |"
                csv_row.append("")
        lines.append(row)
        csv_rows.append(csv_row)

    save_csv("comparison_by_defense.csv", ["model"] + defense_types, csv_rows)

    # By Category
    all_categories = set()
    for results in all_results.values():
        for r in results:
            if r.category:
                all_categories.add(r.category)
    categories = sorted(all_categories)

    if categories:
        lines.append("")
        lines.append("## ASR by Category")
        lines.append("")
        header = "| Model | " + " | ".join(categories) + " |"
        lines.append(header)
        lines.append("| --- | " + " | ".join(["---:"] * len(categories)) + " |")

        csv_rows = []
        for model in models:
            results = all_results[model]
            row = f"| {model} |"
            csv_row = [model]
            for cat in categories:
                cat_results = [r for r in results if r.test_type == "attack" and r.category == cat]
                if cat_results:
                    success = sum(1 for r in cat_results if r.attack_successful)
                    pct = success / len(cat_results) * 100
                    row += f" {success}/{len(cat_results)} ({pct:.0f}%) |"
                    csv_row.append(f"{pct:.1f}")
                else:
                    row += " - |"
                    csv_row.append("")
            lines.append(row)
            csv_rows.append(csv_row)

        save_csv("comparison_by_category.csv", ["model"] + categories, csv_rows)

    lines.append("")
    return lines


# =============================================================================
# Run All Command
# =============================================================================


@app.command()
def run(
    config_file: Path = typer.Argument(
        ...,
        help="Path to benchmark configuration file (YAML)",
        exists=True,
    ),
    skip_generate: bool = typer.Option(
        False,
        "--skip-generate",
        help="Skip dataset generation (use existing dataset)",
    ),
    skip_evaluate: bool = typer.Option(
        False,
        "--skip-evaluate",
        help="Skip evaluation (only generate and/or report)",
    ),
    skip_report: bool = typer.Option(
        False,
        "--skip-report",
        help="Skip report generation",
    ),
    dataset_file: Optional[Path] = typer.Option(
        None,
        "--dataset",
        "-d",
        help="Existing dataset file to use (requires --skip-generate)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
    csv_dir: Optional[Path] = typer.Option(
        None,
        "--csv",
        "-c",
        help="Output directory for CSV tables (optional)",
    ),
    jobs: int = typer.Option(
        1,
        "--jobs",
        "-j",
        help="Number of parallel model evaluations (default: 1 = sequential)",
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        "-r",
        help="Resume from existing result files, skipping already-evaluated instances",
    ),
    rerun_categories: Optional[str] = typer.Option(
        None,
        "--rerun-categories",
        help="Force re-run specific categories (comma-separated, e.g., 'web_dom,calendar'). Implies --resume for other categories.",
    ),
):
    """
    Run the full benchmark pipeline: generate → evaluate → report.

    Reads a benchmark configuration file and executes all steps:
    1. Generate benchmark instances for each category
    2. Evaluate each configured model on the dataset
    3. Generate reports for each model's results

    Use -j to run multiple model evaluations in parallel:
        uv run dib run configs/benchmark_full.yaml -j 3

    Use -r to resume from incomplete evaluations:
        uv run dib run configs/benchmark_full.yaml -r

    Example:
        uv run dib run configs/benchmark_full.yaml
        uv run dib run configs/benchmark_full.yaml --skip-generate --dataset out/generated/instances.jsonl
        uv run dib run configs/benchmark_full.yaml -j 3 -r  # Resume parallel evaluation
    """
    import yaml
    from datetime import datetime

    console.print(f"[bold blue]Running benchmark from config: {config_file}[/bold blue]")

    # Load benchmark config
    try:
        with open(config_file, encoding="utf-8") as f:
            config_data = yaml.safe_load(f)
    except Exception as e:
        console.print(f"[bold red]✗ Error loading config file: {e}[/bold red]")
        raise typer.Exit(1)

    # Parse config
    raw_categories = config_data.get("categories", [])
    formats = config_data.get("formats", ["json"])
    models = config_data.get("models", [])
    default_seed_limit = config_data.get("seed_limit")
    output_dir = Path(config_data.get("output_dir", "out"))
    defense = config_data.get("defense", "random_key")
    defense_only = config_data.get("defense_only", False)
    no_defense = config_data.get("no_defense", False)
    random_id_length = config_data.get("random_id_length", 8)
    instance_limit = config_data.get("instance_limit")
    attack_types = config_data.get("attack_types")  # None = all attacks

    # Parse categories - support both string and dict formats
    # String format: "category_name" - uses default seed_limit
    # Dict format: {"name": "category_name", "seed_limit": N, "subcategories": [...]} - uses per-category settings
    categories = []
    category_seed_limits = {}
    category_subcategories = {}  # Per-category subcategory filters
    for cat_entry in raw_categories:
        if isinstance(cat_entry, str):
            categories.append(cat_entry)
        elif isinstance(cat_entry, dict):
            cat_name = cat_entry.get("name")
            if cat_name:
                categories.append(cat_name)
                if "seed_limit" in cat_entry:
                    category_seed_limits[cat_name] = cat_entry["seed_limit"]
                if "subcategories" in cat_entry:
                    category_subcategories[cat_name] = cat_entry["subcategories"]

    console.print(f"\n[cyan]Configuration:[/cyan]")
    console.print(f"  Categories: {categories}")
    console.print(f"  Formats: {formats}")
    console.print(f"  Models: {[m.get('model') for m in models]}")
    console.print(f"  Default seed limit: {default_seed_limit}")
    if category_seed_limits:
        console.print(f"  Per-category seed limits: {category_seed_limits}")
    if category_subcategories:
        console.print(f"  Per-category subcategories: {category_subcategories}")
    if attack_types:
        console.print(f"  Attack types: {attack_types}")
    console.print(f"  Output dir: {output_dir}")

    if not categories:
        console.print("[red]No categories specified in config[/red]")
        raise typer.Exit(1)

    if not models:
        console.print("[red]No models specified in config[/red]")
        raise typer.Exit(1)

    # Prepare output directories
    generated_dir = output_dir / "generated"
    runs_dir = output_dir / "runs"
    reports_dir = output_dir / "reports"
    generated_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset_path = dataset_file or (generated_dir / f"instances_{timestamp}.jsonl")

    # ==========================================================================
    # Step 1: Generate
    # ==========================================================================
    if not skip_generate:
        console.print(f"\n[bold magenta]Step 1/3: Generating benchmark dataset[/bold magenta]")

        from data_injection_bench.generator import DatasetGenerator
        from data_injection_bench.bench_types import Category, Format as FmtEnum

        generator = DatasetGenerator()
        all_instances = []

        # Determine which instances to generate
        generate_undefended = not defense_only
        generate_defended = not no_defense

        for cat_name in categories:
            try:
                cat = Category(cat_name)
            except ValueError:
                console.print(f"[yellow]Warning: Unknown category '{cat_name}', skipping[/yellow]")
                continue

            # Determine seed limit for this category (per-category overrides default)
            cat_seed_limit = category_seed_limits.get(cat_name, default_seed_limit)
            console.print(f"\n[cyan]Generating for category: {cat.value} (seed_limit={cat_seed_limit})[/cyan]")

            # Convert format strings to Format enums
            fmt_enums = []
            for fmt in formats:
                try:
                    fmt_enums.append(FmtEnum(fmt))
                except ValueError:
                    console.print(f"[yellow]Warning: Unknown format '{fmt}', skipping[/yellow]")

            if not fmt_enums:
                fmt_enums = [FmtEnum.JSON]

            defense_params = {"random_id_length": random_id_length}
            cat_subcategories = category_subcategories.get(cat_name)  # Get subcategory filter

            # Generate undefended instances
            if generate_undefended:
                try:
                    undefended = generator.generate_instances(
                        category=cat,
                        formats=fmt_enums,
                        seed_limit=cat_seed_limit,
                        defense_type=None,
                        defense_params=None,
                        attack_types=attack_types,
                        subcategories=cat_subcategories,
                    )
                    all_instances.extend(undefended)
                    console.print(f"  [green]✓ {len(undefended)} undefended instances[/green]")
                except Exception as e:
                    console.print(f"  [red]Error generating undefended: {e}[/red]")
                    if verbose:
                        import traceback
                        console.print(traceback.format_exc())

            # Generate defended instances
            if generate_defended:
                try:
                    defended = generator.generate_instances(
                        category=cat,
                        formats=fmt_enums,
                        seed_limit=cat_seed_limit,
                        defense_type=defense,
                        defense_params=defense_params,
                        attack_types=attack_types,
                        subcategories=cat_subcategories,
                    )
                    all_instances.extend(defended)
                    console.print(f"  [green]✓ {len(defended)} defended instances[/green]")
                except Exception as e:
                    console.print(f"  [red]Error generating defended: {e}[/red]")
                    if verbose:
                        import traceback
                        console.print(traceback.format_exc())

        # Save combined dataset
        generator.save_instances(all_instances, dataset_path)
        console.print(f"\n[bold green]✓ Generated {len(all_instances)} total instances[/bold green]")
        console.print(f"  Saved to: {dataset_path}")
    else:
        console.print(f"\n[yellow]Skipping generation, using dataset: {dataset_path}[/yellow]")
        if not dataset_path.exists():
            console.print(f"[red]Dataset file not found: {dataset_path}[/red]")
            raise typer.Exit(1)

    # ==========================================================================
    # Step 2: Evaluate
    # ==========================================================================
    results_files = []

    if not skip_evaluate:
        console.print(f"\n[bold magenta]Step 2/3: Evaluating models[/bold magenta]")

        import json as json_module
        from data_injection_bench.generator import DatasetGenerator
        from data_injection_bench.eval import OpenAIProvider, AnthropicProvider, GoogleProvider, ModelRunner, Scorer
        from data_injection_bench.bench_types import ToolAccessMode, EvaluationResult
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Load instances
        generator = DatasetGenerator()
        all_instances = generator.load_instances(dataset_path)

        if instance_limit:
            all_instances = all_instances[:instance_limit]
            console.print(f"  [dim]Limited to {instance_limit} instances[/dim]")

        console.print(f"  Loaded {len(all_instances)} instances")

        def find_existing_results(model_name: str) -> tuple[Path | None, list[EvaluationResult], set[str]]:
            """Find existing results file for a model.

            Returns (results_file, existing_results, completed_ids).
            Searches both runs_dir and runs_dir/archive.
            """
            pattern = f"results_{model_name.replace('/', '_')}_*.jsonl"
            # Search in runs_dir first, then archive
            existing_files = sorted(runs_dir.glob(pattern))
            archive_path = runs_dir / "archive"
            if archive_path.exists():
                existing_files.extend(sorted(archive_path.glob(pattern)))
            # Sort all by modification time to get the most recent
            existing_files = sorted(existing_files, key=lambda p: p.stat().st_mtime)
            if not existing_files:
                return None, [], set()

            # Use the most recent file
            latest_file = existing_files[-1]
            existing_results = []
            completed_ids = set()

            try:
                with open(latest_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json_module.loads(line)
                            existing_results.append(EvaluationResult(**data))
                            # Only count as completed if no error (retry errors on resume)
                            if data.get("error") is None:
                                completed_ids.add(data.get("instance_id"))
            except Exception:
                return None, [], set()

            return latest_file, existing_results, completed_ids

        # Pre-compute resume info for each model if resuming
        model_resume_info: dict[str, tuple[Path | None, list, set[str], list]] = {}
        archive_dir = runs_dir / "archive"

        # Parse rerun_categories (implies resume for other categories)
        force_rerun_cats: set[str] = set()
        if rerun_categories:
            force_rerun_cats = {c.strip() for c in rerun_categories.split(",")}
            console.print(f"  [yellow]Force re-run categories: {force_rerun_cats}[/yellow]")
            resume = True  # Imply resume for non-rerun categories

        if resume:
            for mc in models:
                model_name = mc.get("model")
                existing_file, existing_results, completed_ids = find_existing_results(model_name)

                # If rerun_categories specified, remove those from completed_ids
                # so they get re-run while keeping results from other categories
                if force_rerun_cats:
                    # Get instance_ids that belong to force_rerun categories
                    rerun_instance_ids = {i.instance_id for i in all_instances if i.category in force_rerun_cats}
                    completed_ids = completed_ids - rerun_instance_ids
                    # Also filter existing_results to exclude rerun categories
                    existing_results = [r for r in existing_results if r.instance_id not in rerun_instance_ids]

                # Filter to instances not yet completed
                remaining_instances = [i for i in all_instances if i.instance_id not in completed_ids]
                model_resume_info[model_name] = (existing_file, existing_results, completed_ids, remaining_instances)

                if existing_file:
                    console.print(f"  [dim]{model_name}: Found {len(completed_ids)} completed, {len(remaining_instances)} remaining[/dim]")
                    # Move existing file to archive directory (if not already there)
                    archive_dir.mkdir(parents=True, exist_ok=True)
                    if existing_file.parent != archive_dir:
                        archived_file = archive_dir / existing_file.name
                        existing_file.rename(archived_file)
                        console.print(f"  [dim]  Archived: {archived_file}[/dim]")
                        # Update the stored reference to archived location
                        model_resume_info[model_name] = (archived_file, existing_results, completed_ids, remaining_instances)
                    else:
                        console.print(f"  [dim]  Using archived: {existing_file}[/dim]")

        def evaluate_model(
            model_config: dict,
            progress_callback: Callable[[int, int], None] | None = None,
        ) -> tuple:
            """Evaluate a single model. Returns (model_name, results_file, error).

            Results are saved incrementally after each instance completes,
            so progress is preserved even if the script is interrupted.
            """
            model_name = model_config.get("model")
            provider_name = model_config.get("provider", "openai")
            tool_access = model_config.get("tool_access", "none")

            try:
                # Get instances to evaluate (filtered if resuming)
                if resume and model_name in model_resume_info:
                    existing_file, existing_results, completed_ids, instances_to_run = model_resume_info[model_name]
                else:
                    existing_file, existing_results, completed_ids, instances_to_run = None, [], set(), all_instances

                # Create output file path
                results_file = runs_dir / f"results_{model_name.replace('/', '_')}_{timestamp}.jsonl"

                # Skip if all instances already completed successfully
                if not instances_to_run:
                    # Copy existing successful results to new file
                    # Filter to only include results for instances in current dataset
                    # Deduplicate: keep only first occurrence of each instance_id
                    current_instance_ids = {i.instance_id for i in all_instances}
                    seen_ids: set[str] = set()
                    with open(results_file, "w", encoding="utf-8") as f:
                        for result in existing_results:
                            if result.error is None and result.instance_id in current_instance_ids:
                                if result.instance_id not in seen_ids:
                                    seen_ids.add(result.instance_id)
                                    f.write(result.model_dump_json() + "\n")
                    return (model_name, results_file, None)

                # Initialize provider
                if provider_name == "openai":
                    llm_provider = OpenAIProvider(model_name=model_name)
                elif provider_name == "anthropic":
                    llm_provider = AnthropicProvider(model_name=model_name)
                elif provider_name == "google":
                    llm_provider = GoogleProvider(model_name=model_name)
                else:
                    return (model_name, None, f"Provider '{provider_name}' not implemented")

                # Initialize runner and scorer
                tool_mode = ToolAccessMode.PYTHON if tool_access == "python" else ToolAccessMode.NONE
                runner = ModelRunner(llm_provider, tool_access_mode=tool_mode)
                scorer = Scorer()

                # Open file for incremental writing
                # First, write existing successful results if resuming (exclude errors to retry)
                # Filter to only include results for instances in current dataset
                # Deduplicate: keep only first occurrence of each instance_id
                current_instance_ids = {i.instance_id for i in all_instances}
                seen_ids: set[str] = set()
                with open(results_file, "w", encoding="utf-8") as f:
                    for result in existing_results:
                        if result.error is None and result.instance_id in current_instance_ids:
                            if result.instance_id not in seen_ids:
                                seen_ids.add(result.instance_id)
                                f.write(result.model_dump_json() + "\n")

                # Process instances one by one and save incrementally
                for i, instance in enumerate(instances_to_run, 1):
                    if verbose and not progress_callback:
                        print(f"[{i}/{len(instances_to_run)}] Running {instance.instance_id}...")

                    # Run single instance
                    result = runner.run_instance(instance, verbose and not progress_callback)

                    # Score single result
                    scored_results = scorer.score_results([instance], [result], verbose=False)
                    scored_result = scored_results[0]

                    # Append to file immediately
                    with open(results_file, "a", encoding="utf-8") as f:
                        f.write(scored_result.model_dump_json() + "\n")

                    if verbose and not progress_callback and result.error:
                        print(f"  Error: {result.error}")

                    # Update progress
                    if progress_callback:
                        progress_callback(i, len(instances_to_run))

                return (model_name, results_file, None)

            except Exception as e:
                import traceback
                error_msg = str(e)
                if verbose:
                    error_msg = traceback.format_exc()
                # Return partial results file if it exists
                results_file = runs_dir / f"results_{model_name.replace('/', '_')}_{timestamp}.jsonl"
                if results_file.exists():
                    return (model_name, results_file, f"Partial results saved. Error: {error_msg}")
                return (model_name, None, error_msg)

        if jobs > 1 and len(models) > 1:
            # Parallel evaluation with progress bars
            actual_jobs = min(jobs, len(models))
            console.print(f"  [cyan]Running {len(models)} models in parallel (max {actual_jobs} workers)[/cyan]\n")

            # Create progress display with one task per model
            with Progress(
                TextColumn("[bold blue]{task.description:<40}"),
                BarColumn(bar_width=30),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                refresh_per_second=4,
            ) as progress:
                # Create task for each model (with correct totals for resume)
                model_tasks: dict[str, TaskID] = {}
                for mc in models:
                    model_name = mc.get("model")
                    if resume and model_name in model_resume_info:
                        _, _, _, remaining = model_resume_info[model_name]
                        total = len(remaining)
                    else:
                        total = len(all_instances)
                    task_id = progress.add_task(model_name, total=max(total, 1))  # min 1 to avoid division by zero
                    model_tasks[model_name] = task_id

                def evaluate_model_with_progress(model_config: dict) -> tuple:
                    """Wrapper that updates progress bar."""
                    model_name = model_config.get("model")
                    task_id = model_tasks[model_name]

                    # Check if already complete (no remaining instances)
                    if resume and model_name in model_resume_info:
                        _, _, _, remaining = model_resume_info[model_name]
                        if not remaining:
                            # Mark progress as complete
                            progress.update(task_id, completed=1)
                            return evaluate_model(model_config, progress_callback=None)

                    def update_progress(current: int, total: int):
                        progress.update(task_id, completed=current)

                    return evaluate_model(model_config, progress_callback=update_progress)

                with ThreadPoolExecutor(max_workers=actual_jobs) as executor:
                    futures = {executor.submit(evaluate_model_with_progress, mc): mc for mc in models}

                    for future in as_completed(futures):
                        model_name, results_file, error = future.result()
                        if error:
                            console.print(f"  [red]✗ {model_name}: {error}[/red]")
                        else:
                            results_files.append((model_name, results_file))

            # Print final status after progress bars complete
            console.print()
            for model_name, results_file in results_files:
                if resume and model_name in model_resume_info:
                    _, existing_results, _, remaining = model_resume_info[model_name]
                    if existing_results and not remaining:
                        console.print(f"  [green]✓ {model_name}: {results_file} [dim](all {len(existing_results)} cached)[/dim][/green]")
                    elif existing_results:
                        console.print(f"  [green]✓ {model_name}: {results_file} [dim](resumed, +{len(remaining)} new)[/dim][/green]")
                    else:
                        console.print(f"  [green]✓ {model_name}: {results_file}[/green]")
                else:
                    console.print(f"  [green]✓ {model_name}: {results_file}[/green]")
        else:
            # Sequential evaluation with progress bar
            for model_config in models:
                model_name = model_config.get("model")
                provider_name = model_config.get("provider", "openai")

                # Determine instance count for progress bar
                if resume and model_name in model_resume_info:
                    _, _, completed_ids, remaining = model_resume_info[model_name]
                    instance_count = len(remaining)
                    if not remaining:
                        # All instances already completed
                        existing_file = model_resume_info[model_name][0]
                        console.print(f"\n[cyan]Evaluating model: {model_name} ({provider_name})[/cyan]")
                        console.print(f"  [yellow]All {len(completed_ids)} instances already completed[/yellow]")
                        if existing_file:
                            results_files.append((model_name, existing_file))
                            console.print(f"  [green]✓ Using existing results: {existing_file}[/green]")
                        continue
                else:
                    instance_count = len(all_instances)

                console.print(f"\n[cyan]Evaluating model: {model_name} ({provider_name})[/cyan]")
                if resume and model_name in model_resume_info:
                    _, _, completed_ids, _ = model_resume_info[model_name]
                    if completed_ids:
                        console.print(f"  [dim]Resuming: {len(completed_ids)} done, {instance_count} remaining[/dim]")

                # Use progress bar for sequential mode too
                with Progress(
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=40),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    console=console,
                    refresh_per_second=4,
                ) as progress:
                    task_id = progress.add_task(f"  {model_name}", total=max(instance_count, 1))

                    def update_progress(current: int, total: int):
                        progress.update(task_id, completed=current)

                    model_name, results_file, error = evaluate_model(model_config, progress_callback=update_progress)

                if error:
                    console.print(f"  [red]Error evaluating {model_name}: {error}[/red]")
                else:
                    results_files.append((model_name, results_file))
                    console.print(f"  [green]✓ Results saved to: {results_file}[/green]")
    else:
        console.print(f"\n[yellow]Skipping evaluation[/yellow]")
        # Try to find existing results files for report generation
        for model_config in models:
            model_name = model_config.get("model")
            pattern = f"results_{model_name.replace('/', '_')}_*.jsonl"
            existing = sorted(runs_dir.glob(pattern))
            if existing:
                results_files.append((model_name, existing[-1]))
                console.print(f"  Found existing results for {model_name}: {existing[-1]}")

    # ==========================================================================
    # Step 3: Report
    # ==========================================================================
    if not skip_report and results_files:
        console.print(f"\n[bold magenta]Step 3/3: Generating reports[/bold magenta]")

        import json
        from data_injection_bench.bench_types import Instance, EvaluationResult
        from data_injection_bench.eval.score import print_evaluation_summary

        # Load instances for metadata lookup (required for attack detection)
        instances = []
        instance_map = {}
        with open(dataset_path, encoding="utf-8") as f:
            content = f.read().strip()
            if content.startswith("["):
                data = json.loads(content)
            else:
                data = [json.loads(line) for line in content.splitlines() if line.strip()]
            instances = [Instance(**item) for item in data]
            instance_map = {inst.instance_id: inst for inst in instances}

        for model_name, results_file in results_files:
            console.print(f"\n[cyan]Generating report for: {model_name}[/cyan]")

            try:
                # Load results
                results = []
                raw_results = []
                with open(results_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            raw_results.append(data)
                            results.append(EvaluationResult(**data))

                # Print summary
                print_evaluation_summary(results, model_name, instances)

                # Generate markdown report
                report_file = reports_dir / f"report_{model_name.replace('/', '_')}_{timestamp}.md"
                report_lines = _generate_markdown_report(model_name, results, raw_results, instance_map, csv_output_dir=csv_dir)
                report_file.write_text("\n".join(report_lines), encoding="utf-8")

                console.print(f"  [green]✓ Report saved to: {report_file}[/green]")
                if csv_dir:
                    console.print(f"  [green]CSV tables saved to: {csv_dir}[/green]")

            except Exception as e:
                console.print(f"  [red]Error generating report for {model_name}: {e}[/red]")
                if verbose:
                    import traceback
                    console.print(traceback.format_exc())

        # Generate comparison report if multiple models
        if len(results_files) > 1:
            console.print(f"\n[cyan]Generating cross-model comparison report...[/cyan]")
            try:
                comparison_file = reports_dir / f"comparison_{timestamp}.md"
                comparison_lines = _generate_comparison_report(
                    [rf for _, rf in results_files],
                    csv_output_dir=csv_dir,
                )
                comparison_file.write_text("\n".join(comparison_lines), encoding="utf-8")
                console.print(f"  [green]✓ Comparison report saved to: {comparison_file}[/green]")
            except Exception as e:
                console.print(f"  [red]Error generating comparison report: {e}[/red]")
                if verbose:
                    import traceback
                    console.print(traceback.format_exc())

    elif skip_report:
        console.print(f"\n[yellow]Skipping report generation[/yellow]")
    else:
        console.print(f"\n[yellow]No results files to report on[/yellow]")

    console.print(f"\n[bold green]✓ Benchmark run complete![/bold green]")
    console.print(f"  Dataset: {dataset_path}")
    console.print(f"  Results: {runs_dir}")
    console.print(f"  Reports: {reports_dir}")


# =============================================================================
# Info Command
# =============================================================================


@app.command()
def info():
    """
    Display benchmark information and statistics.

    Shows available categories, formats, task types, attack types,
    and directory structure.
    """
    console.print("[bold blue]Data Injection Benchmark Information[/bold blue]\n")

    # Count seeds per category
    seeds_dir = Path("data/seeds")
    def count_seeds(category_dir: str, pattern: str = "*.json") -> int:
        cat_path = seeds_dir / category_dir
        if not cat_path.exists():
            return 0
        return len(list(cat_path.glob(pattern)))

    # Categories
    table = Table(title="Available Categories", show_header=True)
    table.add_column("Category", style="cyan")
    table.add_column("Seeds", style="green", justify="right")
    table.add_column("Description", style="dim")

    categories = [
        ("calendar", "calendar", "Calendar events (Google Calendar)"),
        ("cloud_drive", "cloud_drive", "Cloud storage files (Google Drive)"),
        ("email", "email", "Email messages (Gmail)"),
        ("github_comments", "github_comments", "GitHub issue comments"),
        ("github_issue", "github_issue", "GitHub issues"),
        ("reference_json", "reference_json", "Synthetic JSON for testing"),
        ("web_dom", "web_dom", "Web accessibility trees"),
    ]

    for cat, cat_dir, desc in categories:
        pattern = "*.txt" if cat == "web_dom" else "*.json"
        seed_count = count_seeds(cat_dir, pattern)
        # Exclude manifest files
        if cat_dir in ["github_issue", "github_comments"]:
            seed_count = max(0, seed_count - 1)
        table.add_row(cat, str(seed_count), desc)

    console.print(table)
    console.print()

    # Formats
    table = Table(title="Supported Formats", show_header=True)
    table.add_column("Format", style="cyan")
    table.add_column("Description", style="dim")

    formats = [
        ("json", "Structured JSON data"),
        ("markdown", "Markdown formatted text"),
    ]

    for fmt, desc in formats:
        table.add_row(fmt, desc)

    console.print(table)
    console.print()

    # Task types
    table = Table(title="Task Types", show_header=True)
    table.add_column("Task", style="cyan")
    table.add_column("Description", style="dim")

    tasks = [
        ("extraction", "Extract a single field value"),
        ("filtering", "Filter items by a predicate"),
        ("aggregation", "Aggregate values (sum, avg, count, top-k)"),
    ]

    for task, desc in tasks:
        table.add_row(task, desc)

    console.print(table)
    console.print()

    # Attack types
    table = Table(title="Attack Types", show_header=True)
    table.add_column("Attack", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Description", style="dim")

    attacks = [
        ("insert_complete", "Syntactic", "Insert complete object/element"),
        ("override_pre", "Syntactic", "Duplicate key before target"),
        ("override_post", "Syntactic", "Duplicate key after target"),
        ("cross", "Syntactic", "Mixed format delimiters"),
        ("error", "Semantic", "Fake error messages"),
        ("contextual", "Semantic", "Domain-specific deception"),
    ]

    for attack, cat, desc in attacks:
        table.add_row(attack, cat, desc)

    console.print(table)
    console.print()

    # Defense types
    table = Table(title="Defense Types", show_header=True)
    table.add_column("Defense", style="cyan")
    table.add_column("Description", style="dim")

    defenses = [
        ("none", "No defense applied"),
        ("random_keys", "Append random suffix to JSON keys"),
    ]

    for defense, desc in defenses:
        table.add_row(defense, desc)

    console.print(table)
    console.print()

    # LLM Providers
    table = Table(title="Supported LLM Providers", show_header=True)
    table.add_column("Provider", style="cyan")
    table.add_column("Env Variable", style="yellow")
    table.add_column("Example Models", style="dim")

    providers = [
        ("openai", "OPENAI_API_KEY", "gpt-4o, gpt-4o-mini, gpt-4-turbo"),
        ("anthropic", "ANTHROPIC_API_KEY", "claude-sonnet-4-20250514, claude-3-5-sonnet-20241022"),
        ("google", "GOOGLE_API_KEY", "gemini-2.0-flash, gemini-1.5-pro"),
    ]

    for provider, env_var, models in providers:
        table.add_row(provider, env_var, models)

    console.print(table)


# =============================================================================
# View Command - Pretty-view benchmark instances
# =============================================================================


@app.command()
def view(
    dataset: Path = typer.Argument(
        ...,
        help="Path to the benchmark dataset (JSON or JSONL file)",
        exists=True,
    ),
    instance_id: Optional[str] = typer.Option(
        None,
        "--id",
        "-i",
        help="View a specific instance by ID (partial match supported)",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category",
    ),
    test_type: Optional[str] = typer.Option(
        None,
        "--test-type",
        "-t",
        help="Filter by test type (benign/attack)",
    ),
    defense: Optional[str] = typer.Option(
        None,
        "--defense",
        "-d",
        help="Filter by defense type (none/random_key)",
    ),
    format_filter: Optional[str] = typer.Option(
        None,
        "--format",
        "-f",
        help="Filter by format (json/markdown/web_dom)",
    ),
    attack_type: Optional[str] = typer.Option(
        None,
        "--attack",
        "-a",
        help="Filter by attack type",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        "-n",
        help="Maximum number of instances to show in list view",
    ),
    show_input: bool = typer.Option(
        False,
        "--show-input",
        "-I",
        help="Show full input data in detail view",
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary",
        "-s",
        help="Show only summary statistics",
    ),
):
    """Pretty-view benchmark instances.

    Examples:
        dib view dataset.json                      # List first 20 instances
        dib view dataset.json --id s001           # View instance containing 's001'
        dib view dataset.json -c web_dom -t attack # Filter by category and test type
        dib view dataset.json --summary           # Show only summary statistics
    """
    import json
    from collections import defaultdict
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown

    # Load dataset
    instances = []
    if dataset.suffix == ".jsonl":
        with dataset.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    instances.append(json.loads(line))
    else:
        with dataset.open() as f:
            data = json.load(f)
            if isinstance(data, list):
                instances = data
            else:
                instances = [data]

    console.print(f"\n[bold]Loaded {len(instances)} instances from {dataset}[/bold]\n")

    # Apply filters
    filtered = instances
    if category:
        filtered = [i for i in filtered if i.get("category", "").lower() == category.lower()]
    if test_type:
        filtered = [i for i in filtered if i.get("test_type", "").lower() == test_type.lower()]
    if defense:
        if defense.lower() == "none":
            filtered = [i for i in filtered if not i.get("defense_type")]
        else:
            filtered = [i for i in filtered if i.get("defense_type", "").lower() == defense.lower()]
    if format_filter:
        filtered = [i for i in filtered if i.get("format", "").lower() == format_filter.lower()]
    if attack_type:
        filtered = [i for i in filtered if i.get("attack_type", "").lower() == attack_type.lower()]

    if len(filtered) != len(instances):
        console.print(f"[dim]Filtered to {len(filtered)} instances[/dim]\n")

    # If instance_id is specified, show detail view
    if instance_id:
        matches = [i for i in filtered if instance_id in i.get("instance_id", "")]
        if not matches:
            console.print(f"[red]No instance found matching '{instance_id}'[/red]")
            raise typer.Exit(1)

        for inst in matches[:5]:  # Show up to 5 matches
            _print_instance_detail(console, inst, show_input)

        if len(matches) > 5:
            console.print(f"\n[dim]... and {len(matches) - 5} more matches[/dim]")
        return

    # Summary statistics
    if summary_only or not filtered:
        _print_dataset_summary(console, filtered)
        return

    # List view
    _print_instance_list(console, filtered, limit)

    # Brief summary
    console.print("")
    _print_dataset_summary(console, filtered, brief=True)


def _print_instance_detail(console: Console, inst: dict, show_input: bool = False):
    """Print detailed view of a single instance."""
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text
    import json

    instance_id = inst.get("instance_id", "unknown")
    test_type = inst.get("test_type", "unknown")
    category = inst.get("category", "unknown")
    fmt = inst.get("format", "unknown")
    task_type = inst.get("task_type", "unknown")
    defense_type = inst.get("defense_type") or "none"
    attack_type = inst.get("attack_type") or "-"

    # Color based on test type
    type_color = "green" if test_type == "benign" else "red"

    # Header
    console.print(Panel(
        f"[bold]{instance_id}[/bold]",
        title=f"[{type_color}]{test_type.upper()}[/{type_color}]",
        border_style=type_color,
    ))

    # Metadata table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    table.add_row("Category", category)
    table.add_row("Format", fmt)
    table.add_row("Task Type", task_type)
    table.add_row("Target Field", inst.get("target_field", "-"))
    table.add_row("Defense", defense_type)
    if test_type == "attack":
        table.add_row("Attack Type", attack_type)

        # Show attack params
        attack_params = inst.get("attack_params")
        if attack_params:
            guess_key = attack_params.get("guess_key_match")
            if guess_key is not None:
                table.add_row("Guess Key Match", "✓ correct" if guess_key else "✗ wrong")
            if attack_params.get("injection_field"):
                table.add_row("Injection Field", attack_params["injection_field"])

    console.print(table)
    console.print("")

    # Task prompt
    console.print("[bold cyan]Task Prompt:[/bold cyan]")
    console.print(Panel(inst.get("task_prompt", "-"), border_style="dim"))

    # Groundtruth and targeted output
    groundtruth = inst.get("groundtruth_output", "-")
    targeted = inst.get("targeted_output", "-")

    console.print(f"[bold cyan]Groundtruth:[/bold cyan] {groundtruth}")
    if test_type == "attack" and targeted != groundtruth:
        console.print(f"[bold red]Targeted Output:[/bold red] {targeted}")

    # Input data (optional)
    if show_input:
        console.print("\n[bold cyan]Input Data:[/bold cyan]")
        input_data = inst.get("input", "")

        # Try to pretty-print JSON
        if fmt == "json":
            try:
                parsed = json.loads(input_data)
                formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
                console.print(Syntax(formatted, "json", theme="monokai", line_numbers=True))
            except json.JSONDecodeError:
                console.print(input_data[:2000])
                if len(input_data) > 2000:
                    console.print(f"[dim]... ({len(input_data) - 2000} more chars)[/dim]")
        else:
            # Show first 2000 chars for other formats
            console.print(Panel(input_data[:2000], border_style="dim"))
            if len(input_data) > 2000:
                console.print(f"[dim]... ({len(input_data) - 2000} more chars)[/dim]")

    console.print("")


def _print_instance_list(console: Console, instances: list, limit: int):
    """Print a list of instances in table format."""
    table = Table(title=f"Instances (showing {min(limit, len(instances))} of {len(instances)})")

    table.add_column("Instance ID", style="cyan", no_wrap=True)
    table.add_column("Type", justify="center")
    table.add_column("Category")
    table.add_column("Format")
    table.add_column("Task")
    table.add_column("Defense")
    table.add_column("Attack")
    table.add_column("Groundtruth", max_width=30)

    for inst in instances[:limit]:
        test_type = inst.get("test_type", "?")
        type_style = "green" if test_type == "benign" else "red"

        defense = inst.get("defense_type") or "-"
        attack = inst.get("attack_type") or "-"

        # Truncate groundtruth
        gt = str(inst.get("groundtruth_output", "-"))[:30]
        if len(str(inst.get("groundtruth_output", ""))) > 30:
            gt += "..."

        table.add_row(
            inst.get("instance_id", "?"),
            f"[{type_style}]{test_type}[/{type_style}]",
            inst.get("category", "?"),
            inst.get("format", "?"),
            inst.get("task_type", "?"),
            defense,
            attack,
            gt,
        )

    console.print(table)


def _print_dataset_summary(console: Console, instances: list, brief: bool = False):
    """Print summary statistics of the dataset."""
    from collections import defaultdict

    if not instances:
        console.print("[yellow]No instances to summarize[/yellow]")
        return

    # Collect stats
    by_category = defaultdict(lambda: {"benign": 0, "attack": 0})
    by_test_type = defaultdict(int)
    by_defense = defaultdict(lambda: {"benign": 0, "attack": 0})
    by_format = defaultdict(lambda: {"benign": 0, "attack": 0})
    by_task_type = defaultdict(lambda: {"benign": 0, "attack": 0})
    by_attack_type = defaultdict(int)

    for inst in instances:
        test_type = inst.get("test_type", "unknown")
        category = inst.get("category", "unknown")
        defense = inst.get("defense_type") or "none"
        fmt = inst.get("format", "unknown")
        task_type = inst.get("task_type", "unknown")
        attack_type = inst.get("attack_type")

        by_test_type[test_type] += 1
        by_category[category][test_type] += 1
        by_defense[defense][test_type] += 1
        by_format[fmt][test_type] += 1
        by_task_type[task_type][test_type] += 1

        if attack_type:
            by_attack_type[attack_type] += 1

    if brief:
        # One-line summary
        benign = by_test_type.get("benign", 0)
        attack = by_test_type.get("attack", 0)
        cats = ", ".join(sorted(by_category.keys()))
        console.print(f"[dim]Summary: {benign} benign, {attack} attack | Categories: {cats}[/dim]")
        return

    # Full summary
    console.print("[bold]Dataset Summary[/bold]\n")

    # Test type breakdown
    table = Table(title="By Test Type", show_header=True)
    table.add_column("Test Type")
    table.add_column("Count", justify="right")
    for tt, count in sorted(by_test_type.items()):
        table.add_row(tt, str(count))
    table.add_row("[bold]Total[/bold]", f"[bold]{len(instances)}[/bold]")
    console.print(table)
    console.print("")

    # Category breakdown
    table = Table(title="By Category", show_header=True)
    table.add_column("Category")
    table.add_column("Benign", justify="right")
    table.add_column("Attack", justify="right")
    table.add_column("Total", justify="right")
    for cat in sorted(by_category.keys()):
        b = by_category[cat]["benign"]
        a = by_category[cat]["attack"]
        table.add_row(cat, str(b), str(a), str(b + a))
    console.print(table)
    console.print("")

    # Defense breakdown
    table = Table(title="By Defense", show_header=True)
    table.add_column("Defense")
    table.add_column("Benign", justify="right")
    table.add_column("Attack", justify="right")
    table.add_column("Total", justify="right")
    for defense in sorted(by_defense.keys()):
        b = by_defense[defense]["benign"]
        a = by_defense[defense]["attack"]
        table.add_row(defense, str(b), str(a), str(b + a))
    console.print(table)
    console.print("")

    # Task type breakdown
    table = Table(title="By Task Type", show_header=True)
    table.add_column("Task Type")
    table.add_column("Benign", justify="right")
    table.add_column("Attack", justify="right")
    table.add_column("Total", justify="right")
    for task in sorted(by_task_type.keys()):
        b = by_task_type[task]["benign"]
        a = by_task_type[task]["attack"]
        table.add_row(task, str(b), str(a), str(b + a))
    console.print(table)
    console.print("")

    # Attack type breakdown (if any)
    if by_attack_type:
        table = Table(title="By Attack Type", show_header=True)
        table.add_column("Attack Type")
        table.add_column("Count", justify="right")
        for at, count in sorted(by_attack_type.items()):
            table.add_row(at, str(count))
        console.print(table)


# =============================================================================
# Compare Command - Cross-model comparison
# =============================================================================


@app.command()
def compare(
    results_files: List[Path] = typer.Argument(
        ...,
        help="Paths to result files (.jsonl) to compare",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for comparison report (default: out/reports/comparison_{timestamp}.md)",
    ),
    csv_dir: Optional[Path] = typer.Option(
        None,
        "--csv",
        "-c",
        help="Output directory for CSV tables",
    ),
):
    """
    Generate a cross-model comparison report.

    Takes multiple result files and creates a unified comparison showing
    how different models perform on the same benchmark.

    Examples:
        uv run dib compare out/runs/results_gpt-4o-mini_*.jsonl out/runs/results_claude-*jsonl
        uv run dib compare out/runs/*.jsonl -o comparison.md
    """
    import json
    import csv
    from datetime import datetime
    from collections import defaultdict
    from data_injection_bench.bench_types import EvaluationResult

    # Validate files exist and filter out directories
    valid_files = []
    for f in results_files:
        if not f.exists():
            console.print(f"[red]File not found: {f}[/red]")
            raise typer.Exit(1)
        if f.is_dir():
            console.print(f"[yellow]Skipping directory: {f}[/yellow]")
            continue
        valid_files.append(f)
    results_files = valid_files

    if len(results_files) < 2:
        console.print("[red]Need at least 2 result files to compare[/red]")
        raise typer.Exit(1)

    console.print(f"[bold blue]Comparing {len(results_files)} result files...[/bold blue]")

    # Load all results
    all_results = {}  # model_name -> list of results
    for results_file in results_files:
        results = []
        with open(results_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    results.append(EvaluationResult(**data))

        if results:
            model_name = results[0].model_name
            # Handle duplicate model names by appending file stem
            if model_name in all_results:
                model_name = f"{model_name} ({results_file.stem})"
            all_results[model_name] = results
            console.print(f"  Loaded {len(results)} results for {model_name}")

    models = sorted(all_results.keys())

    def save_csv(filename: str, headers: list, rows: list):
        if csv_dir is None:
            return
        csv_dir.mkdir(parents=True, exist_ok=True)
        filepath = csv_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        console.print(f"  [dim]Saved CSV: {filepath}[/dim]")

    # =========================================================================
    # Generate Paper-focused Comparison Report
    # =========================================================================

    lines = []
    lines.append("# Cross-Model Comparison Report")
    lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"\nModels compared: {len(models)}")
    for model in models:
        lines.append(f"- {model}")
    lines.append("")

    # Helper to get guess_key_match from attack_params
    def get_guess_key_match(r) -> Optional[bool]:
        params = r.attack_params or {}
        return params.get("guess_key_match")

    # Map attack types to paper terminology
    def get_attack_type_label(at: str) -> str:
        if at in ("override_pre", "override_post"):
            return "inconsistent"
        if at == "insert_complete":
            return "consistent"
        return at

    # Define model tiers for paper
    # Flagship: GPT-5.2, Claude Opus 4.5, Gemini 3 Pro
    # Efficient: GPT-5-mini, Claude Sonnet 4.5, Gemini 3 Flash
    MODEL_TIERS = {
        "gpt-5.2": "Flagship",
        "gpt-5-mini": "Efficient",
        "claude-opus-4-5": "Flagship",
        "claude-sonnet-4-5": "Efficient",
        "gemini-3-pro": "Flagship",
        "gemini-3-flash": "Efficient",
        "gpt-4o": "Flagship",
        "gpt-4o-mini": "Efficient",
        "claude-3-5-sonnet": "Efficient",
        "claude-sonnet-4": "Efficient",
        "claude-opus-4": "Flagship",
        "gemini-2.0-flash": "Efficient",
        "gemini-1.5-pro": "Flagship",
    }

    def get_model_tier(model_name: str) -> str:
        name_lower = model_name.lower()
        for key, tier in MODEL_TIERS.items():
            if key in name_lower:
                return tier
        return "Unknown"

    # Category to structure mapping for RQ3
    CATEGORY_STRUCTURE = {
        "calendar": "List",
        "cloud_drive": "List",
        "github_comments": "List",
        "web_dom": "List",
        "email": "Object",
        "github_issue": "Object",
        "reference_json": "Object",
    }

    # -------------------------------------------------------------------------
    # Table 1 (RQ1): Main Vulnerability Table
    # Uses "consistent" attacks only (insert_complete in code)
    # Columns: Model, Tier, Benign Utility (All/JSON/MD/DOM),
    #          ASR Known (All/JSON/MD/DOM),
    #          ASR Randomized JSON (None/Correct/Wrong), ASR Randomized DOM (Correct)
    # -------------------------------------------------------------------------
    lines.append("")
    lines.append("## Paper Table 1: LLM Vulnerability to Delimiter Injection")
    lines.append("*Note: ASR uses consistent attacks only*")
    lines.append("")
    lines.append("| Model | Tier | Util All | Util JSON | Util MD | Util DOM | ASR Known All | ASR Known JSON | ASR Known MD | ASR Known DOM | ASR Rand JSON None | ASR Rand JSON Correct | ASR Rand JSON Wrong | ASR Rand DOM Correct |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")

    csv_rq1_rows = []
    for model in models:
        results = all_results[model]
        tier = get_model_tier(model)

        # Benign utility by format
        benign_all = [r for r in results if r.test_type == "benign"]
        benign_json = [r for r in benign_all if r.format == "json"]
        benign_md = [r for r in benign_all if r.format == "markdown"]
        benign_dom = [r for r in benign_all if r.format == "web_dom"]

        def calc_utility(res_list):
            if not res_list:
                return 0, 0, ""
            correct = sum(1 for r in res_list if r.benign_correct)
            pct = correct / len(res_list) * 100
            return len(res_list), correct, f"{pct:.1f}"

        util_all = calc_utility(benign_all)
        util_json = calc_utility(benign_json)
        util_md = calc_utility(benign_md)
        util_dom = calc_utility(benign_dom)

        # ASR Known (no defense) - consistent attacks only (insert_complete)
        attack_known_all = [r for r in results if r.test_type == "attack" and r.attack_type == "insert_complete" and not r.defense_type]
        attack_known_json = [r for r in attack_known_all if r.format == "json"]
        attack_known_md = [r for r in attack_known_all if r.format == "markdown"]
        attack_known_dom = [r for r in attack_known_all if r.format == "web_dom"]

        def calc_asr(res_list):
            if not res_list:
                return 0, 0, ""
            success = sum(1 for r in res_list if r.attack_successful)
            pct = success / len(res_list) * 100
            return len(res_list), success, f"{pct:.1f}"

        asr_known_all = calc_asr(attack_known_all)
        asr_known_json = calc_asr(attack_known_json)
        asr_known_md = calc_asr(attack_known_md)
        asr_known_dom = calc_asr(attack_known_dom)

        # ASR Randomized - with defense, consistent attacks only (insert_complete)
        attack_rand_all = [r for r in results if r.test_type == "attack" and r.attack_type == "insert_complete" and r.defense_type]

        # JSON with defense - break down by guess_key_match
        attack_rand_json = [r for r in attack_rand_all if r.format == "json"]
        attack_rand_json_none = [r for r in attack_rand_json if get_guess_key_match(r) is None]
        attack_rand_json_correct = [r for r in attack_rand_json if get_guess_key_match(r) == True]
        attack_rand_json_wrong = [r for r in attack_rand_json if get_guess_key_match(r) == False]

        # DOM with defense - only correct guess matters
        attack_rand_dom = [r for r in attack_rand_all if r.format == "web_dom"]
        attack_rand_dom_correct = [r for r in attack_rand_dom if get_guess_key_match(r) == True]

        asr_rand_json_none = calc_asr(attack_rand_json_none)
        asr_rand_json_correct = calc_asr(attack_rand_json_correct)
        asr_rand_json_wrong = calc_asr(attack_rand_json_wrong)
        asr_rand_dom_correct = calc_asr(attack_rand_dom_correct)

        # Format display values
        def fmt_pct(calc_result):
            return calc_result[2] if calc_result[2] else "-"

        row = f"| {model} | {tier} | {fmt_pct(util_all)} | {fmt_pct(util_json)} | {fmt_pct(util_md)} | {fmt_pct(util_dom)} | {fmt_pct(asr_known_all)} | {fmt_pct(asr_known_json)} | {fmt_pct(asr_known_md)} | {fmt_pct(asr_known_dom)} | {fmt_pct(asr_rand_json_none)} | {fmt_pct(asr_rand_json_correct)} | {fmt_pct(asr_rand_json_wrong)} | {fmt_pct(asr_rand_dom_correct)} |"
        lines.append(row)

        csv_rq1_rows.append([
            model, tier,
            util_all[0], util_all[1], util_all[2],
            util_json[0], util_json[1], util_json[2],
            util_md[0], util_md[1], util_md[2],
            util_dom[0], util_dom[1], util_dom[2],
            asr_known_all[0], asr_known_all[1], asr_known_all[2],
            asr_known_json[0], asr_known_json[1], asr_known_json[2],
            asr_known_md[0], asr_known_md[1], asr_known_md[2],
            asr_known_dom[0], asr_known_dom[1], asr_known_dom[2],
            asr_rand_json_none[0], asr_rand_json_none[1], asr_rand_json_none[2],
            asr_rand_json_correct[0], asr_rand_json_correct[1], asr_rand_json_correct[2],
            asr_rand_json_wrong[0], asr_rand_json_wrong[1], asr_rand_json_wrong[2],
            asr_rand_dom_correct[0], asr_rand_dom_correct[1], asr_rand_dom_correct[2],
        ])

    save_csv("paper_rq1_vulnerability.csv", [
        "model", "tier",
        "util_all_n", "util_all_correct", "util_all_pct",
        "util_json_n", "util_json_correct", "util_json_pct",
        "util_md_n", "util_md_correct", "util_md_pct",
        "util_dom_n", "util_dom_correct", "util_dom_pct",
        "asr_known_all_n", "asr_known_all_success", "asr_known_all_pct",
        "asr_known_json_n", "asr_known_json_success", "asr_known_json_pct",
        "asr_known_md_n", "asr_known_md_success", "asr_known_md_pct",
        "asr_known_dom_n", "asr_known_dom_success", "asr_known_dom_pct",
        "asr_rand_json_none_n", "asr_rand_json_none_success", "asr_rand_json_none_pct",
        "asr_rand_json_correct_n", "asr_rand_json_correct_success", "asr_rand_json_correct_pct",
        "asr_rand_json_wrong_n", "asr_rand_json_wrong_success", "asr_rand_json_wrong_pct",
        "asr_rand_dom_correct_n", "asr_rand_dom_correct_success", "asr_rand_dom_correct_pct",
    ], csv_rq1_rows)

    # -------------------------------------------------------------------------
    # Table 2 (RQ2): Structural Consistency
    # Consistent = properly structured fake objects (insert_complete)
    # Inconsistent = malformed fields (override_pre, override_post -> insert_incomplete)
    # Uses known condition (no defense)
    # -------------------------------------------------------------------------
    lines.append("")
    lines.append("## Paper Table 2: ASR by Structural Consistency")
    lines.append("*Known condition (no defense)*")
    lines.append("")
    lines.append("| Model | Consistent (%) | Inconsistent (%) |")
    lines.append("| --- | ---: | ---: |")

    csv_rq2_rows = []
    for model in models:
        results = all_results[model]

        # Consistent = properly structured fake objects (insert_complete), known condition
        consistent = [r for r in results if r.test_type == "attack" and r.attack_type == "insert_complete" and not r.defense_type]
        # Inconsistent = malformed fields (override_pre, override_post), known condition
        inconsistent = [r for r in results if r.test_type == "attack" and get_attack_type_label(r.attack_type) == "inconsistent" and not r.defense_type]

        cons_success = sum(1 for r in consistent if r.attack_successful)
        cons_pct = cons_success / len(consistent) * 100 if consistent else 0

        incons_success = sum(1 for r in inconsistent if r.attack_successful)
        incons_pct = incons_success / len(inconsistent) * 100 if inconsistent else 0

        cons_str = f"{cons_pct:.1f}" if consistent else "-"
        incons_str = f"{incons_pct:.1f}" if inconsistent else "-"

        lines.append(f"| {model} | {cons_str} | {incons_str} |")
        csv_rq2_rows.append([model, len(consistent), cons_success, f"{cons_pct:.1f}", len(inconsistent), incons_success, f"{incons_pct:.1f}"])

    save_csv("paper_rq2_consistency.csv", [
        "model", "consistent_n", "consistent_success", "consistent_pct",
        "inconsistent_n", "inconsistent_success", "inconsistent_pct"
    ], csv_rq2_rows)

    # -------------------------------------------------------------------------
    # Table 3 (RQ3): ASR by Data Structure (per model)
    # Uses consistent attacks, known condition (no defense)
    # Structure: List (calendar, cloud_drive, github_comments, web_dom)
    #            Object (email, github_issue, reference_json)
    # -------------------------------------------------------------------------
    lines.append("")
    lines.append("## Paper Table 3: ASR by Data Structure")
    lines.append("*Consistent attacks, known condition (no defense)*")
    lines.append("")

    for model in models:
        results = all_results[model]
        lines.append(f"### {model}")
        lines.append("")
        lines.append("| Structure | Category | ASR (%) |")
        lines.append("| --- | --- | ---: |")

        csv_rq3_rows = []

        # Group by structure, then category
        for structure in ["List", "Object"]:
            struct_categories = [cat for cat, struct in CATEGORY_STRUCTURE.items() if struct == structure]
            for cat in sorted(struct_categories):
                # Consistent attacks (insert_complete), known condition (no defense)
                cat_results = [r for r in results if r.test_type == "attack" and r.attack_type == "insert_complete" and not r.defense_type and r.category == cat]
                if cat_results:
                    success = sum(1 for r in cat_results if r.attack_successful)
                    pct = success / len(cat_results) * 100
                    lines.append(f"| {structure} | {cat} | {pct:.1f} |")
                    csv_rq3_rows.append([model, structure, cat, len(cat_results), success, f"{pct:.1f}"])
                else:
                    lines.append(f"| {structure} | {cat} | - |")
                    csv_rq3_rows.append([model, structure, cat, 0, 0, ""])

        lines.append("")
        save_csv(f"paper_rq3_structure_{model.replace('/', '_')}.csv", [
            "model", "structure", "category", "n", "success", "asr_pct"
        ], csv_rq3_rows)

    # -------------------------------------------------------------------------
    # Table 4 (RQ4): ASR by Task Type (per model)
    # Uses consistent attacks only
    # Known = no defense, Randomized = with defense
    # -------------------------------------------------------------------------
    lines.append("")
    lines.append("## Paper Table 4: ASR by Task Type")
    lines.append("*Consistent attacks only*")
    lines.append("")

    for model in models:
        results = all_results[model]
        lines.append(f"### {model}")
        lines.append("")
        lines.append("| Task Type | Known (%) | Randomized (%) |")
        lines.append("| --- | ---: | ---: |")

        csv_rq4_rows = []

        for task_type in ["extraction", "aggregation"]:
            # Known = consistent attacks (insert_complete), no defense
            known_results = [r for r in results if r.test_type == "attack" and r.attack_type == "insert_complete" and not r.defense_type and r.task_type == task_type]
            # Randomized = consistent attacks (insert_complete), with defense
            rand_results = [r for r in results if r.test_type == "attack" and r.attack_type == "insert_complete" and r.defense_type and r.task_type == task_type]

            known_success = sum(1 for r in known_results if r.attack_successful)
            known_pct = known_success / len(known_results) * 100 if known_results else 0

            rand_success = sum(1 for r in rand_results if r.attack_successful)
            rand_pct = rand_success / len(rand_results) * 100 if rand_results else 0

            known_str = f"{known_pct:.1f}" if known_results else "-"
            rand_str = f"{rand_pct:.1f}" if rand_results else "-"

            lines.append(f"| {task_type} | {known_str} | {rand_str} |")
            csv_rq4_rows.append([model, task_type, len(known_results), known_success, f"{known_pct:.1f}", len(rand_results), rand_success, f"{rand_pct:.1f}"])

        lines.append("")
        save_csv(f"paper_rq4_tasktype_{model.replace('/', '_')}.csv", [
            "model", "task_type", "known_n", "known_success", "known_pct",
            "randomized_n", "randomized_success", "randomized_pct"
        ], csv_rq4_rows)

    lines.append("")

    # Save report
    if output is None:
        output_dir = Path("out/reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = output_dir / f"comparison_{timestamp}.md"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")

    console.print(f"\n[bold green]✓ Comparison report saved to: {output}[/bold green]")
    if csv_dir:
        console.print(f"[green]CSV tables saved to: {csv_dir}[/green]")


# =============================================================================
# Version Command
# =============================================================================


@app.command()
def version():
    """Display version information."""
    console.print("[bold]Data Injection Benchmark[/bold]")
    console.print("Version: 0.1.0")
    console.print("Python: " + sys.version.split()[0])


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
