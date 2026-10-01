#!/usr/bin/env python3
"""Generate datasets from seeds and diff against gold outputs."""

from __future__ import annotations

import argparse
import contextlib
import difflib
import io
import json
import re
from pathlib import Path
from typing import Iterable, List, Tuple

from rich.console import Console
from rich.text import Text

from data_injection_bench.bench_types import Category, Format
from data_injection_bench.generator import DatasetGenerator


def _parse_line(line: str) -> Tuple[Path, Path, Category, List[Format]]:
    parts = [part.strip() for part in line.split("|")]
    if len(parts) != 4:
        raise ValueError("Expected 4 pipe-separated fields")
    seed_file = Path(parts[0])
    gold_file = Path(parts[1])
    category = Category(parts[2])
    formats = [Format(fmt.strip()) for fmt in parts[3].split(",") if fmt.strip()]
    if not formats:
        formats = [Format.JSON]
    return seed_file, gold_file, category, formats


def _iter_specs(path: Path) -> Iterable[Tuple[Path, Path, Category, List[Format]]]:
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        yield _parse_line(line)


def _load_json(path: Path) -> List[dict]:
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Expected list in {path}")
    return data


def _pretty(data: List[dict]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)


def _diff_text(a: str, b: str, fromfile: str, tofile: str, context: int) -> List[str]:
    diff = difflib.unified_diff(
        a.splitlines(),
        b.splitlines(),
        fromfile=fromfile,
        tofile=tofile,
        n=context,
        lineterm="",
    )
    return list(diff)


def _style_line(line: str) -> Text:
    if line.startswith("+++ ") or line.startswith("--- "):
        return Text(line, style="bold")
    if line.startswith("@@"):
        return Text(line, style="yellow")
    if line.startswith("+") and not line.startswith("+++"):
        return Text(line, style="green")
    if line.startswith("-") and not line.startswith("---"):
        return Text(line, style="red")
    return Text(line)

TOKEN_RE = re.compile(r"\w+|\s+|[^\w\s]")


def _tokenize(line: str) -> List[str]:
    return TOKEN_RE.findall(line)


def _style_word_diff(removed: str, added: str) -> Tuple[Text, Text]:
    removed_text = Text()
    added_text = Text()
    removed_text.append("- ", style="red bold")
    added_text.append("+ ", style="green bold")
    removed_tokens = _tokenize(removed)
    added_tokens = _tokenize(added)
    matcher = difflib.SequenceMatcher(a=removed_tokens, b=added_tokens)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            chunk_removed = "".join(removed_tokens[i1:i2])
            chunk_added = "".join(added_tokens[j1:j2])
            removed_text.append(chunk_removed, style="dim")
            added_text.append(chunk_added, style="dim")
        elif tag == "delete":
            removed_text.append("".join(removed_tokens[i1:i2]), style="red")
        elif tag == "insert":
            added_text.append("".join(added_tokens[j1:j2]), style="green")
        elif tag == "replace":
            removed_text.append("".join(removed_tokens[i1:i2]), style="red bold")
            added_text.append("".join(added_tokens[j1:j2]), style="green bold")
    return removed_text, added_text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate outputs from seeds and diff against gold files."
    )
    parser.add_argument(
        "spec_file",
        type=Path,
        help="Path to input file: seed_file | gold_json | category | formats",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=3,
        help="Number of context lines for unified diff",
    )
    parser.add_argument(
        "--max-diff-lines",
        type=int,
        default=0,
        help="Maximum diff lines to print per file (0 = no limit)",
    )
    parser.add_argument(
        "--pager",
        dest="pager",
        action="store_true",
        default=True,
        help="Show diffs in a pager for scrolling",
    )
    parser.add_argument(
        "--no-pager",
        dest="pager",
        action="store_false",
        help="Print diffs directly without a pager",
    )
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="Exit with non-zero status if any diff is found",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress generator output",
    )
    args = parser.parse_args()

    generator = DatasetGenerator()
    console = Console(color_system="truecolor", force_terminal=True, force_interactive=True)
    had_diff = False
    had_error = False

    all_lines: List[Text] = []

    for seed_file, gold_file, category, formats in _iter_specs(args.spec_file):
        output_path = Path("/tmp") / f"{seed_file.stem}_generated.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if args.quiet:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    generator.generate_and_save(
                        category=category,
                        formats=formats,
                        output_file=output_path,
                        seed_file=str(seed_file),
                    )
            else:
                generator.generate_and_save(
                    category=category,
                    formats=formats,
                    output_file=output_path,
                    seed_file=str(seed_file),
                )
        except Exception as exc:
            print(f"[error] Failed generation for {seed_file}: {exc}")
            had_error = True
            continue

        try:
            generated = _load_json(output_path)
            gold = _load_json(gold_file)
        except Exception as exc:
            print(f"[error] Failed to load JSON: {exc}")
            had_error = True
            continue

        gen_text = _pretty(generated)
        gold_text = _pretty(gold)
        diff_lines = _diff_text(
            gold_text,
            gen_text,
            str(gold_file),
            str(output_path),
            args.context,
        )

        if diff_lines:
            had_diff = True
            added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
            removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))

            gold_rel = gold_file.as_posix().lstrip("/")
            out_rel = output_path.as_posix().lstrip("/")
            header = [
                f"=== Diff for {seed_file} ===",
                f"Summary: +{added} -{removed}",
                f"diff --git a/{gold_rel} b/{out_rel}",
                f"--- a/{gold_rel}",
                f"+++ b/{out_rel}",
            ]

            to_show = diff_lines
            if args.max_diff_lines > 0:
                to_show = diff_lines[: args.max_diff_lines]

            lines: List[Text] = [Text(line) for line in header]
            idx = 0
            while idx < len(to_show):
                line = to_show[idx]
                if line.startswith("--- ") or line.startswith("+++ "):
                    idx += 1
                    continue
                if line.startswith("-") and not line.startswith("---"):
                    removed_block: List[str] = []
                    while idx < len(to_show) and to_show[idx].startswith("-") and not to_show[idx].startswith("---"):
                        removed_block.append(to_show[idx][1:])
                        idx += 1
                    added_block: List[str] = []
                    while idx < len(to_show) and to_show[idx].startswith("+") and not to_show[idx].startswith("+++"):
                        added_block.append(to_show[idx][1:])
                        idx += 1

                    if added_block:
                        pairs = min(len(removed_block), len(added_block))
                        for i in range(pairs):
                            removed_text, added_text = _style_word_diff(
                                removed_block[i],
                                added_block[i],
                            )
                            lines.append(removed_text)
                            lines.append(added_text)
                        for remainder in removed_block[pairs:]:
                            lines.append(_style_line(f"-{remainder}"))
                        for remainder in added_block[pairs:]:
                            lines.append(_style_line(f"+{remainder}"))
                    else:
                        for remainder in removed_block:
                            lines.append(_style_line(f"-{remainder}"))
                    continue

                if line.startswith("+") and not line.startswith("+++"):
                    lines.append(_style_line(line))
                    idx += 1
                    continue

                lines.append(_style_line(line))
                idx += 1

            if args.pager:
                all_lines.extend(lines)
            else:
                for line in lines:
                    console.print(line)
        else:
            match_lines = [
                Text(f"\n=== Match for {seed_file} ==="),
                Text("No differences."),
            ]
            if args.pager:
                all_lines.extend(match_lines)
            else:
                for line in match_lines:
                    console.print(line)

    if args.pager and all_lines:
        with console.pager(styles=True):
            for line in all_lines:
                console.print(line)

    if had_error:
        return 1
    if args.fail_on_diff and had_diff:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
