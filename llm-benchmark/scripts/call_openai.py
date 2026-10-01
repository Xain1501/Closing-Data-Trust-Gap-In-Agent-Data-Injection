#!/usr/bin/env python3
"""Call an OpenAI model with a prompt loaded from a file."""

from __future__ import annotations

import argparse
import os
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Call an OpenAI model with a prompt from an input file."
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to a text file containing the prompt.",
    )
    parser.add_argument(
        "--model",
        "-m",
        required=True,
        help="OpenAI model name, e.g. gpt-4o-mini.",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output file path, or '-' for stdout (default).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Missing OPENAI_API_KEY in environment.", file=sys.stderr)
        return 1

    try:
        from openai import OpenAI
    except ImportError:
        print("OpenAI package not installed. Install with: pip install openai", file=sys.stderr)
        return 1

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            prompt = handle.read()
    except OSError as exc:
        print(f"Failed to read input file: {exc}", file=sys.stderr)
        return 1

    client = OpenAI(api_key=api_key)
    kwargs = {
        "model": args.model,
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        stream = client.chat.completions.create(stream=True, **kwargs)
    except Exception as exc:
        print(f"OpenAI API call failed: {exc}", file=sys.stderr)
        return 1

    chunks: list[str] = []
    try:
        for event in stream:
            if not event.choices:
                continue
            delta = event.choices[0].delta
            if not delta or not delta.content:
                continue
            chunk = delta.content
            chunks.append(chunk)
            sys.stdout.write(chunk)
            sys.stdout.flush()
    except Exception as exc:
        print(f"\nOpenAI stream failed: {exc}", file=sys.stderr)
        return 1

    content = "".join(chunks)

    if args.output == "-":
        if content and not content.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
    except OSError as exc:
        print(f"Failed to write output file: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
