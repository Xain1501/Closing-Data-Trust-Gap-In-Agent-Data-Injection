#!/usr/bin/env python3
"""Collect GitHub issue data as seed samples.

Usage:
    python collect_github.py --repo pytorch/pytorch --limit 15
    python collect_github.py --repo microsoft/vscode --limit 10 --with-comments
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import sleep
from typing import Any, Dict, List, Optional

import requests

from anonymizer import get_fake_email, get_fake_username


def anonymize_github_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Anonymize sensitive fields in GitHub issue data."""
    # Clone to avoid modifying original
    data = data.copy()

    # Anonymize user data
    if "user" in data and data["user"]:
        original_login = data["user"].get("login", str(data["user"].get("id", "unknown")))
        data["user"] = {
            "login": get_fake_username(original_login),
            "id": data["user"].get("id"),
            "type": data["user"].get("type", "User"),
        }

    # Anonymize assignees
    if "assignees" in data:
        data["assignees"] = [
            {
                "login": get_fake_username(a.get("login", str(a.get("id", i)))),
                "id": a.get("id"),
                "type": a.get("type", "User"),
            }
            for i, a in enumerate(data["assignees"])
        ]

    # Keep labels and milestones as-is (not sensitive)

    # Sanitize body text (remove potential emails, URLs to private resources)
    if "body" in data and data["body"]:
        body = data["body"]
        # Replace emails with consistent fake emails
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', body)
        for email in emails:
            body = body.replace(email, get_fake_email(email))
        data["body"] = body

    # Remove sensitive URLs
    for field in ["url", "repository_url", "labels_url", "comments_url",
                  "events_url", "html_url"]:
        if field in data:
            # Keep structure but sanitize
            if "api.github.com" in data[field]:
                data[field] = data[field].replace(
                    "https://api.github.com/repos/",
                    "https://api.github.com/repos/example/repo/"
                )

    # Anonymize comments if present
    if "comments_data" in data and data["comments_data"]:
        anonymized_comments = []
        for comment in data["comments_data"]:
            anon_comment = comment.copy()

            # Anonymize comment author
            if "user" in anon_comment and anon_comment["user"]:
                original_login = anon_comment["user"].get("login", str(anon_comment["user"].get("id", "unknown")))
                anon_comment["user"] = {
                    "login": get_fake_username(original_login),
                    "id": anon_comment["user"].get("id"),
                    "type": anon_comment["user"].get("type", "User"),
                }

            # Anonymize comment body
            if "body" in anon_comment and anon_comment["body"]:
                body = anon_comment["body"]
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', body)
                for email in emails:
                    body = body.replace(email, get_fake_email(email))
                anon_comment["body"] = body

            # Sanitize comment URLs
            for field in ["url", "html_url"]:
                if field in anon_comment and "api.github.com" in anon_comment[field]:
                    anon_comment[field] = anon_comment[field].replace(
                        "https://api.github.com/repos/",
                        "https://api.github.com/repos/example/repo/"
                    )

            anonymized_comments.append(anon_comment)

        data["comments_data"] = anonymized_comments

    return data


def collect_issues(
    repo: str,
    limit: int = 10,
    state: str = "all",
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Collect issues from a GitHub repository.

    Args:
        repo: Repository in format 'owner/repo'
        limit: Maximum number of issues to collect
        state: Issue state ('open', 'closed', 'all')
        github_token: Optional GitHub API token for higher rate limits

    Returns:
        List of issue dictionaries
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    issues = []
    page = 1
    per_page = min(100, limit)

    print(f"Collecting issues from {repo}...")

    while len(issues) < limit:
        url = f"https://api.github.com/repos/{repo}/issues"
        params = {
            "state": state,
            "per_page": per_page,
            "page": page,
            "sort": "created",
            "direction": "desc",
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()

            batch = response.json()
            if not batch:
                break

            # Track original batch size before filtering
            original_batch_size = len(batch)

            # Filter out pull requests (they appear in issues API)
            batch = [item for item in batch if "pull_request" not in item]

            issues.extend(batch)
            print(f"  Collected {len(issues)} issues...")

            # Stop if we got fewer items than requested (end of results)
            if original_batch_size < per_page:
                break

            page += 1
            sleep(1)  # Be nice to the API

        except requests.exceptions.RequestException as e:
            print(f"Error fetching issues: {e}", file=sys.stderr)
            break

    return issues[:limit]


def collect_issue_comments(
    repo: str,
    issue_number: int,
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Collect comments for a specific issue.

    Args:
        repo: Repository in format 'owner/repo'
        issue_number: Issue number
        github_token: Optional GitHub API token

    Returns:
        List of comment dictionaries
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching comments for issue #{issue_number}: {e}", file=sys.stderr)
        return []


def save_seeds(
    issues: List[Dict[str, Any]],
    output_dir: Path,
    repo: str,
    prefix: str = "api",
    anonymize: bool = True,
):
    """Save issues as seed files with separate files per API endpoint.

    Args:
        issues: List of issue dictionaries
        output_dir: Directory to save seeds
        repo: Repository name (for manifest)
        prefix: Filename prefix
        anonymize: Whether to anonymize data
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "repository": repo,
        "collection_info": {
            "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "total_issues": len(issues),
            "anonymized": anonymize,
        },
        "files": []
    }

    for i, issue in enumerate(issues, 1):
        # Extract comments before anonymization
        comments_data = issue.pop("comments_data", None)

        if anonymize:
            issue = anonymize_github_data(issue)

        # Create descriptive filename slug
        title_slug = re.sub(r'[^a-z0-9]+', '_', issue.get("title", "").lower())[:30]
        issue_number = issue.get("number")

        # Save issue file
        issue_filename = f"{prefix}_{i:03d}_issue_{title_slug}.json"
        issue_filepath = output_dir / issue_filename

        with open(issue_filepath, "w", encoding="utf-8") as f:
            json.dump(issue, f, indent=2, ensure_ascii=False)

        print(f"  Saved: {issue_filepath}")

        # Prepare manifest entry
        file_entry = {
            "index": i,
            "issue_number": issue_number,
            "issue_file": issue_filename,
            "issue_endpoint": f"GET /repos/{repo}/issues",
            "issue_url": f"https://api.github.com/repos/{repo}/issues/{issue_number}",
        }

        # Save comments file if present
        if comments_data:
            comments_filename = f"{prefix}_{i:03d}_comments_{title_slug}.json"
            comments_filepath = output_dir / comments_filename

            with open(comments_filepath, "w", encoding="utf-8") as f:
                json.dump(comments_data, f, indent=2, ensure_ascii=False)

            print(f"  Saved: {comments_filepath}")

            file_entry["comments_file"] = comments_filename
            file_entry["comments_endpoint"] = f"GET /repos/{repo}/issues/{issue_number}/comments"
            file_entry["comments_url"] = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"
            file_entry["comments_count"] = len(comments_data)

        manifest["files"].append(file_entry)

    # Save manifest
    manifest_path = output_dir / f"{prefix}_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"\n  Manifest: {manifest_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Collect GitHub issues as seed samples"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository in format 'owner/repo' (e.g., pytorch/pytorch)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of issues to collect (default: 10)",
    )
    parser.add_argument(
        "--state",
        choices=["open", "closed", "all"],
        default="all",
        help="Issue state to collect (default: all)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/seeds/github_issue"),
        help="Output directory for seed files",
    )
    parser.add_argument(
        "--prefix",
        default="api",
        help="Filename prefix (default: api)",
    )
    parser.add_argument(
        "--with-comments",
        action="store_true",
        help="Also collect and embed comments in issue data",
    )
    parser.add_argument(
        "--no-anonymize",
        action="store_true",
        help="Skip anonymization (use with caution)",
    )

    args = parser.parse_args()

    # Get GitHub token from environment if available
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("Note: No GITHUB_TOKEN found. Using unauthenticated API (lower rate limits)")
        print("      Set GITHUB_TOKEN environment variable for higher limits")

    # Collect issues
    issues = collect_issues(
        repo=args.repo,
        limit=args.limit,
        state=args.state,
        github_token=github_token,
    )

    if not issues:
        print("No issues collected!", file=sys.stderr)
        return 1

    print(f"\nCollected {len(issues)} issues")

    # Optionally collect comments
    if args.with_comments:
        print("\nCollecting comments for issues...")
        for issue in issues:
            if issue.get("comments", 0) > 0:
                comments = collect_issue_comments(
                    repo=args.repo,
                    issue_number=issue["number"],
                    github_token=github_token,
                )
                issue["comments_data"] = comments
                sleep(0.5)  # Rate limiting

    # Save seeds
    print(f"\nSaving seeds to {args.output_dir}...")
    save_seeds(
        issues=issues,
        output_dir=args.output_dir,
        repo=args.repo,
        prefix=args.prefix,
        anonymize=not args.no_anonymize,
    )

    print(f"\n✓ Successfully collected {len(issues)} GitHub issue seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
