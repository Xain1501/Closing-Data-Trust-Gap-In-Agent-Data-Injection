"""Schema-specific transformers for GitHub issue data."""

import csv
import io
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "Jinja2 is required for GitHub markdown templating. Install it with `pip install jinja2`."
    ) from exc

from .transformers import FormatTransformer

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "github_issue"
_REACTION_ORDER = ["total_count", "+1", "-1", "laugh", "hooray", "confused", "heart", "rocket", "eyes"]


def _build_template_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def markdown_filter(value: Optional[str]) -> str:
        if value is None:
            return "*No content*"
        stripped = str(value).strip()
        return stripped if stripped else "*No content*"

    env.filters["markdown"] = markdown_filter
    return env


_ENV = _build_template_env()


def _parse_owner_repo(issue: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Derive owner/repo from html_url or repository_url."""
    candidates = [issue.get("repository_url"), issue.get("html_url")]
    for url in candidates:
        if not url:
            continue
        parts = url.split("/")
        try:
            if "api.github.com" in url and "repos" in parts:
                idx = parts.index("repos")
                return parts[idx + 1], parts[idx + 2]
            if "github.com" in url:
                idx = parts.index("github.com")
                return parts[idx + 1], parts[idx + 2]
        except (ValueError, IndexError):
            continue
    return None, None


def _join_field(items: List[Dict[str, Any]], field_name: str) -> Optional[str]:
    values = []
    for item in items or []:
        if isinstance(item, dict):
            value = item.get(field_name)
            if value:
                values.append(str(value))
    return ", ".join(values) if values else None


def _normalize_reactions(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}

    reactions = OrderedDict()
    for key in _REACTION_ORDER:
        if key not in raw:
            continue
        value = raw.get(key, 0)
        # Keep only reactions that are present and non-zero to avoid noise.
        if isinstance(value, (int, float)) and value > 0:
            reactions[key] = value
        elif value not in (None, 0, "0", "", False):
            reactions[key] = value

    return dict(reactions)


def _issue_context(issue: Dict[str, Any]) -> Dict[str, Any]:
    owner, repo = _parse_owner_repo(issue)
    user = issue.get("user") or {}
    labels = _join_field(issue.get("labels", []), "name")
    assignees = _join_field(issue.get("assignees", []), "login")
    reactions = _normalize_reactions(issue.get("reactions"))

    return {
        "number": issue.get("number", "N/A"),
        "title": issue.get("title", "Untitled"),
        "owner": owner or "unknown-owner",
        "repo": repo or "unknown-repo",
        "html_url": issue.get("html_url", issue.get("url", "")),
        "state": issue.get("state", "unknown"),
        "author": user.get("login", "unknown"),
        "author_association": issue.get("author_association", "NONE"),
        "created_at": issue.get("created_at", "N/A"),
        "updated_at": issue.get("updated_at", "N/A"),
        "comments": issue.get("comments", 0),
        "labels": labels,
        "assignees": assignees,
        "milestone": (issue.get("milestone") or {}).get("title") if issue.get("milestone") else None,
        "closed_at": issue.get("closed_at"),
        "state_reason": issue.get("state_reason"),
        "body": issue.get("body"),
        "reactions": reactions,
    }


def _normalize_comment(comment: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(comment, dict):
        comment = {}

    user = comment.get("user") or {}
    reactions = _normalize_reactions(comment.get("reactions"))
    return {
        "author": user.get("login", "unknown"),
        "author_association": comment.get("author_association"),
        "created_at": comment.get("created_at", "unknown"),
        "updated_at": comment.get("updated_at"),
        "html_url": comment.get("html_url"),
        "body": comment.get("body"),
        "reactions": reactions,
    }


class GitHubIssueTransformer:
    """Transform a single GitHub issue into various formats."""

    def __init__(self) -> None:
        self._markdown_template = _ENV.get_template("template-github-issue-json-markdown.md")

    def to_markdown(self, issue: Dict[str, Any]) -> str:
        return self._markdown_template.render(**_issue_context(issue))

    def to_csv(self, issue: Dict[str, Any]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(
            [
                "number",
                "title",
                "state",
                "author",
                "labels",
                "assignees",
                "milestone",
                "created_at",
                "updated_at",
                "comments",
                "body",
            ]
        )

        user = issue.get("user", {})
        label_names = (_join_field(issue.get("labels", []), "name") or "").replace(",", ";")
        assignee_logins = (_join_field(issue.get("assignees", []), "login") or "").replace(",", ";")
        milestone = issue.get("milestone", {})

        writer.writerow(
            [
                issue.get("number", ""),
                issue.get("title", ""),
                issue.get("state", ""),
                user.get("login", "") if user else "",
                label_names,
                assignee_logins,
                milestone.get("title", "") if milestone else "",
                issue.get("created_at", ""),
                issue.get("updated_at", ""),
                issue.get("comments", 0),
                issue.get("body", "").replace("\n", " ").replace("\r", "")[:500],
            ]
        )

        return output.getvalue()

    def to_text(self, issue: Dict[str, Any]) -> str:
        context = _issue_context(issue)
        lines = []

        lines.append(f"Issue #{context['number']}: {context['title']}")
        lines.append(f"State: {context['state']}")
        lines.append(f"Repository: {context['owner']}/{context['repo']}")

        lines.append(f"Author: {context['author']}")
        if context["labels"]:
            lines.append(f"Labels: {context['labels']}")
        if context["assignees"]:
            lines.append(f"Assignees: {context['assignees']}")

        lines.append(f"Created: {context['created_at']}")
        lines.append(f"Updated: {context['updated_at']}")
        lines.append(f"Comments: {context['comments']}")
        lines.append("")
        lines.append("Description:")
        body = context.get("body") or "No description provided"
        lines.append(body)

        return "\n".join(lines)


class GitHubCommentsTransformer:
    """Transform GitHub comments into various formats."""

    def __init__(self) -> None:
        # v1 is the default, v2 is retained for compatibility if needed.
        self._markdown_template = _ENV.get_template("template-github-comments-json-markdown-1.md")
        self._markdown_template_v2 = _ENV.get_template("template-github-comments-json-markdown-2.md")

    def to_markdown(self, comments: List[Dict[str, Any]], *, variant: int = 1) -> str:
        normalized = [_normalize_comment(c) for c in comments or []]
        if variant == 2:
            return self._markdown_template_v2.render(total=len(normalized), comments=normalized)
        return self._markdown_template.render(total=len(normalized), comments=normalized)

    def to_csv(self, comments: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["id", "author", "created_at", "updated_at", "body"])

        for comment in comments:
            user = comment.get("user", {})
            writer.writerow(
                [
                    comment.get("id", ""),
                    user.get("login", "") if user else "",
                    comment.get("created_at", ""),
                    comment.get("updated_at", ""),
                    comment.get("body", "").replace("\n", " ").replace("\r", "")[:500],
                ]
            )

        return output.getvalue()

    def to_text(self, comments: List[Dict[str, Any]]) -> str:
        if not comments:
            return "No comments"

        normalized = [_normalize_comment(c) for c in comments]

        lines = []
        lines.append(f"Comments ({len(normalized)}):")
        lines.append("")

        for i, comment in enumerate(normalized, 1):
            lines.append(f"[Comment {i}] {comment['author']} ({comment['created_at']})")
            lines.append(comment.get("body") or "No content")
            if comment.get("reactions"):
                reactions = ", ".join(f"{k}: {v}" for k, v in comment["reactions"].items())
                lines.append(f"Reactions: {reactions}")
            lines.append("")

        return "\n".join(lines)


def register_github_issue_transformers() -> None:
    """Register GitHub templates in the shared transformer registry."""
    FormatTransformer.register("github_issue", GitHubIssueTransformer())
    FormatTransformer.register("github_comments", GitHubCommentsTransformer())
