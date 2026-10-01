"""Parsers for different data formats."""

from .json_parser import (
    JSONParser,
    extract_comment_fields,
    extract_issue_field,
    filter_comments,
    parse_github_comments,
    parse_github_issue,
)
from .github_issue_transformers import register_github_issue_transformers
from .transformers import FormatTransformer

# Register built-in transformers so category modules stay pluggable.
register_github_issue_transformers()

__all__ = [
    "JSONParser",
    "FormatTransformer",
    "register_github_issue_transformers",
    "parse_github_issue",
    "parse_github_comments",
    "extract_issue_field",
    "extract_comment_fields",
    "filter_comments",
]
