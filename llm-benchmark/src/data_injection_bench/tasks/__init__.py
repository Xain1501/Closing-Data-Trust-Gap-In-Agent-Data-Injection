"""Task implementations for the benchmark."""

# Generic tasks
from .extraction import ExtractionTask
from .filtering import FilteringTask, Predicates
from .aggregation import AggregationTask, CountTask, TopKTask

# GitHub-specific tasks
from .github_tasks import (
    # Issue tasks
    GitHubIssueExtraction,
    GitHubIssueSummary,
    create_issue_extraction,
    create_issue_summary,
    # Comment tasks
    GitHubCommentExtraction,
    GitHubCommentsSummary,
    GitHubCommentsAuthorsExtraction,
    GitHubCommentsTopics,
    create_comment_extraction,
    create_comments_summary,
    create_comments_authors,
    create_comments_topics,
    # Comment filtering
    GitHubCommentsFilter,
    create_comments_by_author_filter,
    create_comments_containing_filter,
    create_comments_by_association_filter,
    # Comment aggregation
    GitHubCommentsCount,
    GitHubCommentsAggregation,
    create_comments_count,
    create_comments_aggregation,
    create_top_k_comments,
)

__all__ = [
    # Generic tasks
    "ExtractionTask",
    "FilteringTask",
    "Predicates",
    "AggregationTask",
    "CountTask",
    "TopKTask",
    # GitHub issue tasks
    "GitHubIssueExtraction",
    "GitHubIssueSummary",
    "create_issue_extraction",
    "create_issue_summary",
    # GitHub comment tasks
    "GitHubCommentExtraction",
    "GitHubCommentsSummary",
    "GitHubCommentsAuthorsExtraction",
    "GitHubCommentsTopics",
    "create_comment_extraction",
    "create_comments_summary",
    "create_comments_authors",
    "create_comments_topics",
    # GitHub filtering
    "GitHubCommentsFilter",
    "create_comments_by_author_filter",
    "create_comments_containing_filter",
    "create_comments_by_association_filter",
    # GitHub aggregation
    "GitHubCommentsCount",
    "GitHubCommentsAggregation",
    "create_comments_count",
    "create_comments_aggregation",
    "create_top_k_comments",
]
