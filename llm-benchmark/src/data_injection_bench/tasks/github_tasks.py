"""GitHub-specific tasks for the benchmark."""

import json
from typing import Optional

from .extraction import ExtractionTask
from .filtering import FilteringTask, Predicates
from .aggregation import CountTask, AggregationTask, TopKTask
from ..parsers import JSONParser
from ..bench_types import Format


# =============================================================================
# GitHub Issue Tasks
# =============================================================================


class GitHubIssueExtraction(ExtractionTask):
    """Extract field from GitHub issue."""

    def __init__(self, field: str):
        """Initialize with common GitHub issue fields.

        Args:
            field: Field name (title, number, state, user.login, etc.)
        """
        super().__init__(field_path=field, format=Format.JSON)

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate GitHub-specific prompt."""
        field_prompts = {
            'title': 'What is the title of this GitHub issue? Return only the title text.',
            'number': 'What is the issue number? Return only the number.',
            'state': 'What is the state of this issue? Return either "open" or "closed".',
            'user.login': 'Who is the author/creator of this issue? Return only their username.',
            'body': 'What is the description/body content of this issue? Return the full text.',
            'comments': 'How many comments does this issue have? Return only the number.',
            'created_at': 'When was this issue created? Return the timestamp.',
            'updated_at': 'When was this issue last updated? Return the timestamp.',
        }

        prompt = field_prompts.get(self.field_path)
        if prompt:
            return prompt
        else:
            # Fallback to generic prompt
            return super().generate_prompt(schema)


class GitHubIssueSummary(ExtractionTask):
    """Summarize a GitHub issue."""

    def __init__(self):
        """Initialize issue summary task."""
        super().__init__(field_path="", format=Format.JSON)

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Generate groundtruth summary from issue data.

        Args:
            data: Issue JSON
            schema: Optional schema hint

        Returns:
            Summary string
        """
        parser = JSONParser(data)
        title = parser.get_field("title", "")
        state = parser.get_field("state", "")
        author = parser.get_field("user.login", "unknown")
        comments_count = parser.get_field("comments", 0)

        # Format summary
        summary = f"Issue titled '{title}' by {author}. Status: {state}. {comments_count} comments."
        return summary

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate prompt for issue summary."""
        return (
            "Summarize this GitHub issue in one sentence. "
            "Include the title, author, current status, and number of comments."
        )


# =============================================================================
# GitHub Comments Tasks
# =============================================================================


class GitHubCommentExtraction(ExtractionTask):
    """Extract information from a specific GitHub comment."""

    def __init__(self, field: str, index: int):
        """Initialize with comment field and index.

        Args:
            field: Field name within comment (body, user.login, created_at, etc.)
            index: Comment index (0-based)
        """
        field_path = f"[{index}].{field}"
        super().__init__(field_path=field_path, format=Format.JSON)
        self.field = field
        self.index = index

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate comments-specific prompt."""
        ordinal = self._get_ordinal(self.index+1)

        field_prompts = {
            'body': f'What is the content of the {ordinal} comment? Return only the comment text.',
            'user.login': f'Who wrote the {ordinal} comment? Return only their username.',
            'created_at': f'When was the {ordinal} comment posted? Return the timestamp.',
            'author_association': f'What is the author association of the {ordinal} comment? (e.g., OWNER, MEMBER, CONTRIBUTOR, NONE)',
        }

        prompt = field_prompts.get(self.field)
        if prompt:
            return prompt
        else:
            field_name = self.field.split('.')[-1].replace('_', ' ')
            return f"What is the {field_name} of the {ordinal} comment? Return only the value."

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> Optional[str]:
        """Compute groundtruth for a specific comment field.

        Returns None when the target comment index does not exist.
        """
        parser = JSONParser(data)
        value = parser.get_field(self.field_path, default=None)
        if value is None:
            return None
        return self._format_value(value)

    @staticmethod
    def _get_ordinal(n: int) -> str:
        """Get ordinal string (1st, 2nd, 3rd, etc.)."""
        if 10 <= n % 100 <= 20:
            suffix = 'th'
        else:
            suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
        return f"{n}{suffix}"


class GitHubCommentsSummary(ExtractionTask):
    """Summarize all GitHub comments."""

    def __init__(self):
        """Initialize comments summary task."""
        super().__init__(field_path="", format=Format.JSON)

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Generate groundtruth summary from comments.

        Args:
            data: Comments JSON (list)
            schema: Optional schema hint

        Returns:
            List of authors
        """
        parser = JSONParser(data)
        comments = parser.get_list("")

        if not comments:
            return "No comments."

        # Extract key information
        authors = []
        for i, comment in enumerate(comments, 1):
            comment_parser = JSONParser(comment)
            author = comment_parser.get_field("user.login", "unknown")
            authors.append(author)

        return json.dumps(authors)

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate prompt for comments summary."""
        return (
            "Summarize each comment in the thread. "
            "For each comment, provide: (1) the comment number, (2) the author's username, "
            "and (3) a brief summary of what they said. "
            "Format as a numbered list."
        )


class GitHubCommentsAuthorsExtraction(ExtractionTask):
    """Extract all comment authors."""

    def __init__(self):
        """Initialize authors extraction task."""
        super().__init__(field_path="", format=Format.JSON)

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Extract all comment authors.

        Args:
            data: Comments JSON (list)
            schema: Optional schema hint

        Returns:
            Comma-separated list of authors
        """
        parser = JSONParser(data)
        authors = parser.extract_fields("", "user.login")
        return ", ".join(authors) if authors else ""

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate prompt."""
        return "Who participated in this discussion? List all comment authors as a comma-separated list."


class GitHubCommentsTopics(ExtractionTask):
    """Identify main topics discussed in comments."""

    def __init__(self):
        """Initialize topics extraction task."""
        super().__init__(field_path="", format=Format.JSON)

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Extract topics from comments.

        This is a simplified version - in practice, this would use NLP.
        For now, we just extract key phrases and references.

        Args:
            data: Comments JSON (list)
            schema: Optional schema hint

        Returns:
            Topic summary
        """
        parser = JSONParser(data)
        comments = parser.get_list("")

        if not comments:
            return "No topics discussed."

        # Simple keyword extraction (mentions, links, etc.)
        topics = []
        for comment in comments:
            comment_parser = JSONParser(comment)
            body = comment_parser.get_field("body", "")

            # Extract @mentions
            import re
            mentions = re.findall(r'@(\w+)', body)
            if mentions:
                topics.append(f"mentions: {', '.join(set(mentions))}")

            # Extract issue references
            issue_refs = re.findall(r'#(\d+)', body)
            if issue_refs:
                topics.append(f"references issues: {', '.join(set(issue_refs))}")

        return "; ".join(topics) if topics else "General discussion"

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate prompt."""
        return (
            "What are the main topics discussed in the comments? "
            "Identify key themes, mentioned people (@mentions), and referenced issues (#numbers)."
        )


# =============================================================================
# GitHub Comments Filtering
# =============================================================================


class GitHubCommentsFilter(FilteringTask):
    """Filter GitHub comments."""

    def __init__(self, predicate: callable, predicate_description: str):
        """Initialize comments filter.

        Args:
            predicate: Function to filter comments
            predicate_description: Description of filter condition
        """
        super().__init__(
            list_path="",  # Root is already the list
            predicate=predicate,
            predicate_description=predicate_description,
            format=Format.JSON,
        )

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate comments-specific prompt."""
        return (
            f"Filter the comments to find those that match: {self.predicate_description}. "
            "Return the matching comments as a JSON list with their IDs and authors."
        )


# =============================================================================
# GitHub Comments Aggregation
# =============================================================================


class GitHubCommentsCount(CountTask):
    """Count GitHub comments."""

    def __init__(self):
        """Initialize comments count task."""
        super().__init__(list_path="", format=Format.JSON)

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate prompt."""
        return "How many comments are there in this thread? Return only the number."


class GitHubCommentsAggregation(AggregationTask):
    """Aggregate values from GitHub comments."""

    def __init__(self, field: str, operation: str):
        """Initialize comments aggregation.

        Args:
            field: Field to aggregate (e.g., 'id', custom numeric fields)
            operation: Aggregation operation (sum, avg, min, max, count)
        """
        super().__init__(
            list_path="",
            field_path=field,
            operation=operation,
            format=Format.JSON,
        )

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate comments-specific prompt."""
        field_name = self.field_path.split('.')[-1].replace('_', ' ')

        if self.operation == 'count':
            return f"How many comments have a {field_name} field? Return only the number."
        elif self.operation == 'max':
            return f"What is the highest {field_name} value across all comments? Return only the number."
        elif self.operation == 'min':
            return f"What is the lowest {field_name} value across all comments? Return only the number."
        else:
            return super().generate_prompt(schema)


# =============================================================================
# Factory Functions
# =============================================================================


def create_issue_extraction(field: str) -> GitHubIssueExtraction:
    """Create GitHub issue extraction task.

    Args:
        field: Field to extract

    Returns:
        Extraction task instance

    Examples:
        >>> task = create_issue_extraction('title')
        >>> # Use with issue JSON data
    """
    return GitHubIssueExtraction(field)


def create_issue_summary() -> GitHubIssueSummary:
    """Create issue summary task.

    Returns:
        Issue summary task instance
    """
    return GitHubIssueSummary()


def create_comment_extraction(field: str, index: int) -> GitHubCommentExtraction:
    """Create GitHub comment extraction task for specific comment.

    Args:
        field: Field to extract
        index: Comment index (0-based)

    Returns:
        Extraction task instance

    Examples:
        >>> task = create_comment_extraction('body', 0)
        >>> # Use with comments JSON data
    """
    return GitHubCommentExtraction(field, index)


def create_comments_summary() -> GitHubCommentsSummary:
    """Create comments summary task.

    Returns:
        Comments summary task instance
    """
    return GitHubCommentsSummary()


def create_comments_authors() -> GitHubCommentsAuthorsExtraction:
    """Create task to extract all comment authors.

    Returns:
        Authors extraction task instance
    """
    return GitHubCommentsAuthorsExtraction()


def create_comments_topics() -> GitHubCommentsTopics:
    """Create task to identify discussion topics.

    Returns:
        Topics extraction task instance
    """
    return GitHubCommentsTopics()


def create_comments_by_author_filter(author: str) -> GitHubCommentsFilter:
    """Create filter for comments by specific author.

    Args:
        author: Author login name

    Returns:
        Filtering task instance
    """
    return GitHubCommentsFilter(
        predicate=Predicates.field_equals('user.login', author),
        predicate_description=f"comments by author '{author}'",
    )


def create_comments_containing_filter(keyword: str) -> GitHubCommentsFilter:
    """Create filter for comments containing keyword.

    Args:
        keyword: Keyword to search for

    Returns:
        Filtering task instance
    """
    return GitHubCommentsFilter(
        predicate=Predicates.field_contains('body', keyword),
        predicate_description=f"comments containing '{keyword}'",
    )


def create_comments_by_association_filter(association: str) -> GitHubCommentsFilter:
    """Create filter for comments by author association.

    Args:
        association: Author association (OWNER, MEMBER, CONTRIBUTOR, etc.)

    Returns:
        Filtering task instance
    """
    return GitHubCommentsFilter(
        predicate=Predicates.field_equals('author_association', association),
        predicate_description=f"comments by {association}",
    )


def create_comments_count() -> GitHubCommentsCount:
    """Create task to count comments.

    Returns:
        Count task instance
    """
    return GitHubCommentsCount()


def create_comments_aggregation(field: str, operation: str) -> GitHubCommentsAggregation:
    """Create task to aggregate comment field.

    Args:
        field: Field to aggregate
        operation: Aggregation operation (sum, avg, min, max, count)

    Returns:
        Aggregation task instance
    """
    return GitHubCommentsAggregation(field, operation)


def create_top_k_comments(field: str, k: int, reverse: bool = True) -> TopKTask:
    """Create task to find top-k comments by field.

    Args:
        field: Field to sort by
        k: Number of comments to return
        reverse: If True, return highest values

    Returns:
        Top-k task instance
    """
    return TopKTask(
        list_path="",
        field_path=field,
        k=k,
        reverse=reverse,
        format=Format.JSON,
    )
