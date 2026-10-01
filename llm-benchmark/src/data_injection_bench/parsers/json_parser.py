"""JSON parser for structured data."""

import json
from typing import Any, Dict, List, Optional, Union


class JSONParser:
    """Parser for JSON-formatted tool outputs."""

    def __init__(self, data: Union[str, Dict, List]):
        """Initialize parser with JSON data.

        Args:
            data: JSON string or pre-parsed dict/list
        """
        if isinstance(data, str):
            self.data = json.loads(data)
        else:
            self.data = data

    def get_field(self, path: str, default: Any = None) -> Any:
        """Get field value using dot notation path.

        Args:
            path: Dot-separated path (e.g., 'user.login', 'items[0].title')
            default: Default value if path not found

        Returns:
            Field value or default

        Examples:
            >>> parser = JSONParser({'user': {'login': 'alice'}})
            >>> parser.get_field('user.login')
            'alice'
        """
        try:
            value = self.data
            for part in self._parse_path(path):
                if isinstance(part, int):
                    value = value[part]
                else:
                    value = value[part]
            return value
        except (KeyError, IndexError, TypeError):
            return default

    def get_list(self, path: str = "") -> List[Any]:
        """Get list at path.

        Args:
            path: Path to list (empty string for root if data is list)

        Returns:
            List at path or empty list if not found
        """
        if path:
            value = self.get_field(path, default=[])
        else:
            value = self.data

        if isinstance(value, list):
            return value
        return []

    def filter_items(
        self,
        list_path: str,
        predicate: callable,
    ) -> List[Any]:
        """Filter items in a list by predicate.

        Args:
            list_path: Path to list
            predicate: Function that takes item and returns bool

        Returns:
            Filtered list of items

        Examples:
            >>> data = {'issues': [{'state': 'open'}, {'state': 'closed'}]}
            >>> parser = JSONParser(data)
            >>> parser.filter_items('issues', lambda x: x['state'] == 'open')
            [{'state': 'open'}]
        """
        items = self.get_list(list_path)
        return [item for item in items if predicate(item)]

    def extract_fields(
        self,
        list_path: str,
        field_path: str,
    ) -> List[Any]:
        """Extract specific field from each item in a list.

        Args:
            list_path: Path to list
            field_path: Field path within each item

        Returns:
            List of extracted field values

        Examples:
            >>> data = {'issues': [{'title': 'Bug'}, {'title': 'Feature'}]}
            >>> parser = JSONParser(data)
            >>> parser.extract_fields('issues', 'title')
            ['Bug', 'Feature']
        """
        items = self.get_list(list_path)
        result = []
        for item in items:
            if isinstance(item, dict):
                item_parser = JSONParser(item)
                value = item_parser.get_field(field_path)
                if value is not None:
                    result.append(value)
        return result

    def count_items(self, list_path: str = "") -> int:
        """Count items in a list.

        Args:
            list_path: Path to list (empty for root list)

        Returns:
            Number of items
        """
        return len(self.get_list(list_path))

    def aggregate(
        self,
        list_path: str,
        field_path: str,
        operation: str,
    ) -> Optional[Union[int, float]]:
        """Aggregate numeric field across list items.

        Args:
            list_path: Path to list
            field_path: Path to numeric field within each item
            operation: One of 'sum', 'avg', 'min', 'max', 'count'

        Returns:
            Aggregated value

        Examples:
            >>> data = {'items': [{'price': 10}, {'price': 20}]}
            >>> parser = JSONParser(data)
            >>> parser.aggregate('items', 'price', 'sum')
            30
        """
        values = self.extract_fields(list_path, field_path)
        numeric_values = [v for v in values if isinstance(v, (int, float))]

        if not numeric_values:
            return None

        if operation == 'sum':
            return sum(numeric_values)
        elif operation == 'avg':
            return sum(numeric_values) / len(numeric_values)
        elif operation == 'min':
            return min(numeric_values)
        elif operation == 'max':
            return max(numeric_values)
        elif operation == 'count':
            return len(numeric_values)
        else:
            raise ValueError(f"Unknown operation: {operation}")

    def _parse_path(self, path: str) -> List[Union[str, int]]:
        """Parse dot notation path into parts.

        Args:
            path: Dot-separated path with optional array indices

        Returns:
            List of path components (strings and ints)

        Examples:
            >>> JSONParser({})._parse_path('user.name')
            ['user', 'name']
            >>> JSONParser({})._parse_path('items[0].title')
            ['items', 0, 'title']
        """
        parts = []
        current = ""

        for char in path:
            if char == '.':
                if current:
                    parts.append(current)
                    current = ""
            elif char == '[':
                if current:
                    parts.append(current)
                    current = ""
            elif char == ']':
                if current.isdigit():
                    parts.append(int(current))
                    current = ""
            else:
                current += char

        if current:
            parts.append(current)

        return parts

    def to_dict(self) -> Union[Dict, List]:
        """Get the underlying data structure.

        Returns:
            Parsed JSON data
        """
        return self.data


# Helper functions for GitHub-specific parsing

def parse_github_issue(data: Union[str, Dict]) -> JSONParser:
    """Parse GitHub issue JSON.

    Args:
        data: Issue JSON data

    Returns:
        JSONParser instance
    """
    return JSONParser(data)


def parse_github_comments(data: Union[str, List]) -> JSONParser:
    """Parse GitHub comments JSON.

    Args:
        data: Comments JSON data (list)

    Returns:
        JSONParser instance
    """
    return JSONParser(data)


def extract_issue_field(issue_data: Union[str, Dict], field: str) -> Any:
    """Extract field from GitHub issue.

    Args:
        issue_data: Issue JSON
        field: Field name (supports dot notation)

    Returns:
        Field value

    Examples:
        >>> extract_issue_field({'title': 'Bug report'}, 'title')
        'Bug report'
        >>> extract_issue_field({'user': {'login': 'alice'}}, 'user.login')
        'alice'
    """
    parser = parse_github_issue(issue_data)
    return parser.get_field(field)


def extract_comment_fields(comments_data: Union[str, List], field: str) -> List[Any]:
    """Extract field from all comments.

    Args:
        comments_data: Comments JSON (list)
        field: Field name (supports dot notation)

    Returns:
        List of field values

    Examples:
        >>> comments = [{'body': 'Hello'}, {'body': 'World'}]
        >>> extract_comment_fields(comments, 'body')
        ['Hello', 'World']
    """
    parser = parse_github_comments(comments_data)
    return parser.extract_fields("", field)


def filter_comments(
    comments_data: Union[str, List],
    predicate: callable,
) -> List[Dict]:
    """Filter comments by predicate.

    Args:
        comments_data: Comments JSON (list)
        predicate: Function that takes comment dict and returns bool

    Returns:
        Filtered comments

    Examples:
        >>> comments = [{'author_association': 'OWNER'}, {'author_association': 'NONE'}]
        >>> filter_comments(comments, lambda c: c['author_association'] == 'OWNER')
        [{'author_association': 'OWNER'}]
    """
    parser = parse_github_comments(comments_data)
    return parser.filter_items("", predicate)
