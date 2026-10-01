"""Filtering tasks for the benchmark."""

import json
from typing import Any, Callable, Dict, List, Optional

from ..parsers import JSONParser
from ..bench_types import Format


class FilteringTask:
    """Filter items by predicate."""

    def __init__(
        self,
        list_path: str,
        predicate: Callable[[Dict], bool],
        predicate_description: str,
        format: Format = Format.JSON,
    ):
        """Initialize filtering task.

        Args:
            list_path: Path to list to filter (empty string for root list)
            predicate: Function that returns True for items to keep
            predicate_description: Human-readable description of predicate
            format: Data format
        """
        self.list_path = list_path
        self.predicate = predicate
        self.predicate_description = predicate_description
        self.format = format

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Compute groundtruth by filtering items.

        Args:
            data: Input data
            schema: Optional schema hint

        Returns:
            Filtered items as JSON list
        """
        if self.format == Format.JSON:
            parser = JSONParser(data)
            filtered = parser.filter_items(self.list_path, self.predicate)
            return json.dumps(filtered, ensure_ascii=False)
        else:
            raise NotImplementedError(f"Filtering from {self.format} not yet implemented")

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate task prompt for LLM.

        Args:
            schema: Optional schema hint

        Returns:
            Task prompt
        """
        return f"Filter the items: {self.predicate_description}. Return the matching items as a JSON list."


# Common predicate builders

class Predicates:
    """Common predicates for filtering tasks."""

    @staticmethod
    def field_equals(field: str, value: Any) -> Callable[[Dict], bool]:
        """Create predicate that checks if field equals value.

        Args:
            field: Field path (supports dot notation)
            value: Expected value

        Returns:
            Predicate function

        Examples:
            >>> pred = Predicates.field_equals('state', 'open')
            >>> pred({'state': 'open'})
            True
        """
        def predicate(item: Dict) -> bool:
            parser = JSONParser(item)
            return parser.get_field(field) == value
        return predicate

    @staticmethod
    def field_contains(field: str, substring: str) -> Callable[[Dict], bool]:
        """Create predicate that checks if field contains substring.

        Args:
            field: Field path
            substring: Substring to search for

        Returns:
            Predicate function

        Examples:
            >>> pred = Predicates.field_contains('body', 'bug')
            >>> pred({'body': 'This is a bug report'})
            True
        """
        def predicate(item: Dict) -> bool:
            parser = JSONParser(item)
            value = parser.get_field(field)
            if isinstance(value, str):
                return substring.lower() in value.lower()
            return False
        return predicate

    @staticmethod
    def field_in(field: str, values: List[Any]) -> Callable[[Dict], bool]:
        """Create predicate that checks if field value is in list.

        Args:
            field: Field path
            values: List of acceptable values

        Returns:
            Predicate function

        Examples:
            >>> pred = Predicates.field_in('author_association', ['OWNER', 'MEMBER'])
            >>> pred({'author_association': 'OWNER'})
            True
        """
        def predicate(item: Dict) -> bool:
            parser = JSONParser(item)
            return parser.get_field(field) in values
        return predicate

    @staticmethod
    def field_greater_than(field: str, threshold: float) -> Callable[[Dict], bool]:
        """Create predicate that checks if numeric field > threshold.

        Args:
            field: Field path
            threshold: Numeric threshold

        Returns:
            Predicate function

        Examples:
            >>> pred = Predicates.field_greater_than('comments', 5)
            >>> pred({'comments': 10})
            True
        """
        def predicate(item: Dict) -> bool:
            parser = JSONParser(item)
            value = parser.get_field(field)
            if isinstance(value, (int, float)):
                return value > threshold
            return False
        return predicate

    @staticmethod
    def field_less_than(field: str, threshold: float) -> Callable[[Dict], bool]:
        """Create predicate that checks if numeric field < threshold.

        Args:
            field: Field path
            threshold: Numeric threshold

        Returns:
            Predicate function
        """
        def predicate(item: Dict) -> bool:
            parser = JSONParser(item)
            value = parser.get_field(field)
            if isinstance(value, (int, float)):
                return value < threshold
            return False
        return predicate

    @staticmethod
    def has_field(field: str) -> Callable[[Dict], bool]:
        """Create predicate that checks if field exists and is not None.

        Args:
            field: Field path

        Returns:
            Predicate function

        Examples:
            >>> pred = Predicates.has_field('assignee')
            >>> pred({'assignee': 'alice'})
            True
            >>> pred({'assignee': None})
            False
        """
        def predicate(item: Dict) -> bool:
            parser = JSONParser(item)
            value = parser.get_field(field)
            return value is not None
        return predicate

    @staticmethod
    def label_matches(label_name: str) -> Callable[[Dict], bool]:
        """Create predicate for GitHub issues with specific label.

        Args:
            label_name: Label name to match

        Returns:
            Predicate function

        Examples:
            >>> pred = Predicates.label_matches('bug')
            >>> pred({'labels': [{'name': 'bug'}]})
            True
        """
        def predicate(item: Dict) -> bool:
            labels = item.get('labels', [])
            if not isinstance(labels, list):
                return False
            return any(
                label.get('name', '').lower() == label_name.lower()
                for label in labels
                if isinstance(label, dict)
            )
        return predicate


