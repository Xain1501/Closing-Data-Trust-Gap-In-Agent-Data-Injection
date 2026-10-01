"""Aggregation tasks for the benchmark."""

import json
from typing import Any, Dict, List, Optional

from ..parsers import JSONParser
from ..bench_types import Format


class AggregationTask:
    """Aggregate values across multiple items."""

    def __init__(
        self,
        list_path: str,
        field_path: str,
        operation: str,
        format: Format = Format.JSON,
    ):
        """Initialize aggregation task.

        Args:
            list_path: Path to list (empty string for root list)
            field_path: Path to field within each item
            operation: Aggregation operation (sum, avg, min, max, count)
            format: Data format
        """
        self.list_path = list_path
        self.field_path = field_path
        self.operation = operation.lower()
        self.format = format

        if self.operation not in ['sum', 'avg', 'min', 'max', 'count']:
            raise ValueError(f"Unknown operation: {operation}")

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Compute groundtruth by aggregating values.

        Args:
            data: Input data
            schema: Optional schema hint

        Returns:
            Aggregated value as string
        """
        if self.format == Format.JSON:
            parser = JSONParser(data)
            result = parser.aggregate(self.list_path, self.field_path, self.operation)
            return self._format_result(result)
        else:
            raise NotImplementedError(f"Aggregation from {self.format} not yet implemented")

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate task prompt for LLM.

        Args:
            schema: Optional schema hint

        Returns:
            Task prompt
        """
        field_name = self.field_path.split('.')[-1].replace('_', ' ')

        if self.operation == 'sum':
            prompt = f"What is the total sum of {field_name} across all items?"
        elif self.operation == 'avg':
            prompt = f"What is the average {field_name} across all items?"
        elif self.operation == 'min':
            prompt = f"What is the minimum {field_name} across all items?"
        elif self.operation == 'max':
            prompt = f"What is the maximum {field_name} across all items?"
        elif self.operation == 'count':
            prompt = f"How many items have a {field_name} value?"
        else:
            prompt = f"Compute the {self.operation} of {field_name}."

        return prompt + " Return only the numeric value, nothing else."

    def _format_result(self, result: Optional[float]) -> str:
        """Format aggregation result.

        Args:
            result: Numeric result or None

        Returns:
            String representation
        """
        if result is None:
            return "0"
        elif isinstance(result, float) and result.is_integer():
            return str(int(result))
        elif isinstance(result, float):
            return f"{result:.2f}"
        else:
            return str(result)


class CountTask:
    """Count items in a list."""

    def __init__(self, list_path: str = "", format: Format = Format.JSON):
        """Initialize count task.

        Args:
            list_path: Path to list (empty string for root list)
            format: Data format
        """
        self.list_path = list_path
        self.format = format

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Compute groundtruth by counting items.

        Args:
            data: Input data
            schema: Optional schema hint

        Returns:
            Count as string
        """
        if self.format == Format.JSON:
            parser = JSONParser(data)
            count = parser.count_items(self.list_path)
            return str(count)
        else:
            raise NotImplementedError(f"Counting from {self.format} not yet implemented")

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate task prompt for LLM.

        Args:
            schema: Optional schema hint

        Returns:
            Task prompt
        """
        if schema == "github_comments":
            return "How many comments are there? Return only the number, nothing else."
        elif schema == "github_issue":
            if self.list_path == "labels":
                return "How many labels does this issue have? Return only the number, nothing else."
            elif self.list_path == "assignees":
                return "How many assignees does this issue have? Return only the number, nothing else."
            else:
                return "How many items are there? Return only the number, nothing else."
        else:
            return "How many items are there in the list? Return only the number, nothing else."


class TopKTask:
    """Find top-k items by a field value."""

    def __init__(
        self,
        list_path: str,
        field_path: str,
        k: int,
        reverse: bool = True,
        format: Format = Format.JSON,
    ):
        """Initialize top-k task.

        Args:
            list_path: Path to list
            field_path: Field to sort by
            k: Number of items to return
            reverse: If True, return largest values; if False, return smallest
            format: Data format
        """
        self.list_path = list_path
        self.field_path = field_path
        self.k = k
        self.reverse = reverse
        self.format = format

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Compute groundtruth by finding top-k items.

        Args:
            data: Input data
            schema: Optional schema hint

        Returns:
            Top-k items as JSON list
        """
        if self.format == Format.JSON:
            parser = JSONParser(data)
            items = parser.get_list(self.list_path)

            # Extract field values and sort
            items_with_values = []
            for item in items:
                if isinstance(item, dict):
                    item_parser = JSONParser(item)
                    value = item_parser.get_field(self.field_path)
                    if value is not None and isinstance(value, (int, float)):
                        items_with_values.append((value, item))

            # Sort and take top k
            items_with_values.sort(key=lambda x: x[0], reverse=self.reverse)
            top_k = [item for _, item in items_with_values[:self.k]]

            return json.dumps(top_k, ensure_ascii=False)
        else:
            raise NotImplementedError(f"Top-k from {self.format} not yet implemented")

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate task prompt for LLM.

        Args:
            schema: Optional schema hint

        Returns:
            Task prompt
        """
        field_name = self.field_path.split('.')[-1].replace('_', ' ')
        direction = "highest" if self.reverse else "lowest"

        return f"Find the top {self.k} items with the {direction} {field_name}. Return as a JSON list containing only the IDs of the items."


