"""Generic extraction tasks for the benchmark."""

from typing import Any, Optional

from ..parsers import JSONParser
from ..bench_types import Format


class ExtractionTask:
    """Extract a single field from structured data."""

    def __init__(self, field_path: str, format: Format = Format.JSON):
        """Initialize extraction task.

        Args:
            field_path: Path to field (dot notation for JSON, e.g., 'user.login')
                       Supports nested fields: 'user.profile.email'
                       Supports array indexing: 'items[0].name'
            format: Data format
        """
        self.field_path = field_path
        self.format = format

    def compute_groundtruth(self, data: str, schema: Optional[str] = None) -> str:
        """Compute groundtruth answer by extracting field.

        Args:
            data: Input data (JSON, Markdown, CSV, or Text)
            schema: Optional schema hint (e.g., 'github_issue')

        Returns:
            Extracted field value as string
        """
        if self.format == Format.JSON:
            parser = JSONParser(data)
            value = parser.get_field(self.field_path)
            return self._format_value(value)
        else:
            # For non-JSON formats, we need to parse back to JSON first
            # This is a simplification - in practice, we'd need format-specific extractors
            raise NotImplementedError(f"Extraction from {self.format} not yet implemented")

    def generate_prompt(self, schema: Optional[str] = None) -> str:
        """Generate task prompt for LLM.

        Args:
            schema: Optional schema hint

        Returns:
            Task prompt
        """
        # Convert path to human-readable field name
        field_name = self.field_path.split('.')[-1].replace('[', '').replace(']', '')
        field_name_readable = field_name.replace('_', ' ')

        return f"Extract the {field_name_readable}. Return only the value, nothing else."

    @staticmethod
    def _format_value(value: Any) -> str:
        """Format value as string.

        Args:
            value: Value to format

        Returns:
            String representation
        """
        if value is None:
            return ""
        elif isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, (list, dict)):
            import json
            return json.dumps(value, ensure_ascii=False)
        else:
            return str(value)
