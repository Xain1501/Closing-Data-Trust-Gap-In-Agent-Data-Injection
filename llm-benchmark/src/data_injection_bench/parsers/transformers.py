"""Format transformers for converting between data formats."""

import csv
import io
from typing import Any, Dict, List, Optional, Protocol, Union

from .json_parser import JSONParser


class SchemaTransformer(Protocol):
    """Transformer protocol for a schema-specific formatter."""

    def to_markdown(self, data: Union[Dict, List]) -> str:
        """Convert parsed JSON into markdown."""

    def to_csv(self, data: Union[Dict, List]) -> str:
        """Convert parsed JSON into CSV."""

    def to_text(self, data: Union[Dict, List]) -> str:
        """Convert parsed JSON into plain text."""


class GenericTransformer:
    """Generic fallback transformer with minimal assumptions."""

    def to_markdown(self, data: Any) -> str:
        return self._generic_json_to_markdown(data)

    def to_csv(self, data: Any) -> str:
        return self._generic_json_to_csv(data)

    def to_text(self, data: Any) -> str:
        return self._generic_json_to_text(data)

    def _generic_json_to_markdown(self, data: Any, level: int = 1) -> str:
        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{'#' * level} {key}")
                    lines.append("")
                    lines.append(self._generic_json_to_markdown(value, level + 1))
                else:
                    lines.append(f"- **{key}**: {value}")
            return "\n".join(lines)
        if isinstance(data, list):
            lines = []
            for i, item in enumerate(data, 1):
                lines.append(f"{i}. {self._generic_json_to_markdown(item, level)}")
            return "\n".join(lines)
        return str(data)

    def _generic_json_to_csv(self, data: Any) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        if isinstance(data, list) and data and isinstance(data[0], dict):
            keys = list(data[0].keys())
            writer.writerow(keys)
            for item in data:
                writer.writerow([item.get(k, "") for k in keys])
        elif isinstance(data, dict):
            writer.writerow(["key", "value"])
            for key, value in data.items():
                writer.writerow([key, str(value)])
        else:
            writer.writerow(["value"])
            writer.writerow([str(data)])

        return output.getvalue()

    def _generic_json_to_text(self, data: Any, indent: int = 0) -> str:
        prefix = "  " * indent

        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{key}:")
                    lines.append(self._generic_json_to_text(value, indent + 1))
                else:
                    lines.append(f"{prefix}{key}: {value}")
            return "\n".join(lines)
        if isinstance(data, list):
            lines = []
            for item in data:
                if isinstance(item, (dict, list)):
                    lines.append(self._generic_json_to_text(item, indent))
                else:
                    lines.append(f"{prefix}- {item}")
            return "\n".join(lines)
        return f"{prefix}{data}"


class FormatTransformer:
    """Dispatch format transformations to schema-specific handlers."""

    _registry: Dict[str, SchemaTransformer] = {"__generic__": GenericTransformer()}
    _DEFAULT_SCHEMA_KEY = "__generic__"

    @classmethod
    def register(cls, schema: str, transformer: SchemaTransformer) -> None:
        """Register a schema-specific transformer."""
        cls._registry[schema] = transformer

    @classmethod
    def _resolve_schema(
        cls,
        schema: Optional[str],
        category_config: Optional[Dict[str, Any]],
        subcategory: Optional[str],
        transform_name: str,
    ) -> Optional[str]:
        if schema:
            return schema
        if category_config:
            schemas = category_config.get("schemas", {})
            if subcategory:
                transform_config = schemas.get(subcategory, {})
                if isinstance(transform_config, dict):
                    schema_entry = transform_config.get(transform_name)
                    if isinstance(schema_entry, dict):
                        return schema_entry.get("template")
                    if isinstance(schema_entry, str):
                        return schema_entry
        return None

    @classmethod
    def _get_transformer(cls, schema: Optional[str]) -> SchemaTransformer:
        if schema and schema in cls._registry:
            return cls._registry[schema]
        return cls._registry[cls._DEFAULT_SCHEMA_KEY]

    @classmethod
    def json_to_markdown(
        cls,
        data: Union[str, Dict, List],
        schema: Optional[str] = None,
        *,
        category_config: Optional[Dict[str, Any]] = None,
        subcategory: Optional[str] = None,
    ) -> str:
        """Convert JSON to Markdown format."""
        parser = JSONParser(data)
        resolved_schema = cls._resolve_schema(schema, category_config, subcategory, "json_to_markdown")
        transformer = cls._get_transformer(resolved_schema)
        return transformer.to_markdown(parser.to_dict())

    @classmethod
    def json_to_csv(
        cls,
        data: Union[str, Dict, List],
        schema: Optional[str] = None,
        *,
        category_config: Optional[Dict[str, Any]] = None,
        subcategory: Optional[str] = None,
    ) -> str:
        """Convert JSON to CSV format."""
        parser = JSONParser(data)
        resolved_schema = cls._resolve_schema(schema, category_config, subcategory, "json_to_csv")
        transformer = cls._get_transformer(resolved_schema)
        return transformer.to_csv(parser.to_dict())

    @classmethod
    def json_to_text(
        cls,
        data: Union[str, Dict, List],
        schema: Optional[str] = None,
        *,
        category_config: Optional[Dict[str, Any]] = None,
        subcategory: Optional[str] = None,
    ) -> str:
        """Convert JSON to plain text format."""
        parser = JSONParser(data)
        resolved_schema = cls._resolve_schema(schema, category_config, subcategory, "json_to_text")
        transformer = cls._get_transformer(resolved_schema)
        return transformer.to_text(parser.to_dict())
