"""Helpers for parsing and manipulating field paths."""

from __future__ import annotations

from typing import Any, List, Optional, Tuple, Union

from .parsers import JSONParser


PathPart = Union[str, int]


def parse_path(path: str) -> List[PathPart]:
    """Parse dot-notation paths with list indices into parts."""
    parts: List[PathPart] = []
    current = ""
    for char in path:
        if char == ".":
            if current:
                parts.append(current)
                current = ""
        elif char == "[":
            if current:
                parts.append(current)
                current = ""
        elif char == "]":
            if current.isdigit():
                parts.append(int(current))
                current = ""
        else:
            current += char
    if current:
        parts.append(current)
    return parts


def parts_to_path(parts: List[PathPart]) -> str:
    """Rebuild a path string from parsed parts."""
    path = ""
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            if path and not path.endswith("]"):
                path += "."
            elif path and path.endswith("]"):
                path += "."
            path += part
    return path


def split_first_list_index(path: str) -> Optional[Tuple[str, int, str]]:
    """Return (list_path, index, suffix_path) for the first list index."""
    parts = parse_path(path)
    for idx, part in enumerate(parts):
        if isinstance(part, int):
            list_path = parts_to_path(parts[:idx])
            suffix_path = parts_to_path(parts[idx + 1 :])
            return list_path, part, suffix_path
    return None


def list_path_from_template(template: str) -> Optional[str]:
    """Get the list path for a template with a single [] placeholder."""
    if "[]" not in template:
        return None
    normalized = template.replace("[]", "[0]", 1)
    info = split_first_list_index(normalized)
    if not info:
        return None
    return info[0]


def resolve_injection_field(
    template: Optional[str],
    target_field: str,
    data_source: Any,
) -> Optional[str]:
    """Resolve [] in template to an index based on target_field and data."""
    if not template or "[]" not in template:
        return template
    target_info = split_first_list_index(target_field)
    target_idx = target_info[1] if target_info else 0
    list_path = list_path_from_template(template)
    if list_path is None:
        return template.replace("[]", f"[{target_idx}]", 1)
    try:
        parser = JSONParser(data_source)
        items = parser.get_list(list_path)
        if items:
            target_idx = max(0, min(target_idx, len(items) - 1))
    except Exception:
        pass
    return template.replace("[]", f"[{target_idx}]", 1)


def get_parent_and_key(data: Any, path: str) -> Tuple[Optional[Any], Optional[PathPart]]:
    """Return (parent, key) for a path, or (None, None) on failure."""
    parts = parse_path(path)
    if not parts:
        return None, None
    current = data
    for part in parts[:-1]:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return None, None
            current = current[part]
        else:
            if not isinstance(current, dict) or part not in current:
                return None, None
            current = current[part]
    return current, parts[-1]


def set_path_value(data: Any, path: str, value: Any) -> bool:
    """Set a value in a nested structure. Returns True on success."""
    parts = parse_path(path)
    if not parts:
        return False
    current = data
    for part in parts[:-1]:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return False
            current = current[part]
        else:
            if not isinstance(current, dict):
                return False
            if part not in current or current[part] is None:
                current[part] = {}
            current = current[part]
    last = parts[-1]
    if isinstance(last, int):
        if not isinstance(current, list) or last >= len(current):
            return False
        current[last] = value
        return True
    if not isinstance(current, dict):
        return False
    current[last] = value
    return True


def build_nested_value(path: str, value: Any) -> Any:
    """Build a nested structure that sets path to value."""
    parts = parse_path(path)
    if not parts:
        return value
    current = value
    for part in reversed(parts):
        if isinstance(part, int):
            items: List[Any] = []
            while len(items) <= part:
                items.append(None)
            items[part] = current
            current = items
        else:
            current = {part: current}
    return current


def rebuild_indexed_path(list_path: str, index: int, suffix: str) -> str:
    """Rebuild a path with a new list index and suffix."""
    prefix = f"{list_path}[{index}]" if list_path else f"[{index}]"
    if suffix:
        return f"{prefix}.{suffix}"
    return prefix
