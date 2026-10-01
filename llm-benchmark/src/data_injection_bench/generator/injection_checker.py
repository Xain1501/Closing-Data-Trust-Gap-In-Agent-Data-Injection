"""Heuristic checker for injected payload completeness."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pytest
import copy
from ..bench_types import AttackType, Category, Format
from ..generator.inject import Injector
from ..parsers import JSONParser


@dataclass
class InjectionCheckResult:
    """Result of an injection completeness check."""

    required_fields: List[str]
    missing_fields: List[str]
    found_fields: List[str]


def check_injection_completeness(
    original_input: Any,
    injection_field: str,
    injected_value: Any,
) -> InjectionCheckResult:
    """Check whether injected_value includes schema-required fields.

    Rules (heuristic):
    - Fields before the target in the parent object are required (fake opening).
    - Fields after the target in the parent object are required (fake closing).
    - For list-target injections (starts with [), require the first key
      of the list element schema as fake opening.
    - For object fields in the closing, require their last key as well.
    """
    data = _ensure_json(original_input)
    raw_payload = injected_value if isinstance(injected_value, str) else json.dumps(injected_value)

    parent, target_key, is_list_target = _get_parent_and_target(data, injection_field)
    required = []

    # print(f"\ntarget_key: {target_key}")
    # print(f"is_list_target: {is_list_target}")
    # print(f"injected_value: {injected_value}")

    if isinstance(parent, dict) and isinstance(target_key, str):
        keys = list(parent.keys())
        if target_key in keys:
            idx = keys.index(target_key)
            required.extend(keys[:idx])
            required.extend(keys[idx + 1 :])

            if is_list_target:
                element_schema = _first_list_element_schema(parent.get(target_key))
                if element_schema:
                    required.insert(0, element_schema[0])

            required.extend(_closing_leaf_keys(parent, keys[idx + 1 :]))

    required = _dedupe(required)
    reconstructed_payload = _reconstruct_payload_json(
        raw_payload,
        original_input=data,
        injection_field=injection_field,
    )
    # print(f"required: {required}\n")
    # print(f"raw_payload: {raw_payload}\n")
    # print(f"reconstructed_payload: {reconstructed_payload}\n")
    found = _fields_present_in_payload(required, reconstructed_payload, raw_payload)
    missing = [field for field in required if field not in found]
    return InjectionCheckResult(required_fields=required, missing_fields=missing, found_fields=found)


def _ensure_json(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _parse_path(path: str) -> List[str]:
    parts = []
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
            if current:
                parts.append(current)
                current = ""
        else:
            current += char
    if current:
        parts.append(current)
    return parts


def _get_parent_and_target(
    data: Any,
    injection_field: str,
) -> Tuple[Any, Optional[str], bool]:
    is_list_target = "[" in injection_field
    path = injection_field
    parts = _parse_path(path)
    if not parts:
        return None, None, is_list_target

    parent = data
    for part in parts[:-1]:
        if isinstance(parent, list):
            try:
                parent = parent[int(part)]
            except (ValueError, IndexError):
                return None, None, is_list_target
        elif isinstance(parent, dict):
            parent = parent.get(part)
        else:
            return None, None, is_list_target

    return parent, parts[-1], is_list_target


def _first_list_element_schema(value: Any) -> List[str]:
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, dict):
            return list(first.keys())
    return []


def _closing_leaf_keys(parent: Dict[str, Any], keys: List[str]) -> List[str]:
    leaf_keys = []
    for key in keys:
        value = parent.get(key)
        if isinstance(value, dict) and value:
            leaf_keys.append(list(value.keys())[-1])
    return leaf_keys


def _field_in_payload(field: str, payload: str) -> bool:
    pattern = rf'["\']{re.escape(field)}["\']\s*:'
    return re.search(pattern, payload) is not None


def _unescape_json_string(payload: str) -> str:
    """Convert escaped JSON characters back to their literal form."""
    try:
        return payload.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return payload


def _try_parse_json(candidate: str) -> Optional[Any]:
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _extract_embedded_structures(payload: str) -> List[Any]:
    """Scan for dict/list JSON structures inside an arbitrary string."""
    decoder = json.JSONDecoder()
    idx = 0
    found = []
    while idx < len(payload):
        try:
            obj, end = decoder.raw_decode(payload, idx)
            if isinstance(obj, dict):
                found.append(obj)
                idx = end
                continue
            if isinstance(obj, list) and any(isinstance(el, dict) for el in obj):
                found.append(obj)
                idx = end
                continue
            idx = end
        except json.JSONDecodeError:
            idx += 1
    return found


def _set_field(data: Any, path: str, value: Any) -> bool:
    """Replace a nested field in data; returns True on success."""
    parts = _parse_path(path)
    current = data
    for part in parts[:-1]:
        if isinstance(current, list):
            try:
                idx = int(part)
                current = current[idx]
            except (ValueError, IndexError, TypeError):
                return False
        elif isinstance(current, dict):
            if part not in current:
                return False
            current = current.get(part)
        else:
            return False

    if not parts:
        return False

    last = parts[-1]
    if isinstance(current, list):
        try:
            idx = int(last)
            current[idx] = value
            return True
        except (ValueError, IndexError, TypeError):
            return False
    elif isinstance(current, dict):
        current[last] = value
        return True
    return False


def _relative_path_after_first_index(parts: List[str]) -> str:
    """Drop the first list index from a parsed path and rebuild the remainder."""
    for i, part in enumerate(parts):
        if part.isdigit():
            tail = parts[i + 1 :]
            return ".".join(tail) if tail else ""
    return ".".join(parts)


def _decode_structures(payload: str) -> List[Any]:
    """Decode every JSON object/list found in a free-form string."""
    decoder = json.JSONDecoder()
    idx = 0
    decoded: List[Any] = []
    while idx < len(payload):
        try:
            obj, end = decoder.raw_decode(payload, idx)
            if isinstance(obj, (dict, list)):
                decoded.append(obj)
            idx = end
        except json.JSONDecodeError:
            idx += 1
    return decoded


def _reconstruct_payload_json(
    payload: Any,
    original_input: Any,
    injection_field: str,
) -> Optional[Any]:
    """Recover injected payload as JSON by reinserting it into the original structure."""
    if not isinstance(payload, str):
        return None

    normalized = _unescape_json_string(payload)
    normalized = normalized.replace("\n", "\\n")
    original_struct = _ensure_json(original_input)

    placeholder = "__PAYLOAD_PLACEHOLDER__"
    template = copy.deepcopy(original_struct)
    if not _set_field(template, injection_field, placeholder):
        return None

    template_container = template if isinstance(template, list) else [template]

    flattened = json.dumps(template_container, ensure_ascii=False)
    injected_text = flattened.replace(placeholder, normalized)

    try:
        reconstructed = json.loads(injected_text)
    except json.JSONDecodeError:
        return None

    return reconstructed if isinstance(reconstructed, list) else None


def _fields_present_in_payload(
    required: List[str],
    reconstructed_payload: Optional[Any],
    raw_payload: str,
) -> List[str]:
    """Check that each required field exists in every element of reconstructed payload."""
    if reconstructed_payload is None:
        return []

    def _field_exists(element: Any, field: str) -> bool:
        if isinstance(element, dict):
            if field in element:
                return True
            return any(_field_exists(v, field) for v in element.values())
        if isinstance(element, list):
            return any(_field_exists(item, field) for item in element)
        return False

    elements = reconstructed_payload if isinstance(reconstructed_payload, list) else [reconstructed_payload]
    if not elements or any(not isinstance(element, dict) for element in elements):
        return []

    return [
        field
        for field in required
        if all(_field_exists(element, field) for element in elements)
    ]


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _build_payload_with_fields(fields: List[str]) -> str:
    entries = [f"\"{field}\": \"x\"" for field in fields]
    return "{" + ", ".join(entries) + "}"


@pytest.mark.parametrize(
    "seed_path,injection_field,injection_content",
    [
        (
            "data/sample_seeds/api_004_issue_dtensor_fails_at_sharding_prop.json",
            "body",
            {"title": "fake", "user": {"login": "ghost"}},
        ),
        (
            "data/sample_seeds/api_004_comments_dtensor_fails_at_sharding_prop.json",
            "[0].body",
            {"user": {"login": "ghost"}, "author_association": "NONE", "body": "x"},
        ),
    ],
)
def test_injection_checker_complete_payloads_pass(
    seed_path: str,
    injection_field: str,
    injection_content: Dict[str, Any],
):
    with open(seed_path) as f:
        data = json.load(f)

    injector = Injector()
    malicious = injector.inject(
        data=data,
        category=Category.GITHUB_ISSUE,
        format=Format.JSON,
        attack_type=AttackType.INSERT_COMPLETE,
        injection_field=injection_field,
        injection_content=injection_content,
        attack_params={"quote_style": "double"},
    )

    payload = JSONParser(malicious).get_field(injection_field, "")
    result = check_injection_completeness(data, injection_field, payload)
    assert not result.missing_fields
