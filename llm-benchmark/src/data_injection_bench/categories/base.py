"""Category handler base types."""

from dataclasses import dataclass
import copy
from typing import Any, Dict, List, Optional, Protocol

from ..bench_types import AttackType, Category, Format
from ..field_utils import (
    build_nested_value,
    get_parent_and_key,
    resolve_injection_field,
    set_path_value,
    split_first_list_index,
)


@dataclass
class AttackPlan:
    """Planned attack details for a single instance."""

    injection_field: str
    injection_content: Any
    targeted_output: Optional[str]
    data_source: Any
    attack_type: AttackType
    # For insert attacks, these may differ from the original task
    target_field: Optional[str] = None
    task_prompt: Optional[str] = None
    groundtruth: Optional[str] = None
    # For markdown INSERT_COMPLETE: insert at idx (True) or idx+1 (False)
    insert_before: bool = False


class CategoryHandler(Protocol):
    """Protocol for category-specific behavior."""

    name: Category

    def load_seeds(
        self,
        seeds_dir: str,
        limit: Optional[int] = None,
        seed_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load seeds for this category."""

    def generate_tasks(
        self,
        seed: Dict[str, Any],
        formats: List[Format],
        category_config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate tasks for a seed."""

    def plan_attack(
        self,
        seed: Dict[str, Any],
        task_dict: Dict[str, Any],
        attack_config: Dict[str, Any],
        category_config: Dict[str, Any],
    ) -> Optional[AttackPlan]:
        """Plan an attack for this task."""


class BaseCategoryHandler:
    """Default handler with generic helpers."""

    name: Category

    def _pick_injection_field(
        self,
        target_field: str,
        injectable_fields: List[str],
    ) -> Optional[str]:
        if not injectable_fields:
            return None
        candidates = [f for f in injectable_fields if f != target_field]
        return candidates[0] if candidates else None

    def _pick_injection_field_for_seed(
        self,
        target_field: str,
        injectable_fields: List[str],
        data_source: Any,
    ) -> Optional[str]:
        if not injectable_fields or data_source is None:
            return None
        candidates = [f for f in injectable_fields if f != target_field]
        for field in candidates:
            if self._field_exists_in_seed(field, data_source):
                return field
        return None

    def _field_exists_in_seed(self, field_path: str, data_source: Any) -> bool:
        try:
            from ..parsers import JSONParser
            parser = JSONParser(data_source)
            if "[]" in field_path:
                # Probe the first element in the list when wildcard is present.
                probe = field_path.replace("[]", "[0]")
                value = parser.get_field(probe, default=None)
                return value is not None
            value = parser.get_field(field_path, default=None)
            return value is not None
        except Exception:
            return False

    def _resolve_injection_field_for_seed(
        self,
        target_field: str,
        injectable_fields: List[str],
        data_source: Any,
    ) -> Optional[str]:
        template = self._pick_injection_field_for_seed(
            target_field,
            injectable_fields,
            data_source,
        )
        if not template:
            return None
        resolved = resolve_injection_field(template, target_field, data_source)
        # Ensure resolved injection field differs from target field
        if resolved == target_field:
            return None
        return resolved

    def _fake_value_for_target(
        self,
        target_field: str,
        category_config: Dict[str, Any],
    ) -> str:
        field_fake_values = category_config.get("fake_values", {})
        fake_value = field_fake_values.get(target_field, "INJECTED_VALUE")
        if target_field.startswith("[") and "." in target_field:
            parts = target_field.split("]")
            generic_key = "[]" + parts[1]
            if generic_key in field_fake_values:
                fake_value = field_fake_values[generic_key]
        return str(fake_value)

    def _plan_format_breakout(
        self,
        target_field: str,
        fake_value: str,
    ) -> tuple[Any, str]:
        target_info = split_first_list_index(target_field)
        clean_target = target_info[2] if target_info and target_info[2] else target_field
        injection_content = build_nested_value(clean_target, fake_value)
        return injection_content, str(fake_value)

    def _build_syntactic_injection(
        self,
        data_source: Any,
        injection_field: str,
        target_field: str,
        fake_value: str,
        attack_type: AttackType,
        category_config: Optional[Dict[str, Any]] = None,
    ) -> Any:
        parent, _ = get_parent_and_key(data_source, injection_field)
        if parent is None:
            return build_nested_value(target_field, fake_value)

        parent_clone = copy.deepcopy(parent)

        # Apply fake values from config to all fields in the cloned parent
        # If injection_field starts with [, we're extracting from a list, so use [] prefix
        if category_config:
            prefix = "[]" if injection_field.startswith("[") else ""
            self._apply_fake_values_to_clone(parent_clone, category_config, prefix)

        relative_path = self._relative_target_path(target_field, injection_field)
        if relative_path:
            set_path_value(parent_clone, relative_path, fake_value)

        if attack_type in (AttackType.OVERRIDE_PRE, AttackType.OVERRIDE_POST):
            return self._override_payload_value(parent_clone, relative_path, fake_value)

        return parent_clone

    def _apply_fake_values_to_clone(
        self,
        data: Any,
        category_config: Dict[str, Any],
        prefix: str = "",
    ) -> None:
        """Recursively apply fake values from config to all fields in data."""
        fake_values = category_config.get("fake_values", {})

        if isinstance(data, dict):
            for key, value in list(data.items()):
                field_path = f"{prefix}.{key}" if prefix else key

                # Check if there's a fake value for this field
                if field_path in fake_values:
                    data[key] = fake_values[field_path]
                elif key in fake_values:
                    # Also check just the key name for top-level fields
                    data[key] = fake_values[key]
                elif isinstance(value, (dict, list)):
                    # Recurse into nested structures
                    self._apply_fake_values_to_clone(value, category_config, field_path)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    # For list items, use [] notation for config lookup
                    list_prefix = f"{prefix}[]" if prefix else "[]"
                    self._apply_fake_values_to_clone(item, category_config, list_prefix)

    def _relative_target_path(self, target_field: str, injection_field: str) -> str:
        target_info = split_first_list_index(target_field)
        injection_info = split_first_list_index(injection_field)
        if injection_info:
            if target_info:
                return target_info[2]
            return ""
        return target_field

    def _override_payload_value(
        self,
        parent_clone: Any,
        relative_path: str,
        fake_value: str,
    ) -> Any:
        if not relative_path:
            return fake_value
        list_info = split_first_list_index(relative_path)
        if list_info:
            target_key = list_info[0]
            remainder = list_info[2]
        else:
            parts = relative_path.split(".", 1)
            target_key = parts[0]
            remainder = parts[1] if len(parts) > 1 else ""

        if isinstance(parent_clone, dict) and target_key in parent_clone:
            if remainder:
                set_path_value(parent_clone, relative_path, fake_value)
                return parent_clone[target_key]
            return fake_value

        if remainder:
            return build_nested_value(remainder, fake_value)
        return fake_value

    def _plan_error_attack(
        self,
        target_field: str,
        fake_value: str,
        attack_config: Dict[str, Any],
        category_config: Dict[str, Any],
        targeted_output: str,
    ) -> tuple[Optional[Any], Optional[str]]:
        injection_content = attack_config["parameters"].get("message")
        semantic_attacks = category_config.get("semantic_attacks", {}).get("error_messages", [])

        for sa in semantic_attacks:
            if sa.get("type") in attack_config["parameters"].values():
                attack_target_field = sa.get("target_field")
                if attack_target_field and not self._field_matches(target_field, attack_target_field):
                    return None, None

                template = sa.get("template", "")
                # Check for explicit targeted_output in config first
                if sa.get("targeted_output"):
                    targeted_output = sa.get("targeted_output")
                else:
                    # Use the fake_value passed in
                    targeted_output = str(fake_value)

                if "{attacker_data}" in template:
                    # Format as "field: value" for more realistic cached data
                    field_name = target_field.split(".")[-1].replace("[", "").replace("]", "")
                    attacker_data = f"{field_name}: {fake_value}"
                    injection_content = template.replace("{attacker_data}", attacker_data)
                else:
                    injection_content = template

                return injection_content, targeted_output

        return injection_content, targeted_output

    def _plan_contextual_attack(
        self,
        target_field: str,
        attack_config: Dict[str, Any],
        category_config: Dict[str, Any],
        targeted_output: str,
    ) -> Optional[str]:
        injection_content = attack_config["parameters"].get("type")
        semantic_attacks = category_config.get("semantic_attacks", {}).get("contextual_deceptions", [])
        for sa in semantic_attacks:
            if sa.get("type") == injection_content:
                attack_target_field = sa.get("target_field")
                if attack_target_field and not self._field_matches(target_field, attack_target_field):
                    return None
                targeted_output = sa.get("targeted_output", targeted_output)
                break
        return targeted_output

    @staticmethod
    def _field_matches(actual_field: str, pattern_field: str) -> bool:
        """Check if actual_field matches pattern_field with wildcard support.

        Examples:
            _field_matches("[0].user.login", "[].user.login") -> True
            _field_matches("[1].body", "[].body") -> True
            _field_matches("user.login", "user.login") -> True
            _field_matches("[0].user.login", "[].body") -> False
        """
        import re
        # Replace [] with regex pattern to match [N]
        pattern = re.escape(pattern_field).replace(r"\[\]", r"\[\d+\]")
        return bool(re.fullmatch(pattern, actual_field))

    @staticmethod
    def _ordinal(n: int) -> str:
        """Convert number to ordinal (1st, 2nd, 3rd, etc.)."""
        if 10 <= n % 100 <= 20:
            suffix = "th"
        else:
            suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
        return f"{n}{suffix}"

    def _compute_insert_target(
        self,
        target_field: str,
        injection_field: str,
        attack_type: AttackType,
        structure: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Compute the shifted target_field for INSERT_COMPLETE attacks.

        For INSERT_COMPLETE, a new element is inserted, so target always shifts by +1.

        Args:
            target_field: The field path being targeted (e.g., "[1].user.login")
            injection_field: The field path for injection (e.g., "[0].body")
            attack_type: The attack type
            structure: Unused, kept for API compatibility

        Returns the shifted target_field, or None if not applicable.
        """
        if attack_type != AttackType.INSERT_COMPLETE:
            return None

        if not target_field.startswith("["):
            return None

        from ..field_utils import rebuild_indexed_path

        target_info = split_first_list_index(target_field)
        if not target_info:
            return None

        # INSERT_COMPLETE inserts a new element, so target always shifts by +1
        new_idx = target_info[1] + 1
        return rebuild_indexed_path(target_info[0], new_idx, target_info[2])

        return None
