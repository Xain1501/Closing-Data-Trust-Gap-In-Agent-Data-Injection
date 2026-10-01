"""Injection logic for creating malicious instances."""

import json
from typing import Any, Dict, List, Optional

from ..bench_types import Category, Format, AttackType
from ..attacks.syntactic import SyntacticAttacker
from ..attacks.semantic import SemanticAttacker
from ..parsers import JSONParser


class Injector:
    """Injects attacks into data."""

    def __init__(self):
        """Initialize injector."""
        self.syntactic_attacker = SyntacticAttacker()
        self.semantic_attacker = SemanticAttacker()

    def inject(
        self,
        data: Any,
        category: Category,
        format: Format,
        attack_type: AttackType,
        injection_field: Optional[str] = None,
        injection_content: Any = None,
        attack_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Apply attack to data.

        Args:
            data: Original data (seed dict or list)
            category: Data category
            format: Data format
            attack_type: Type of attack
            injection_field: Field to inject into (if applicable)
            injection_content: Content to inject (optional)

        Returns:
            Malicious data string (formatted)
        """
        import copy

        # Handle text-based injection for WEB_DOM category
        if category == Category.WEB_DOM:
            return self._inject_text_placeholder(
                data=data,
                injection_field=injection_field,
                injection_content=injection_content,
            )

        malicious_data = copy.deepcopy(data)
        attack_params = attack_params or {}

        # Branch syntactic handling by target format.
        if attack_type in [
            AttackType.INSERT_COMPLETE,
            AttackType.OVERRIDE_PRE,
            AttackType.OVERRIDE_POST,
            AttackType.CROSS,
        ]:
            if format == Format.MARKDOWN:
                return self._inject_syntactic_markdown(
                    data=malicious_data,
                    injection_field=injection_field,
                    injection_content=injection_content,
                    attack_type=attack_type,
                    attack_params=attack_params,
                )
            # Default to JSON-style breakout payloads
            return self._inject_syntactic_json(
                data=malicious_data,
                injection_field=injection_field,
                injection_content=injection_content,
                attack_type=attack_type,
                format=format,
                attack_params=attack_params,
            )

        # Handle semantic attacks
        else:
            # 1. Generate payload
            payload = self._generate_payload(
                category=category,
                attack_type=attack_type,
                target_value=injection_content,
                format=format
            )

            # 2. Insert payload into data structure
            if injection_field:
                self._insert_payload(malicious_data, injection_field, payload)

            # 3. Serialize
        return json.dumps(malicious_data)

    def _inject_text_placeholder(
        self,
        data: Any,
        injection_field: Optional[str],
        injection_content: Any,
    ) -> str:
        """Inject content into text data by replacing placeholder.

        For WEB_DOM and other text-based categories, replaces {{placeholder}}
        with the injection content.

        Args:
            data: Original text data (string)
            injection_field: Placeholder name (e.g., "fake_button" for {{fake_button}})
            injection_content: Content to inject

        Returns:
            Text with placeholder replaced by injection content
        """
        if not isinstance(data, str):
            data = str(data)

        if injection_field and injection_content:
            placeholder = "{{" + injection_field + "}}"
            return data.replace(placeholder, str(injection_content))

        return data

    def _inject_syntactic_markdown(
        self,
        data: Any,
        injection_field: Optional[str],
        injection_content: Any,
        attack_type: AttackType,
        attack_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Insert syntactic payloads for markdown by structural insertion.
        Markdown uses rendered templates, so we add the injected object/field
        directly into the JSON structure so it surfaces in the markdown.
        """
        attack_params = attack_params or {}
        if injection_field:
            # Handle comment-list style injection like "[0].body" by inserting a new element.
            if isinstance(data, list) and injection_field.startswith("[") and injection_content is not None:
                try:
                    idx_str = injection_field.split("]", 1)[0].strip("[")
                    idx = int(idx_str) if idx_str else 0
                except ValueError:
                    idx = 0
                # insert_before=True: insert at idx (fake becomes [idx], original shifts down)
                # insert_before=False: insert at idx+1 (fake becomes [idx+1])
                if attack_params.get("insert_before"):
                    insert_at = idx
                else:
                    insert_at = min(len(data), idx + 1)
                data.insert(insert_at, injection_content)
            else:
                self._insert_payload(data, injection_field, injection_content)
        return json.dumps(data)

    def _inject_syntactic_json(
        self,
        data: Any,
        injection_field: Optional[str],
        injection_content: Any,
        attack_type: AttackType,
        format: Format,
        attack_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Inject syntactic attack as a string value (simulating attempted breakout)."""
        context = {}
        if injection_field:
            try:
                parser = JSONParser(data)
                original_value = parser.get_field(injection_field)
                if isinstance(original_value, str) and original_value:
                    context["prefix"] = original_value
            except Exception:
                pass

            try:
                parser = JSONParser(data)
                parts = parser._parse_path(injection_field)
                parent = data
                for part in parts[:-1]:
                    if isinstance(part, int):
                        parent = parent[part]
                    else:
                        parent = parent.get(part)
                target_key = parts[-1] if parts else None
                if isinstance(parent, dict) and isinstance(target_key, str):
                    context["target_key"] = target_key
                    context["dummy_value"] = original_value

                    prefix_parts = []
                    suffix_parts = []
                    found_key = False
                    for key, value in parent.items():
                        if key == target_key:
                            found_key = True
                            continue
                        merged_value = value
                        if isinstance(injection_content, dict) and key in injection_content:
                            merged_value = injection_content[key]
                        entry = f"\"{key}\": {json.dumps(merged_value, ensure_ascii=False)}"
                        if found_key:
                            suffix_parts.append(entry)
                        else:
                            prefix_parts.append(entry)

                    opening = ", ".join(prefix_parts)
                    if opening:
                        opening = f"{opening}, \"{target_key}\": \""
                    else:
                        opening = f"\"{target_key}\": \""
                    context["opening"] = opening

                    if suffix_parts:
                        context["suffix"] = ", ".join(suffix_parts)

                    if isinstance(injection_content, dict) and target_key in injection_content:
                        context["injection_body"] = injection_content.get(target_key)
            except Exception:
                pass

        # print(f"opening: {context.get('opening')}")
        # print(f"suffix: {context.get('suffix')}")

        # Apply guess_key transformation AFTER context building but BEFORE payload generation
        # This ensures context uses original keys, but payload has transformed keys
        attack_params = attack_params or {}
        if attack_params.get("guess_key") and isinstance(injection_content, dict):
            injection_content = self.syntactic_attacker.apply_guess_key_transform(
                injection_content, attack_params
            )
            # Also transform injection_body in context if it exists
            if context.get("injection_body") and isinstance(context["injection_body"], dict):
                context["injection_body"] = self.syntactic_attacker.apply_guess_key_transform(
                    context["injection_body"], attack_params
                )

        # 1. Generate raw payload string (which looks like a breakout)
        payload = self.syntactic_attacker.generate_payload(
            content=injection_content,
            attack_type=attack_type,
            format=format,
            context=context,
            attack_params=attack_params,
        )
        
        # 2. Insert payload into the structure as a standard string value
        # This ensures json.dumps escapes it, so it remains inside the string
        # and does NOT cause an actual format breakout.
        if injection_field:
            self._insert_payload(data, injection_field, payload)
        
        # 3. Serialize to JSON
        return json.dumps(data)

    def _generate_payload(
        self,
        category: Category,
        attack_type: AttackType,
        target_value: Any,
        format: Format,
        attack_params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Generate appropriate payload."""
        
        if attack_type in [
            AttackType.INSERT_COMPLETE,
            AttackType.OVERRIDE_PRE,
            AttackType.OVERRIDE_POST,
            AttackType.CROSS,
        ]:
            return self.syntactic_attacker.generate_payload(
                content=target_value or "INJECTED",
                attack_type=attack_type,
                format=format,
                attack_params=attack_params or {},
            )
        
        elif attack_type in [AttackType.ERROR, AttackType.CONTEXTUAL]:
            return self.semantic_attacker.generate_payload(
                category=category,
                attack_type=attack_type,
                target_value=target_value
            )
            
        return target_value

    def _insert_payload(self, data: Any, field_path: str, payload: Any):
        """Insert payload into nested dictionary using dot notation."""
        parts = field_path.split('.')
        current = data
        
        for i, part in enumerate(parts[:-1]):
            if isinstance(current, dict):
                current = current.get(part, {})
            elif isinstance(current, list):
                # Handle array indexing [0]
                if part.startswith('[') and part.endswith(']'):
                    try:
                        idx = int(part[1:-1])
                        current = current[idx]
                    except (ValueError, IndexError):
                        return
            else:
                return

        last_part = parts[-1]
        if isinstance(current, dict):
            current[last_part] = payload
        elif isinstance(current, list) and last_part.startswith('[') and last_part.endswith(']'):
             try:
                idx = int(last_part[1:-1])
                current[idx] = payload
             except (ValueError, IndexError):
                pass
