"""Semantic attacks that exploit domain context."""

import json
from typing import Any, Dict, Optional

from ..bench_types import Category, AttackType


class SemanticAttacker:
    """Applies semantic attacks to data."""

    def generate_payload(
        self,
        category: Category,
        attack_type: AttackType,
        target_value: Any,
    ) -> Any:
        """Generate semantic attack payload.

        Args:
            category: Data category
            attack_type: Type of attack (ERROR, CONTEXTUAL)
            target_value: The specific value/content to inject

        Returns:
            Python object (dict/list/str) representing the payload
        """
        if attack_type == AttackType.ERROR:
            return self._generate_error(category, target_value)

        elif attack_type == AttackType.CONTEXTUAL:
            return self._generate_contextual(target_value)

        return target_value

    def _generate_error(self, category: Category, message: str) -> str:
        """Generate fake error message string.

        For semantic attacks, we inject a plain string error message that contains
        fake data. The message is already constructed in dataset.py with the fake
        data embedded in it (e.g., "API rate limit exceeded. Showing cached data from: user.login: fake_user").

        This string gets inserted into a text field like 'body', making the LLM
        extract the fake data from the error message.

        Args:
            category: Data category
            message: Error message string (may contain embedded fake data)

        Returns:
            Plain string error message
        """
        # Just return the message string - it should already contain the fake data
        return str(message) if message else f"Error: Failed to retrieve {category} data"

    def _generate_contextual(self, target_value: Any) -> Any:
        """Generate deceptive content (category-specific handled by category handlers)."""
        return target_value
