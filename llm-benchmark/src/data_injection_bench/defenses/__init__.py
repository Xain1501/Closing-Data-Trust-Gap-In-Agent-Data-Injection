"""Defense mechanisms for data injection attacks."""

from .random_key import RandomKeyDefense, apply_random_key_defense
from .apply_defense import (
    apply_defense_to_instance,
    apply_defense_to_instances,
    generate_defended_dataset,
)

__all__ = [
    "RandomKeyDefense",
    "apply_random_key_defense",
    "apply_defense_to_instance",
    "apply_defense_to_instances",
    "generate_defended_dataset",
]
