"""Generate task instances from seeds."""

from pathlib import Path
from typing import Dict, List, Optional
import yaml

from ..bench_types import Category, Format
from ..categories import get_category_handler


class TaskGenerator:
    """Generate benchmark tasks from seeds."""

    def load_category_config(self, category: Category) -> Dict:
        """Load category configuration."""
        config_path = Path(f"configs/categories/{category.value}.yaml")
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        return {}

    def generate_tasks_for_seed(
        self,
        seed: Dict,
        category: Category,
        formats: Optional[List[Format]] = None,
    ) -> List[Dict]:
        """Generate tasks for a given seed.

        Args:
            seed: Seed data dictionary
            category: Category of the seed
            formats: Formats to generate

        Returns:
            List of task dictionaries
        """
        if formats is None:
            formats = [Format.JSON]
        handler = get_category_handler(category)
        config = self.load_category_config(category)
        return handler.generate_tasks(seed, formats, config)
