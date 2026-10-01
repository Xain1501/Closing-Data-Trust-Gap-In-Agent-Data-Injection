"""Load seed samples from data/seeds/."""

from pathlib import Path
from typing import Dict, List, Optional

from ..bench_types import Category
from ..categories import get_category_handler


class SeedLoader:
    """Load seed samples for benchmark generation."""

    def __init__(self, seeds_dir: Path = Path("data/seeds")):
        """Initialize seed loader.

        Args:
            seeds_dir: Directory containing seed samples
        """
        self.seeds_dir = Path(seeds_dir)

    def load_seeds(
        self,
        category: Category,
        limit: Optional[int] = None,
        seed_file: Optional[str] = None,
    ) -> List[Dict[str, any]]:
        """Load seeds for a category.

        Args:
            category: Category to load
            limit: Maximum number of seeds
            seed_file: Specific seed file to load

        Returns:
            List of seed dictionaries
        """
        handler = get_category_handler(category)
        return handler.load_seeds(str(self.seeds_dir), limit=limit, seed_file=seed_file)

    def count_seeds(self, category: Category) -> int:
        """Count available seeds for a category.

        Args:
            category: Category to count

        Returns:
            Number of seeds
        """
        return len(self.load_seeds(category))
