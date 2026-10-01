"""Generate benchmark dataset."""

import json
import secrets
import string
from pathlib import Path
from typing import Any, List, Optional, Dict
from datetime import datetime

from ..bench_types import Category, Format, Instance, AttackType
from ..categories import get_category_handler
from ..parsers import FormatTransformer, JSONParser
from ..defenses import RandomKeyDefense, apply_random_key_defense
from .load_seeds import SeedLoader
from .make_tasks import TaskGenerator
from .inject import Injector


def _generate_random_id(length: int = 8) -> str:
    """Generate a random ID for defense."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def _sanitize_field_for_id(field: str) -> str:
    """Sanitize field name for use in instance_id.

    Converts array indices like [0] to idx0, [1] to idx1, etc.
    """
    import re
    # Replace [N] with idxN
    return re.sub(r'\[(\d+)\]', r'idx\1', field)


def _get_web_dom_defense_info(method: str) -> tuple:
    """Get defense info for web_dom based on method.

    Args:
        method: The DOM method (id, id-pos, id-rand, id-rand-wrong, id-ref)

    Returns:
        Tuple of (defense_type, guess_key_match)
        - defense_type: "random_key" for id-rand/id-rand-wrong, None otherwise
        - guess_key_match: True for id-rand (correct), False for id-rand-wrong (wrong), None otherwise
    """
    if method == "id-rand":
        return ("random_key", True)  # correct guess
    elif method == "id-rand-wrong":
        return ("random_key", False)  # wrong guess
    else:
        return (None, None)  # no defense


class DatasetGenerator:
    """Generate benchmark dataset from seeds."""

    def __init__(self, seeds_dir: Path = Path("data/seeds")):
        """Initialize dataset generator.

        Args:
            seeds_dir: Directory containing seed samples
        """
        self.seed_loader = SeedLoader(seeds_dir)
        self.task_generator = TaskGenerator()
        self.injector = Injector()

    def load_attack_config(self) -> List[Dict]:
        """Load attack configuration."""
        import yaml
        config_path = Path("configs/attacks.yaml")
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f).get("attacks", [])
        return []

    def load_category_config(self, category: Category) -> Dict:
        """Load category configuration."""
        import yaml
        config_path = Path(f"configs/categories/{category.value}.yaml")
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        return {}

    def generate_instances(
        self,
        category: Category,
        formats: List[Format],
        seed_limit: Optional[int] = None,
        seed_file: Optional[str] = None,
        apply_attacks: bool = True,
        defense_type: Optional[str] = "random_key",
        defense_params: Optional[Dict[str, Any]] = None,
        attack_types: Optional[List[str]] = None,
        subcategories: Optional[List[str]] = None,
    ) -> List[Instance]:
        """Generate instances (benign and attacked).

        Args:
            category: Data category to generate
            formats: Output formats to generate
            seed_limit: Maximum seeds to use
            seed_file: Specific seed file to use
            apply_attacks: Whether to generate attack instances
            defense_type: Defense to apply ("random_key" or None for no defense)
            defense_params: Defense-specific parameters
            attack_types: List of attack types to include (None = all attacks)
            subcategories: List of subcategories to include (None = all subcategories)
        """
        print(f"Loading seeds for {category}...")
        seeds = self.seed_loader.load_seeds(category, limit=seed_limit, seed_file=seed_file)
        print(f"Loaded {len(seeds)} seeds")

        attacks = self.load_attack_config() if apply_attacks else []

        # Filter attacks by type if specified
        if attack_types and attacks:
            attacks = [a for a in attacks if a.get("attack_type") in attack_types]

        print(f"Loaded {len(attacks)} attack configurations")

        if defense_type:
            print(f"Defense enabled: {defense_type}")

        category_config = self.load_category_config(category)
        handler = get_category_handler(category)

        # Generate a single random_id for this entire generation run
        # This ensures consistency across all instances
        generation_random_id = None
        generation_wrong_id = None  # For guess_key_match=false attacks
        if defense_type == "random_key":
            params = defense_params or {}
            random_id_length = params.get("random_id_length", 8)
            generation_random_id = _generate_random_id(random_id_length)
            # Pre-generate a wrong ID for incorrect guess_key attacks
            generation_wrong_id = _generate_random_id(random_id_length)
            while generation_wrong_id == generation_random_id:
                generation_wrong_id = _generate_random_id(random_id_length)
            print(f"Generated random_id for this run: {generation_random_id}")
        
        instances = []
        for seed_idx, seed in enumerate(seeds):
            print(f"  Processing seed {seed['seed_id']}...")
            tasks = self.task_generator.generate_tasks_for_seed(
                seed=seed,
                category=category,
                formats=formats,
            )

            # Filter by subcategory if specified
            if subcategories:
                original_count = len(tasks)
                tasks = [t for t in tasks if t.get("subcategory", "issue") in subcategories]
                if len(tasks) < original_count:
                    print(f"    Generated {len(tasks)} tasks (filtered from {original_count} by subcategory)")
                else:
                    print(f"    Generated {len(tasks)} tasks")
            else:
                print(f"    Generated {len(tasks)} tasks")

            for i, task_dict in enumerate(tasks):
                # Use metadata from task
                target_field = task_dict["field"]
                seed_file = task_dict.get("seed_file", str(seed.get("filename", "")))
                subcategory = task_dict.get("subcategory", "issue")
                format_type = task_dict["format"]

                # Skip tasks where requested defense won't actually apply
                # This prevents duplicate instances when running both defended/undefended passes
                if defense_type == "random_key":
                    if category == Category.WEB_DOM:
                        # For web_dom, defense is determined by method (id-rand/id-rand-wrong),
                        # not by the defense_type parameter. So skip ALL web_dom in defended pass
                        # to avoid duplicates (they're already generated in undefended pass).
                        continue
                    elif format_type != Format.JSON:
                        # For other categories, defense only applies to JSON format
                        continue

                def _transform_input(raw_data: str, strip_placeholders: bool = False) -> str:
                    if format_type == Format.JSON:
                        return raw_data
                    # Handle WEB_DOM format - no JSON transformation needed
                    if format_type == Format.WEB_DOM:
                        result = raw_data
                        # Remove placeholders for benign instances (e.g., {{fake_button}})
                        if strip_placeholders:
                            import re
                            result = re.sub(r'\{\{[^}]+\}\}', '', result)
                        return result
                    # Try to parse as JSON; if it fails, assume it's already text
                    try:
                        parsed = json.loads(raw_data)
                    except (json.JSONDecodeError, TypeError):
                        # Data is not JSON - return as-is
                        return raw_data
                    if format_type == Format.MARKDOWN:
                        return FormatTransformer.json_to_markdown(
                            parsed,
                            category_config=category_config,
                            subcategory=subcategory,
                        )
                    return raw_data

                # 1. Create Benign Instance
                # Format: s{seed_idx}_t{task_idx}_{field}_benign[_def]
                field_id = _sanitize_field_for_id(task_dict['field'])
                base_benign_id = f"s{seed_idx:03d}_t{i}_{field_id}_benign"

                original_input = _transform_input(task_dict["data"], strip_placeholders=True)
                original_prompt = task_dict["prompt"]

                # Apply defense if enabled and format is JSON
                defended_input = original_input
                defended_prompt = original_prompt
                defense_info = None

                # Determine effective defense_type
                # For web_dom, defense is determined by method (id-rand/id-rand-wrong)
                effective_defense_type = None
                web_dom_guess_key_match = None

                if category == Category.WEB_DOM:
                    method = task_dict.get("method", "")
                    effective_defense_type, web_dom_guess_key_match = _get_web_dom_defense_info(method)
                elif defense_type == "random_key" and format_type == Format.JSON:
                    effective_defense_type = defense_type
                    params = defense_params or {}
                    random_id_length = params.get("random_id_length", 8)

                    defended_input, defended_prompt, defense_info = apply_random_key_defense(
                        input_data=original_input,
                        task_prompt=original_prompt,
                        random_id_length=random_id_length,
                        random_id=generation_random_id,  # Use consistent random_id
                    )

                # Add defense suffix to instance_id if defense is applied
                benign_id = base_benign_id
                if effective_defense_type:
                    benign_id = f"{base_benign_id}_{effective_defense_type}"

                benign_instance = Instance(
                    instance_id=benign_id,
                    category=task_dict["category"],
                    format=format_type,
                    seed_file=seed_file,
                    subcategory=subcategory,
                    test_type="benign",
                    input=defended_input,
                    task_type=task_dict["task_type"],
                    task_prompt=defended_prompt,
                    target_field=task_dict["field"],
                    groundtruth_output=task_dict["groundtruth"],
                    targeted_output=task_dict["groundtruth"],
                    comparison_method=task_dict["comparison_method"],
                    tool_info=task_dict.get("tool_info"),
                    defense_type=effective_defense_type,
                    defense_params=defense_info if defense_info else None,
                )
                instances.append(benign_instance)

                # 2. Create Attacked Instances (skip if benign_only task)
                if apply_attacks and not task_dict.get("benign_only", False):
                    for j, attack_config in enumerate(attacks):
                        task_format_value = task_dict["format"].value
                        applicable_formats = attack_config.get("applicable_formats", [])
                        if task_format_value not in applicable_formats:
                            continue
                        params = attack_config.get("parameters", {})
                        variants = self._expand_param_variants(params)
                        
                        for variant_idx, attack_params in enumerate(variants):
                            # Include target key for override attacks
                            attack_params = dict(attack_params)

                            # Skip guess_key attacks when defense is not random_key
                            if attack_params.get("guess_key_match") is not None:
                                if defense_type != "random_key" or format_type != Format.JSON:
                                    continue

                            if attack_config["attack_type"] in ["override_pre", "override_post"]:
                                tf = self._override_target_field(task_dict["field"])
                                # Use the first segment as the duplicated key.
                                attack_params["target_key"] = tf.split(".")[0] if "." in tf else tf

                            attack_plan = handler.plan_attack(
                                seed=seed,
                                task_dict=task_dict,
                                attack_config=attack_config,
                                category_config=category_config,
                            )
                            if not attack_plan:
                                continue
                            try:
                                # target = injection_idx + 1, same for all formats
                                attack_target_field = task_dict["field"]
                                attack_groundtruth = task_dict["groundtruth"]
                                attack_task_prompt = task_dict["prompt"]

                                if attack_plan.attack_type in [
                                    AttackType.OVERRIDE_PRE,
                                    AttackType.OVERRIDE_POST,
                                ] and not self._is_effective_override(
                                    attack_plan.data_source,
                                    attack_target_field,
                                    attack_plan.attack_type,
                                ):
                                    continue

                                # For guess_key attacks, use the generation-wide random_id
                                guess_key_match = attack_params.get("guess_key_match")
                                if guess_key_match is not None and defense_type == "random_key" and format_type == Format.JSON:
                                    attack_params = dict(attack_params)

                                    if guess_key_match:
                                        # Correct guess: use the generation-wide random_id
                                        attack_params["guess_key"] = generation_random_id
                                    else:
                                        # Incorrect guess: use the generation-wide wrong_id
                                        attack_params["guess_key"] = generation_wrong_id

                                # Pass insert_before for markdown INSERT_COMPLETE
                                if attack_plan.insert_before:
                                    attack_params = dict(attack_params)
                                    attack_params["insert_before"] = True

                                malicious_input = self.injector.inject(
                                    data=attack_plan.data_source,
                                    category=category,
                                    format=format_type,
                                    attack_type=attack_plan.attack_type,
                                    injection_field=attack_plan.injection_field,
                                    injection_content=attack_plan.injection_content,
                                    attack_params=attack_params,
                                )

                                if format_type not in (Format.JSON, Format.WEB_DOM):
                                    try:
                                        malicious_parsed = json.loads(malicious_input)
                                        # Successfully parsed as JSON, transform it
                                        if format_type == Format.MARKDOWN:
                                            malicious_input = FormatTransformer.json_to_markdown(
                                                malicious_parsed,
                                                category_config=category_config,
                                                subcategory=subcategory,
                                            )
                                    except (json.JSONDecodeError, TypeError):
                                        # Data is not JSON - keep malicious_input as-is
                                        pass

                                # Build instance_id with shortened format
                                # Format: s{seed_idx}_t{task_idx}_{field}_{attack_type}_v{variant}[_gk{0/1}][_def]
                                attack_type_short = attack_config['attack_type'][:3]  # First 3 chars
                                attack_field_id = _sanitize_field_for_id(attack_target_field)
                                base_attack_id = f"s{seed_idx:03d}_t{i}_{attack_field_id}_{attack_type_short}_v{variant_idx}"

                                # Determine effective defense_type for attack instance
                                # For web_dom, defense is determined by method (id-rand/id-rand-wrong)
                                attack_effective_defense_type = None
                                attack_guess_key_match = None

                                if category == Category.WEB_DOM:
                                    method = task_dict.get("method", "")
                                    attack_effective_defense_type, attack_guess_key_match = _get_web_dom_defense_info(method)
                                    # Add guess_key_match to attack_params for web_dom
                                    if attack_guess_key_match is not None:
                                        attack_params = dict(attack_params)
                                        attack_params["guess_key_match"] = attack_guess_key_match

                                # Add guess_key suffix if applicable
                                if attack_params.get("guess_key_match") is not None:
                                    gk_suffix = "1" if attack_params.get("guess_key_match") else "0"
                                    base_attack_id = f"{base_attack_id}_gk{gk_suffix}"

                                # Apply defense to attack instance if enabled
                                attack_original_input = malicious_input
                                attack_original_prompt = attack_task_prompt
                                attack_defended_input = malicious_input
                                attack_defended_prompt = attack_task_prompt
                                attack_defense_info = None

                                if defense_type == "random_key" and format_type == Format.JSON:
                                    attack_effective_defense_type = defense_type
                                    params = defense_params or {}
                                    random_id_length = params.get("random_id_length", 8)

                                    # Use generation-wide random_id for consistency
                                    attack_defended_input, attack_defended_prompt, attack_defense_info = apply_random_key_defense(
                                        input_data=malicious_input,
                                        task_prompt=attack_task_prompt,
                                        random_id_length=random_id_length,
                                        random_id=generation_random_id,  # Use consistent random_id
                                    )

                                # Add defense suffix to instance_id if defense is applied
                                attack_id = base_attack_id
                                if attack_effective_defense_type:
                                    attack_id = f"{base_attack_id}_{attack_effective_defense_type}"

                                attack_instance = Instance(
                                    instance_id=attack_id,
                                    category=task_dict["category"],
                                    format=format_type,
                                    seed_file=seed_file,
                                    subcategory=subcategory,
                                    test_type="attack",
                                    input=attack_defended_input,
                                    task_type=task_dict["task_type"],
                                    task_prompt=attack_defended_prompt,
                                    target_field=attack_target_field,
                                    groundtruth_output=attack_groundtruth,
                                    targeted_output=attack_plan.targeted_output,
                                    attack_type=attack_plan.attack_type,
                                    attack_params={**attack_params, "injection_field": attack_plan.injection_field},
                                    comparison_method=task_dict["comparison_method"],
                                    tool_info=task_dict.get("tool_info"),
                                    defense_type=attack_effective_defense_type,
                                    defense_params=attack_defense_info if attack_defense_info else None,
                                )
                                instances.append(attack_instance)
                            except Exception:
                                pass

        return instances

    def _is_effective_override(
        self,
        data_source: Any,
        target_field: str,
        attack_type: AttackType,
    ) -> bool:
        if attack_type not in (AttackType.OVERRIDE_PRE, AttackType.OVERRIDE_POST):
            return True
        try:
            parser = JSONParser(data_source)
            parts = parser._parse_path(target_field)
            parent = data_source
            for part in parts[:-1]:
                if isinstance(parent, list):
                    if not isinstance(part, int):
                        return False
                    parent = parent[part]
                elif isinstance(parent, dict):
                    parent = parent.get(part)
                else:
                    return False
                if parent is None:
                    return False

            if not isinstance(parent, dict) or not parts:
                return False

            key = parts[-1]
            if isinstance(key, int) or key not in parent:
                return False

            keys = list(parent.keys())
            idx = keys.index(key)
            effective = AttackType.OVERRIDE_PRE if idx < len(keys) - 1 else AttackType.OVERRIDE_POST
            return effective == attack_type
        except Exception:
            return False

    def _expand_param_variants(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Expand list parameters into individual variant dictionaries.

        For example:
            {"quote_style": ["double", "single"], "foo": "bar"}
        becomes:
            [{"quote_style": "double", "foo": "bar"}, {"quote_style": "single", "foo": "bar"}]

        Handles multiple list parameters by creating cartesian product.
        """
        if not isinstance(params, dict):
            return [params]

        # Find all list parameters
        list_params = {
            k: v for k, v in params.items()
            if isinstance(v, list)
        }

        if not list_params:
            return [params]

        # Start with base params (non-list values)
        base = {k: v for k, v in params.items() if k not in list_params}
        variants = [base]

        # Expand each list parameter
        for param_name, values in list_params.items():
            new_variants = []
            for variant in variants:
                for value in values:
                    new_variant = dict(variant)
                    new_variant[param_name] = value
                    new_variants.append(new_variant)
            variants = new_variants

        return variants if variants else [params]

    def _override_target_field(self, target_field: str) -> str:
        if target_field.startswith("[") and "]." in target_field:
            return target_field.split("].", 1)[1]
        first_segment = target_field.split(".")[0]
        if "[" in first_segment and "]" in first_segment:
            first_segment = first_segment.split("[", 1)[0]
            return first_segment
        return target_field

    def save_instances(
        self,
        instances: List[Instance],
        output_file: Path,
    ):
        """Save instances to JSON file.

        Args:
            instances: List of Instance objects
            output_file: Output file path
        """
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            # Save as a pretty-printed JSON array
            instances_data = [inst.model_dump() for inst in instances]
            json.dump(instances_data, f, indent=2, ensure_ascii=False)

        print(f"\nSaved {len(instances)} instances to {output_file}")

    def load_instances(self, input_file: Path) -> List[Instance]:
        """Load instances from JSON file.

        Args:
            input_file: Input file path

        Returns:
            List of Instance objects
        """
        with open(input_file, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [Instance(**inst) for inst in data]
            else:
                # Handle single object if needed
                return [Instance(**data)]

    def generate_and_save(
        self,
        category: Category,
        formats: List[Format],
        output_file: Path,
        seed_limit: Optional[int] = None,
        seed_file: Optional[str] = None,
        defense_type: Optional[str] = "random_key",
        defense_params: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Generate dataset and save to file.

        Args:
            category: Category to generate
            formats: Formats to generate
            output_file: Output file path
            seed_limit: Maximum seeds to use
            seed_file: Specific seed file to use
            defense_type: Defense to apply ("random_key" or None)
            defense_params: Defense-specific parameters

        Returns:
            Number of instances generated
        """
        print("=" * 70)
        print(f"Generating dataset: {category}")
        if seed_file:
            print(f"Seed file: {seed_file}")
        print(f"Formats: {[f.value for f in formats]}")
        if defense_type:
            print(f"Defense: {defense_type}")
        print(f"Output: {output_file}")
        print("=" * 70)

        instances = self.generate_instances(
            category=category,
            formats=formats,
            seed_limit=seed_limit,
            seed_file=seed_file,
            apply_attacks=True,
            defense_type=defense_type,
            defense_params=defense_params,
        )

        self.save_instances(instances, output_file)

        # Print statistics
        print("\n" + "=" * 70)
        print("Dataset Statistics")
        print("=" * 70)
        print(f"Total instances: {len(instances)}")
        print(f"Seeds used: {len(set(inst.seed_file for inst in instances))}")

        # Count by task type
        task_type_counts = {}
        for inst in instances:
            task_type_counts[inst.task_type] = task_type_counts.get(inst.task_type, 0) + 1

        print("\nBy task type:")
        for task_type, count in sorted(task_type_counts.items()):
            print(f"  {task_type}: {count}")

        # Count by format
        format_counts = {}
        for inst in instances:
            format_counts[inst.format] = format_counts.get(inst.format, 0) + 1

        print("\nBy format:")
        for fmt, count in sorted(format_counts.items()):
            print(f"  {fmt}: {count}")

        print("=" * 70)

        return len(instances)
