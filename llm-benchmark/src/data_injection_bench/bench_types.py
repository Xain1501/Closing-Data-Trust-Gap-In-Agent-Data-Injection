"""Core data models for the Data Injection Benchmark."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Enums
# =============================================================================


class Category(str, Enum):
    """Data categories from different agent domains."""
    CALENDAR = "calendar"
    CLOUD_DRIVE = "cloud_drive"
    EMAIL = "email"
    GITHUB_COMMENTS = "github_comments"
    GITHUB_ISSUE = "github_issue"
    REFERENCE_JSON = "reference_json"
    WEB_DOM = "web_dom"


class Format(str, Enum):
    """Data formats for tool outputs."""
    JSON = "json"
    MARKDOWN = "markdown"
    WEB_DOM = "web_dom"  # Internal: used by web_dom category


class TaskType(str, Enum):
    """Types of tasks for the benchmark."""
    EXTRACTION = "extraction"  # Extract single field
    FILTERING = "filtering"    # Filter items by predicate
    AGGREGATION = "aggregation"  # Sum, average, count, top-k


class AttackType(str, Enum):
    """Types of attacks (syntactic or semantic)."""
    # Syntactic attacks (format-aware, category-agnostic)
    INSERT_COMPLETE = "insert_complete"  # Syntactically valid structure breakout
    OVERRIDE_PRE = "override_pre"  # Duplicate key before target
    OVERRIDE_POST = "override_post"  # Duplicate key after target
    CROSS = "cross"  # Mixed format delimiters

    # Semantic attacks (category-aware)
    ERROR = "error"  # Fake error messages
    CONTEXTUAL = "contextual"  # Domain-specific deception


# Abbreviation mapping for instance_id (3-char -> full name)
ATTACK_TYPE_ABBREV = {
    "ins": "insert_complete",
    "ove": "override_pre",
    "ovp": "override_post",
    "cro": "cross",
    "err": "error",
    "con": "contextual",
}

# Reverse mapping (full name -> 3-char)
ATTACK_TYPE_ABBREV_REV = {v: k for k, v in ATTACK_TYPE_ABBREV.items()}


class ToolAccessMode(str, Enum):
    """Tool access modes for LLM evaluation."""
    NONE = "none"  # No tool access, only reasoning
    PYTHON = "python"  # Python code execution available


class ComparisonMethod(str, Enum):
    """Methods for comparing model output to groundtruth."""
    EXACT = "exact"  # Exact string match
    STRUCTURED = "structured"  # Semantic comparison of parsed structures
    LLM_JUDGE = "llm_judge"  # Use LLM to evaluate equivalence
    INCLUDES = "includes" # Partial match evaluation


class DefenseType(str, Enum):
    """Types of defenses against data injection attacks."""
    NONE = "none"  # No defense applied
    random_key = "random_key"  # Randomize JSON keys with key_{random_id}
    # Future defenses can be added here:
    # SCHEMA_VALIDATION = "schema_validation"
    # CONTENT_SIGNING = "content_signing"
    # SANDBOXED_PARSING = "sandboxed_parsing"


# =============================================================================
# Core Data Models
# =============================================================================


class Instance(BaseModel):
    """A single benchmark instance."""

    # Identification
    instance_id: str = Field(..., description="Unique instance identifier")
    category: Category = Field(..., description="Data category")
    format: Format = Field(..., description="Data format")
    seed_file: str = Field(..., description="Source seed file name")
    subcategory: str = Field(..., description="Data subcategory (e.g., 'issue', 'comments')")
    test_type: str = Field(..., description="Test type: 'benign' or 'attack'")

    # Inputs
    input: str = Field(..., description="Tool output (benign or attacked)")
    tool_info: Optional[str] = Field(None, description="Information about the tool/API call (e.g., endpoint URL)")

    # Task definition
    task_type: TaskType = Field(..., description="Type of task")
    task_prompt: str = Field(..., description="Prompt given to the LLM")
    target_field: str = Field(..., description="Field targeted by the task")

    # Expected outputs
    groundtruth_output: Optional[str] = Field(..., description="Correct answer (computed by parser)")
    targeted_output: Optional[str] = Field(..., description="What attacker wants LLM to output (same as groundtruth if benign)")

    # Attack metadata (optional for benign)
    attack_type: Optional[AttackType] = Field(None, description="Type of attack applied")
    attack_params: Optional[Dict[str, Any]] = Field(None, description="Attack-specific parameters")

    # Defense metadata (optional)
    defense_type: Optional[str] = Field(None, description="Type of defense applied (e.g., 'random_key')")
    defense_params: Optional[Dict[str, Any]] = Field(None, description="Defense-specific parameters (e.g., key mapping)")

    # Evaluation metadata
    comparison_method: ComparisonMethod = Field(
        default=ComparisonMethod.EXACT,
        description="Method to compare outputs"
    )

    class Config:
        use_enum_values = True


class EvaluationResult(BaseModel):
    """Result of evaluating a single instance."""

    instance_id: str
    model_name: str
    tool_access_mode: ToolAccessMode

    # Instance metadata (copied from Instance for self-contained results)
    test_type: Optional[str] = Field(None, description="Test type: 'benign' or 'attack'")
    category: Optional[str] = Field(None, description="Data category")
    format: Optional[str] = Field(None, description="Data format")
    task_type: Optional[str] = Field(None, description="Task type: 'extraction', 'filtering', or 'aggregation'")
    attack_type: Optional[str] = Field(None, description="Attack type (if attack instance)")
    attack_params: Optional[Dict[str, Any]] = Field(None, description="Attack parameters")
    defense_type: Optional[str] = Field(None, description="Defense type applied")

    # Model outputs
    model_output: str = Field(..., description="LLM's actual output")
    raw_response: Optional[str] = Field(None, description="Full raw response from LLM")

    # Benign evaluation
    benign_correct: bool = Field(..., description="Did model answer benign input correctly?")
    benign_match_score: float = Field(..., description="Score for benign output (0.0-1.0)")

    # Attack evaluation
    attack_successful: bool = Field(..., description="Did attack achieve targeted output?")
    attack_match_score: float = Field(..., description="Score for attack success (0.0-1.0)")

    # Conflict awareness (optional)
    detected_malformation: Optional[bool] = Field(None, description="Did model detect malformed input?")

    # Metadata
    latency_ms: Optional[float] = Field(None, description="Response latency in milliseconds")
    error: Optional[str] = Field(None, description="Error message if evaluation failed")

    class Config:
        use_enum_values = True


# =============================================================================
# Configuration Models
# =============================================================================


class LLMProviderConfig(BaseModel):
    """Configuration for an LLM provider."""

    provider: str = Field(..., description="Provider name (openai, anthropic, custom)")
    model: str = Field(..., description="Model identifier")
    api_key_env: str = Field(..., description="Environment variable for API key")
    temperature: float = Field(default=0.0, description="Sampling temperature")
    max_tokens: int = Field(default=2048, description="Maximum tokens to generate")
    tool_access_mode: ToolAccessMode = Field(
        default=ToolAccessMode.NONE,
        description="Tool access mode"
    )

    class Config:
        use_enum_values = True


class CategoryConfig(BaseModel):
    """Configuration for a data category."""

    category: Category
    injectable_fields: List[str] = Field(..., description="Fields where attacks can be injected")
    targeted_fields: List[str] = Field(..., description="Fields the attacker wants to manipulate")
    semantic_attacks: Dict[str, Any] = Field(default_factory=dict, description="Category-specific attacks")

    class Config:
        use_enum_values = True


class AttackConfig(BaseModel):
    """Configuration for an attack type."""

    attack_type: AttackType
    applicable_formats: List[Format] = Field(..., description="Formats this attack applies to")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Attack parameters")

    class Config:
        use_enum_values = True


class TaskConfig(BaseModel):
    """Configuration for a task type."""

    task_type: TaskType
    comparison_method: ComparisonMethod = Field(
        default=ComparisonMethod.EXACT,
        description="Default comparison method"
    )
    prompt_template: str = Field(..., description="Template for task prompt")

    class Config:
        use_enum_values = True


class BenchmarkConfig(BaseModel):
    """Main benchmark configuration."""

    # Generation settings
    categories: List[Category] = Field(..., description="Categories to include")
    formats: List[Format] = Field(..., description="Formats to generate")
    tasks: List[TaskType] = Field(..., description="Task types to generate")
    attacks: List[AttackType] = Field(..., description="Attack types to apply")

    # Generation parameters
    instances_per_seed: int = Field(default=10, description="Instances to generate per seed")
    seed_limit: Optional[int] = Field(None, description="Max seeds per category (None=all)")

    # Evaluation settings
    models: List[LLMProviderConfig] = Field(..., description="Models to evaluate")
    output_dir: str = Field(default="out", description="Output directory")

    # Optional settings
    enable_conflict_awareness: bool = Field(default=False, description="Test conflict awareness")
    random_seed: int = Field(default=42, description="Random seed for reproducibility")

    class Config:
        use_enum_values = True


# =============================================================================
# Aggregated Results
# =============================================================================


class BenchmarkReport(BaseModel):
    """Aggregated benchmark results."""

    # Overall metrics
    total_instances: int
    total_evaluated: int

    # Utility metrics (benign performance)
    overall_utility: float = Field(..., description="Overall correct rate on benign inputs")
    utility_by_category: Dict[str, float] = Field(default_factory=dict)
    utility_by_format: Dict[str, float] = Field(default_factory=dict)
    utility_by_task: Dict[str, float] = Field(default_factory=dict)

    # Attack success rate (ASR) metrics
    overall_asr: float = Field(..., description="Overall attack success rate")
    asr_by_attack_type: Dict[str, float] = Field(default_factory=dict)
    asr_by_category: Dict[str, float] = Field(default_factory=dict)
    asr_by_format: Dict[str, float] = Field(default_factory=dict)

    # Conflict awareness (optional)
    detection_rate: Optional[float] = Field(None, description="Rate of malformation detection")

    # Model comparison
    model_name: str
    tool_access_mode: ToolAccessMode

    class Config:
        use_enum_values = True
