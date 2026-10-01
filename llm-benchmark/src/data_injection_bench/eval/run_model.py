"""LLM provider implementations for evaluation."""

import os
import random
import time
from typing import Callable, Optional

from ..bench_types import Instance, EvaluationResult, ToolAccessMode, TaskType
from .transform import transform_model_output


def retry_with_backoff(
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
):
    """Decorator for retrying API calls with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential backoff
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    error_str = str(e).lower()
                    error_type = type(e).__name__

                    # Check if this is a rate limit or overload error
                    is_rate_limit = (
                        "rate" in error_str
                        or "limit" in error_str
                        or "quota" in error_str
                        or "overloaded" in error_str
                        or "resource_exhausted" in error_str
                        or "429" in error_str
                        or "529" in error_str
                        or "RateLimitError" in error_type
                        or "ResourceExhausted" in error_type
                        or "APIStatusError" in error_type and "529" in error_str
                    )

                    # Terminate immediately on rate limit errors (no backoff)
                    if is_rate_limit:
                        raise

                    if attempt == max_retries:
                        raise

                    # Calculate delay with jitter for non-rate-limit errors
                    delay = min(
                        base_delay * (exponential_base ** attempt),
                        max_delay
                    )
                    # Add jitter (±25%)
                    delay = delay * (0.75 + random.random() * 0.5)

                    print(f"  Retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})...")
                    time.sleep(delay)

            raise last_exception
        return wrapper
    return decorator


class LLMProvider:
    """Base class for LLM providers."""

    def __init__(
        self,
        model_name: str,
        api_key: Optional[str] = None,
        temperature: Optional[float] = 0.0,
        max_tokens: Optional[int] = 2048,
    ):
        """Initialize provider.

        Args:
            model_name: Model identifier
            api_key: API key (if None, reads from environment)
            temperature: Sampling temperature (None to omit)
            max_tokens: Maximum tokens to generate (None to omit)
        """
        self.model_name = model_name
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens

    def run_instance(
        self,
        prompt: str,
    ) -> str:
        """Run model on a prompt.

        Args:
            prompt: Input prompt string

        Returns:
            Model output string
        """
        raise NotImplementedError


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(
        self,
        model_name: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = 2048,
    ):
        """Initialize OpenAI provider.

        Args:
            model_name: OpenAI model name
            api_key: OpenAI API key (reads from OPENAI_API_KEY if None)
            temperature: Sampling temperature (None to omit)
            max_tokens: Maximum completion tokens (None to omit limit)
        """
        super().__init__(model_name, api_key, temperature, max_tokens)

        if self.api_key is None:
            self.api_key = os.getenv("OPENAI_API_KEY")

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not provided. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter."
            )

        # Import openai only when needed
        try:
            import openai
            self.client = openai.OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "OpenAI package not installed. Install with: pip install openai"
            )

    @retry_with_backoff()
    def run_instance(
        self,
        prompt: str,
    ) -> str:
        """Run OpenAI model on a prompt.

        Args:
            prompt: Input prompt string

        Returns:
            Tuple of (model_output, latency_ms)
        """
        # Call OpenAI API
        start_time = time.time()

        kwargs = dict(
            model=self.model_name,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        # Prefer the new parameter name if a limit is provided
        if self.max_tokens is not None:
            kwargs["max_completion_tokens"] = self.max_tokens

        response = self.client.chat.completions.create(**kwargs)

        latency_ms = (time.time() - start_time) * 1000
        output = response.choices[0].message.content

        return output, latency_ms


class AnthropicProvider(LLMProvider):
    """Anthropic API provider."""

    def __init__(
        self,
        model_name: str = "claude-sonnet-4-20250514",
        api_key: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = 2048,
    ):
        """Initialize Anthropic provider.

        Args:
            model_name: Anthropic model name (e.g., claude-sonnet-4-20250514, claude-3-5-sonnet-20241022)
            api_key: Anthropic API key (reads from ANTHROPIC_API_KEY if None)
            temperature: Sampling temperature (None to omit)
            max_tokens: Maximum tokens to generate
        """
        super().__init__(model_name, api_key, temperature, max_tokens)

        if self.api_key is None:
            self.api_key = os.getenv("ANTHROPIC_API_KEY")

        if not self.api_key:
            raise ValueError(
                "Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

        # Import anthropic only when needed
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "Anthropic package not installed. Install with: pip install anthropic"
            )

    @retry_with_backoff()
    def run_instance(
        self,
        prompt: str,
    ) -> str:
        """Run Anthropic model on a prompt.

        Args:
            prompt: Input prompt string

        Returns:
            Tuple of (model_output, latency_ms)
        """
        start_time = time.time()

        kwargs = dict(
            model=self.model_name,
            max_tokens=self.max_tokens or 2048,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature

        response = self.client.messages.create(**kwargs)

        latency_ms = (time.time() - start_time) * 1000
        output = response.content[0].text

        return output, latency_ms


class GoogleProvider(LLMProvider):
    """Google Gemini API provider."""

    def __init__(
        self,
        model_name: str = "gemini-2.0-flash",
        api_key: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = 2048,
    ):
        """Initialize Google Gemini provider.

        Args:
            model_name: Google model name (e.g., gemini-2.0-flash, gemini-1.5-pro)
            api_key: Google API key (reads from GOOGLE_API_KEY if None)
            temperature: Sampling temperature (None to omit)
            max_tokens: Maximum tokens to generate
        """
        super().__init__(model_name, api_key, temperature, max_tokens)

        if self.api_key is None:
            self.api_key = os.getenv("GOOGLE_API_KEY")

        if not self.api_key:
            raise ValueError(
                "Google API key not provided. Set GOOGLE_API_KEY environment variable "
                "or pass api_key parameter."
            )

        # Import google-genai only when needed
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "Google GenAI package not installed. Install with: pip install google-genai"
            )

    @retry_with_backoff()
    def run_instance(
        self,
        prompt: str,
    ) -> str:
        """Run Google Gemini model on a prompt.

        Args:
            prompt: Input prompt string

        Returns:
            Tuple of (model_output, latency_ms)
        """
        from google.genai import types

        start_time = time.time()

        # Build generation config
        config_kwargs = {}
        if self.temperature is not None:
            config_kwargs["temperature"] = self.temperature
        if self.max_tokens is not None:
            config_kwargs["max_output_tokens"] = self.max_tokens

        config = types.GenerateContentConfig(**config_kwargs) if config_kwargs else None

        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=config,
        )

        latency_ms = (time.time() - start_time) * 1000
        output = response.text

        return output, latency_ms


class ModelRunner:
    """Run models on benchmark instances."""

    def __init__(self, provider: LLMProvider, tool_access_mode: ToolAccessMode = ToolAccessMode.NONE):
        """Initialize model runner.

        Args:
            provider: LLM provider to use
            tool_access_mode: Tool access mode (NONE or PYTHON)
        """
        self.provider = provider
        self.tool_access_mode = tool_access_mode

        if tool_access_mode == ToolAccessMode.PYTHON:
            raise NotImplementedError("Python tool access mode not yet implemented")

    def _get_tool_info(self, instance: Instance) -> str:
        """Get tool info string."""
        if instance.tool_info:
            return instance.tool_info

        category_map = {
            "github_issue": "github.get_issue_details(issue_id='...')",
            "calendar": "calendar.list_events(time_min='...', time_max='...')",
            "email": "email.list_messages(query='...')",
            "slack": "slack.conversations_history(channel='...')",
            "cloud_drive": "drive.files_list(q='...')",
            "web_search": "search.web_search(query='...')",
            "web_html": "browser.get_content(url='...')",
        }
        return category_map.get(instance.category, f"{instance.category}_tool")

    def run_instance(
        self,
        instance: Instance,
        verbose: bool = False,
    ) -> EvaluationResult:
        """Run model on instance and create evaluation result.

        Args:
            instance: Instance to evaluate

        Returns:
            EvaluationResult object
        """
        try:
            # Construct prompt
            tool_info = self._get_tool_info(instance)
            
            # Use data as provided in the instance
            input_data = instance.input

            prompt = f"""{tool_info}
Result:
{input_data}

Task:
{instance.task_prompt}"""

            if verbose:
                print(f"Task:\n{instance.task_prompt}")

            raw_output, latency_ms = self.provider.run_instance(prompt)

            if verbose:
                print(f"\nRaw Output:\n{raw_output}\n")

            # Transform output to extract value from verbose responses unless this is an aggregation/summary task
            if instance.task_type == TaskType.AGGREGATION or instance.target_field == "summary":
                transformed_output = raw_output
            else:
                transformed_output = transform_model_output(
                    raw_output,
                    extract_value=True,
                    normalize=True,
                    groundtruth=instance.groundtruth_output,
                )

            if verbose and transformed_output != raw_output:
                print(f"Transformed Output:\n{transformed_output}\n")

            # Scoring will be done separately
            return EvaluationResult(
                instance_id=instance.instance_id,
                model_name=self.provider.model_name,
                tool_access_mode=self.tool_access_mode,
                test_type=instance.test_type,
                category=instance.category,
                format=instance.format,
                task_type=instance.task_type,
                attack_type=instance.attack_type,
                attack_params=instance.attack_params,
                defense_type=instance.defense_type,
                model_output=transformed_output,
                raw_response=raw_output,
                # Placeholders - will be filled by scorer
                benign_correct=False,
                benign_match_score=0.0,
                attack_successful=False,
                attack_match_score=0.0,
                latency_ms=latency_ms,
                error=None,
            )

        except Exception as e:
            # Re-raise rate limit errors to terminate the run
            error_str = str(e).lower()
            error_type = type(e).__name__
            is_rate_limit = (
                "rate" in error_str
                or "limit" in error_str
                or "quota" in error_str
                or "resource_exhausted" in error_str
                or "429" in error_str
                or "RateLimitError" in error_type
                or "ResourceExhausted" in error_type
            )
            if is_rate_limit:
                raise

            return EvaluationResult(
                instance_id=instance.instance_id,
                model_name=self.provider.model_name,
                tool_access_mode=self.tool_access_mode,
                test_type=instance.test_type,
                category=instance.category,
                format=instance.format,
                task_type=instance.task_type,
                attack_type=instance.attack_type,
                attack_params=instance.attack_params,
                defense_type=instance.defense_type,
                model_output="",
                raw_response="",
                benign_correct=False,
                benign_match_score=0.0,
                attack_successful=False,
                attack_match_score=0.0,
                latency_ms=None,
                error=str(e),
            )

    def run_instances(
        self,
        instances: list[Instance],
        verbose: bool = True,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[EvaluationResult]:
        """Run model on multiple instances.

        Args:
            instances: List of instances
            verbose: Print progress
            progress_callback: Optional callback called after each instance with (current, total)

        Returns:
            List of EvaluationResult objects
        """
        results = []

        for i, instance in enumerate(instances, 1):
            if verbose and not progress_callback:
                print(f"[{i}/{len(instances)}] Running {instance.instance_id}...")

            result = self.run_instance(instance, verbose)
            results.append(result)

            if progress_callback:
                progress_callback(i, len(instances))

            if verbose and not progress_callback and result.error:
                print(f"  Error: {result.error}")

        return results
