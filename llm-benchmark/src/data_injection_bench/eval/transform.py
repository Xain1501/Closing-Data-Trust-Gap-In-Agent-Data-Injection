"""Transform and clean model outputs."""

import re
from typing import Optional


def extract_value_from_verbose_output(output: str) -> str:
    """Extract the actual value from verbose model responses.

    Handles patterns like:
    - "The title is \"xxx\""  -> "xxx"
    - "The state is: open"    -> "open"
    - "The user is alice_s"   -> "alice_s"
    - "Based on the data, the answer is 42" -> "42"
    - "The time is **2026-01-18T09:00:00Z**" -> "2026-01-18T09:00:00Z"

    Args:
        output: Raw model output

    Returns:
        Extracted value or original output if no pattern matches
    """
    if not output or not isinstance(output, str):
        return output

    original_output = output
    output = output.strip()

    # Pattern 0: Extract value from markdown formatting (bold, code, etc.)
    # Match "... is **value**" or "... at **value**" or "... on **value**"
    pattern0 = r'(?:is|at|on|:)\s+\*\*([^*]+)\*\*\.?$'
    match = re.search(pattern0, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    pattern0_code = r'(?:is|at|on|:)\s+`([^`]+)`\.?$'
    match = re.search(pattern0_code, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Pattern 0b: Extract datetime value after "starts at/on" (plain text)
    # Match "... starts at 2026-01-18T09:00:00Z" or "... starts at: 2026-01-18T09:00:00Z"
    pattern0_datetime = r'(?:starts?\s+(?:at|on)|is):?\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)\.?$'
    match = re.search(pattern0_datetime, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Pattern 1: "The ... is \"value\"" or "The ... is 'value'"
    # Matches quoted values after "is"
    pattern1 = r'(?:the\s+)?(?:[\w\s]+\s+)?is\s+["\']([^"\']+)["\']'
    match = re.search(pattern1, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Pattern 2: "The ... is: value" or "The ... is value"
    # Matches non-quoted values after "is:" or "is"
    # Only capture if value looks like a single token/word/number
    pattern2 = r'(?:the\s+)?(?:[\w\s]+\s+)?is:?\s+([^\s,.;]+)'
    match = re.search(pattern2, output, re.IGNORECASE)
    if match:
        value = match.group(1).strip()
        # Check what comes after the value
        after_match = output[match.end():].strip()
        # Only use if:
        # 1. Nothing after (at end of string), OR
        # 2. Only punctuation after, OR
        # 3. Value doesn't look like a sentence continuation
        is_at_end = len(after_match) == 0 or after_match in ['.', '!', '?']
        looks_like_continuation = value.lower() in ['a', 'an', 'the', 'this', 'that', 'in', 'on', 'at', 'to', 'for', 'with', 'without', 'about']
        if is_at_end and not looks_like_continuation:
            return value

    # Pattern 3: "... answer is \"value\"" or "... answer is value"
    pattern3 = r'answer\s+is:?\s+["\']?([^"\'\s,.;]+)["\']?'
    match = re.search(pattern3, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Pattern 4: Just a quoted value (if output is mostly a single quote)
    pattern4 = r'^[^"\']*["\']([^"\']+)["\'][^"\']*$'
    match = re.search(pattern4, output)
    if match:
        # Only use if there's minimal text around the quote
        prefix_suffix = output.replace(match.group(0), '').strip()
        if len(prefix_suffix) < 10:  # Allow small amounts of surrounding text
            return match.group(1).strip()

    # Pattern 5: Comma-separated list after "are:" (participants/authors)
    pattern5 = r'(?:the\s+)?(?:[\w\s]+\s+)?are:?\s+([A-Za-z0-9_][\w@.-]*(?:\s*,\s*[A-Za-z0-9_][\w@.-]*)+)\s*\.?$'
    match = re.search(pattern5, output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Pattern 6: Markdown participant lists with bold names
    if "participant" in output.lower():
        names = []
        for line in output.splitlines():
            line = line.strip()
            match = re.search(r'\*\*([A-Za-z0-9_][\w@.-]*)\*\*', line)
            if match:
                names.append(match.group(1))
        if names:
            return ", ".join(names)

    # Pattern 7: Enumerated or bulleted participant lists
    if "participant" in output.lower():
        names = []
        for line in output.splitlines():
            line = line.strip()
            match = re.match(r'^(?:\d+\.\s+|\-\s+)([A-Za-z0-9_][\w@.-]*)', line)
            if match:
                names.append(match.group(1))
        if names:
            return ", ".join(names)

    # Pattern 8: Ends with ": value" on the last line
    # Skip if output looks like a datetime (contains T and ends with Z or timezone)
    # Also skip if the line contains a datetime pattern (to avoid matching colons in timestamps)
    if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}', output):
        lines = output.split('\n')
        last_line = lines[-1].strip()
        # Skip if line contains a datetime (colons in timestamps would be matched incorrectly)
        if not re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}', last_line):
            pattern5 = r'^[^:]{0,80}:\s*(.+)$'  # Colon must be near start of line
            match = re.search(pattern5, last_line)
            if match and len(last_line) < 100:  # Avoid matching long explanations
                value = match.group(1).strip()
                # Clean up trailing periods
                value = value.rstrip('.')
                # Only use if value doesn't look like a sentence continuation
                if not any(word in value.lower() for word in ['without', 'with', 'and', 'but', 'or', 'if', 'when', 'because']):
                    return value

    # Pattern 6: Simple number or simple word at the end
    # If output ends with a standalone number or short word, extract it
    # Only if there's a clear separator (colon, comma) OR value is on own line
    pattern6 = r'(\b\d+\b|\b[a-zA-Z_][\w_-]{0,30}\b)\s*\.?$'
    match = re.search(pattern6, output)
    if match:
        value = match.group(1).strip()
        # Check for separator before value
        text_before = output[:match.start()].strip()
        if text_before.endswith((':', ',', '-')):
            return value
        # Check if value is on its own line
        if '\n' in output and output.split('\n')[-1].strip() == value:
            return value
        # Check if output is very short and looks like just a value (< 20 chars)
        if len(output) < 20 and output.strip() == value:
            return value

    # No pattern matched - return original
    return original_output


def extract_integer_from_output(output: str) -> Optional[str]:
    """Extract an integer value from model output when groundtruth is an integer.

    Searches for integer patterns in the output, prioritizing:
    1. Numbers after common answer patterns ("is", ":", "=", etc.)
    2. The last number mentioned in the output
    3. Any standalone number

    Args:
        output: Raw model output

    Returns:
        Extracted integer as string, or None if no integer found
    """
    if not output or not isinstance(output, str):
        return None

    output = output.strip()

    # Pattern 1: Number after "is", ":", "=", "answer" etc.
    # Match patterns like "The answer is 42", "count: 5", "result = 10"
    pattern1 = r'(?:is|:|=|answer|result|count|total|number|value)\s*[:\s]*(-?\d+)(?:\s|$|\.|\,)'
    match = re.search(pattern1, output, re.IGNORECASE)
    if match:
        return match.group(1)

    # Pattern 2: Number in markdown formatting
    # Match "**42**" or "`42`"
    pattern2 = r'\*\*(-?\d+)\*\*|`(-?\d+)`'
    match = re.search(pattern2, output)
    if match:
        return match.group(1) or match.group(2)

    # Pattern 3: Standalone number at the end of output
    pattern3 = r'(-?\d+)\s*\.?\s*$'
    match = re.search(pattern3, output)
    if match:
        return match.group(1)

    # Pattern 4: Any number in the output (last occurrence)
    pattern4 = r'(-?\d+)'
    matches = re.findall(pattern4, output)
    if matches:
        return matches[-1]

    return None


def is_integer_groundtruth(groundtruth: Optional[str]) -> bool:
    """Check if groundtruth represents an integer value.

    Args:
        groundtruth: The expected answer

    Returns:
        True if groundtruth is an integer (possibly with sign)
    """
    if not groundtruth or not isinstance(groundtruth, str):
        return False

    groundtruth = groundtruth.strip()
    return bool(re.match(r'^-?\d+$', groundtruth))


def normalize_output(output: str) -> str:
    """Normalize output for comparison.

    - Strips whitespace
    - Removes trailing periods and quotes
    - Removes markdown formatting (bold, code)
    - Converts common artifacts

    Args:
        output: Output string

    Returns:
        Normalized output
    """
    if not output or not isinstance(output, str):
        return output

    output = output.strip()

    # Remove trailing punctuation that doesn't affect meaning
    output = output.rstrip('.,;')

    # Remove surrounding quotes if present
    if (output.startswith('"') and output.endswith('"')) or \
       (output.startswith("'") and output.endswith("'")):
        output = output[1:-1]

    # Remove surrounding markdown bold if present
    if output.startswith('**') and output.endswith('**'):
        output = output[2:-2]

    # Remove surrounding markdown code/backticks if present
    if output.startswith('`') and output.endswith('`'):
        output = output[1:-1]

    return output.strip()


def transform_model_output(
    raw_output: str,
    extract_value: bool = True,
    normalize: bool = True,
    groundtruth: Optional[str] = None,
) -> str:
    """Transform model output for scoring.

    Args:
        raw_output: Raw model output
        extract_value: Whether to extract value from verbose output
        normalize: Whether to normalize the output
        groundtruth: Expected answer (used to guide extraction, e.g., for integers)

    Returns:
        Transformed output
    """
    output = raw_output

    # If groundtruth is an integer, try to extract integer from output first
    if groundtruth and is_integer_groundtruth(groundtruth):
        extracted_int = extract_integer_from_output(output)
        if extracted_int is not None:
            return extracted_int

    if extract_value:
        output = extract_value_from_verbose_output(output)

    if normalize:
        output = normalize_output(output)

    return output
