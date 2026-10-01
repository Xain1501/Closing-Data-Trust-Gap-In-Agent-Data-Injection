"""Utilities for anonymizing seed data with realistic fake names."""

import hashlib
from typing import Dict


# Lists of realistic fake names for anonymization
FIRST_NAMES = [
    "Alice", "Bob", "Carol", "David", "Emma", "Frank", "Grace", "Henry",
    "Iris", "Jack", "Kate", "Liam", "Maya", "Noah", "Olivia", "Peter",
    "Quinn", "Rachel", "Sam", "Tina", "Uma", "Victor", "Wendy", "Xander",
    "Yara", "Zoe", "Alex", "Blake", "Casey", "Drew", "Eli", "Finn",
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
]

# Cache for consistent anonymization (same input -> same output)
_name_cache: Dict[str, str] = {}
_email_cache: Dict[str, str] = {}
_company_cache: Dict[str, str] = {}

COMPANY_DOMAINS = [
    "dia.com",
    "northwind.com",
    "brightlane.com",
    "redwood.com",
    "horizonlab.com",
    "silvergate.com",
    "stellarrail.com",
    "lumenworks.com",
    "canyonbridge.com",
    "blueharbor.com",
    "summitpeak.com",
    "goldfield.com",
    "ironforge.com",
]


def get_fake_name(original_identifier: str, include_last: bool = True) -> str:
    """Generate a consistent fake name for an identifier.

    Args:
        original_identifier: Original name/ID/username to anonymize
        include_last: Whether to include last name

    Returns:
        Fake name (e.g., "Alice Smith" or "Alice")
    """
    if original_identifier in _name_cache:
        return _name_cache[original_identifier]

    # Use hash to consistently map identifier to name
    hash_val = int(hashlib.md5(original_identifier.encode()).hexdigest(), 16)

    first_idx = hash_val % len(FIRST_NAMES)
    first_name = FIRST_NAMES[first_idx]

    if include_last:
        last_idx = (hash_val // len(FIRST_NAMES)) % len(LAST_NAMES)
        last_name = LAST_NAMES[last_idx]
        fake_name = f"{first_name} {last_name}"
    else:
        fake_name = first_name

    _name_cache[original_identifier] = fake_name
    return fake_name


def get_fake_company_domain(original_domain: str) -> str:
    """Generate a consistent fake company domain for an original domain."""
    if original_domain in _company_cache:
        return _company_cache[original_domain]

    hash_val = int(hashlib.md5(original_domain.encode()).hexdigest(), 16)
    domain = COMPANY_DOMAINS[hash_val % len(COMPANY_DOMAINS)]
    _company_cache[original_domain] = domain
    return domain


def get_fake_email(original_email: str) -> str:
    """Generate a consistent fake email for an original email.

    Args:
        original_email: Original email address

    Returns:
        Fake email (e.g., "alice.smith@dia.com")
    """
    if original_email in _email_cache:
        return _email_cache[original_email]

    # Get fake name based on email
    fake_name = get_fake_name(original_email, include_last=True)
    first, last = fake_name.split()
    domain = original_email.split("@")[-1] if "@" in original_email else "unknown.com"
    fake_domain = get_fake_company_domain(domain)
    fake_email = f"{first.lower()}.{last.lower()}@{fake_domain}"

    _email_cache[original_email] = fake_email
    return fake_email


def get_fake_username(original_username: str) -> str:
    """Generate a consistent fake username.

    Args:
        original_username: Original username

    Returns:
        Fake username (e.g., "alice_s")
    """
    fake_name = get_fake_name(original_username, include_last=True)
    first, last = fake_name.split()
    return f"{first.lower()}_{last[0].lower()}"


def clear_caches():
    """Clear anonymization caches (for testing or new collection run)."""
    global _name_cache, _email_cache, _company_cache
    _name_cache = {}
    _email_cache = {}
    _company_cache = {}


# Example usage
if __name__ == "__main__":
    # Demonstrate consistent anonymization
    print("Fake Names:")
    print(f"  user123 -> {get_fake_name('user123')}")
    print(f"  user456 -> {get_fake_name('user456')}")
    print(f"  user123 -> {get_fake_name('user123')} (consistent!)")
    print()
    print("Fake Emails:")
    print(f"  john.doe@dia.com -> {get_fake_email('john.doe@dia.com')}")
    print(f"  jane.smith@lumenworks.com -> {get_fake_email('jane.smith@lumenworks.com')}")
    print(f"  john.doe@dia.com -> {get_fake_email('john.doe@dia.com')} (consistent!)")
    print()
    print("Fake Usernames:")
    print(f"  johndoe123 -> {get_fake_username('johndoe123')}")
    print(f"  janesmith -> {get_fake_username('janesmith')}")
