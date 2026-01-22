"""
Utility functions for input validation and type conversion.

These utilities provide a security boundary, validating all user input
before it reaches the API clients.
"""
import re
from urllib.parse import urlparse
from core.logger import logger


def validate_tenant_name(name: str) -> bool:
    """
    Validate that the tenant name is safe for URLs and index names.

    Only alphanumeric characters, hyphens, and underscores are allowed.
    Must be between 3 and 64 characters long.
    This prevents injection attacks and ensures compatibility with
    OpenSearch index naming conventions.

    Args:
        name: The tenant name to validate.

    Returns:
        True if valid, False otherwise.
    """
    if len(name) < 3 or len(name) > 64:
        logger.error(
            f"Invalid tenant name '{name}'. "
            "Must be between 3 and 64 characters long."
        )
        return False
    pattern = r"^[a-zA-Z0-9_-]+$"
    if not re.match(pattern, name):
        logger.error(
            f"Invalid tenant name '{name}'. "
            "Use only letters, numbers, underscores, or hyphens (no spaces)."
        )
        return False
    return True


def str_to_bool(value: str | None) -> bool:
    """
    Convert an environment variable string to a boolean.

    Recognizes common truthy values: "true", "1", "yes" (case-insensitive).
    Everything else (including None) returns False.

    Args:
        value: The string value to convert.

    Returns:
        True if value represents a truthy string, False otherwise.
    """
    return str(value).lower() in ("true", "1", "yes")


def validate_webhook_url(url: str) -> bool:
    """
    Validate that the webhook URL is properly formatted.

    Must have a valid scheme (http/https) and a network location (host).
    This ensures the notification channel can actually reach the endpoint.

    Args:
        url: The webhook URL to validate.

    Returns:
        True if valid, False otherwise.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            logger.error(
                f"Invalid webhook URL '{url}'. Must start with http:// or https://"
            )
            return False
        if not parsed.netloc:
            logger.error(f"Invalid webhook URL '{url}'. Missing host.")
            return False
        return True
    except Exception:
        logger.error(f"Invalid webhook URL '{url}'. Could not parse URL.")
        return False
