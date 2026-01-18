import re
from core.logger import logger

def validate_tenant_name(name):
    """
    Validates that the tenant name is safe for URLs and index names.
    Only alphanumeric characters, hyphens, and underscores are allowed.
    """
    pattern = r"^[a-zA-Z0-9_-]+$"
    if not re.match(pattern, name):
        logger.error(f"Invalid tenant name '{name}'. Use only letters, numbers, underscores, or hyphens (no spaces).")
        return False
    return True

def str_to_bool(value):
    """Converts environment string to boolean."""
    return str(value).lower() in ("true", "1", "yes")