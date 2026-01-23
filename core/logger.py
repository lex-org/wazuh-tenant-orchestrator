"""
Centralized logging configuration for the Wazuh Tenant Orchestrator.

Provides dual output:
- Console: For real-time developer feedback
- File: For audit trails and debugging
"""
import logging
import sys


def setup_logger() -> logging.Logger:
    """
    Configure a logger that writes to both console and file.

    The logger uses a consistent format across all outputs:
    'YYYY-MM-DD HH:MM:SS - LEVEL - message'

    Returns:
        A configured Logger instance.
    """
    logger = logging.getLogger("TenantOrchestrator")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler('orchestrator.log')
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger


logger: logging.Logger = setup_logger()
