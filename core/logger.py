import logging
import sys

def setup_logger():
    """
    Configures a professional logger that writes to both the console and a file.
    """
    logger = logging.getLogger("TenantOrchestrator")
    logger.setLevel(logging.INFO)

    # Format: Timestamp - Level - Message
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Handler 1: Console (for the developer to see)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Handler 2: File (for the MSP to audit later)
    file_handler = logging.FileHandler('orchestrator.log')
    file_handler.setFormatter(formatter)

    # Add handlers to the logger
    if not logger.handlers:
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger

# Initialize the global logger instance
logger = setup_logger()