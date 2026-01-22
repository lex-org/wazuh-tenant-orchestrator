"""
API configuration settings.

Loads API-specific configuration from environment variables.
"""
import os

from dotenv import load_dotenv

load_dotenv()


class APISettings:
    """Configuration settings for the FastAPI application."""

    API_KEY: str = os.getenv("API_KEY", "")
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    SSL_VERIFY: bool = os.getenv("SSL_VERIFY", "True").lower() in ("true", "1", "yes")


settings = APISettings()
