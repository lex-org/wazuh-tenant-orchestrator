"""
API dependencies including authentication.
"""
from fastapi import Header, HTTPException

from api.config import settings


async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Verify the API key provided in the X-API-Key header.

    Args:
        x_api_key: The API key from the request header.

    Returns:
        The validated API key.

    Raises:
        HTTPException: If the API key is missing or invalid.
    """
    if not settings.API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API_KEY not configured on server"
        )
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return x_api_key
