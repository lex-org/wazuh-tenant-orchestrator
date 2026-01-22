"""
Health check endpoint.
"""
from fastapi import APIRouter

from api.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns basic service status. Does not require authentication.
    """
    return HealthResponse(
        status="healthy",
        version="0.1.0"
    )
