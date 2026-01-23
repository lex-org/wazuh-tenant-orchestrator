"""
FastAPI application setup.

Main entry point for the REST API server.
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.config import settings
from api.routes import health, tenants
from api.schemas import ErrorResponse
from core.exceptions import ConfigurationError, OpenSearchAPIError, WazuhAPIError
from core.logger import logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    logger.info("Starting Wazuh Tenant Orchestrator API")
    if not settings.API_KEY:
        logger.warning("API_KEY not configured - API authentication will fail")
    yield
    logger.info("Shutting down Wazuh Tenant Orchestrator API")


app = FastAPI(
    title="Wazuh Tenant Orchestrator API",
    description="REST API for programmatic multi-tenant provisioning on Wazuh SIEM",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(ConfigurationError)
async def configuration_error_handler(
    request: Request, exc: ConfigurationError
) -> JSONResponse:
    """Handle configuration errors."""
    logger.error(f"Configuration error: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            status="error",
            message="Configuration error",
            detail=str(exc),
        ).model_dump(),
    )


@app.exception_handler(WazuhAPIError)
async def wazuh_api_error_handler(
    request: Request, exc: WazuhAPIError
) -> JSONResponse:
    """Handle Wazuh API errors."""
    logger.error(f"Wazuh API error: {exc}")
    return JSONResponse(
        status_code=502,
        content=ErrorResponse(
            status="error",
            message="Wazuh API error",
            detail=str(exc),
        ).model_dump(),
    )


@app.exception_handler(OpenSearchAPIError)
async def opensearch_api_error_handler(
    request: Request, exc: OpenSearchAPIError
) -> JSONResponse:
    """Handle OpenSearch API errors."""
    logger.error(f"OpenSearch API error: {exc}")
    return JSONResponse(
        status_code=502,
        content=ErrorResponse(
            status="error",
            message="OpenSearch API error",
            detail=str(exc),
        ).model_dump(),
    )


app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(tenants.router, prefix="/api/v1", tags=["tenants"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
    )
