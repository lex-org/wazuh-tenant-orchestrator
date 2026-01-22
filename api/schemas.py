"""
Pydantic request/response models for the API.
"""
from pydantic import BaseModel, HttpUrl


class TenantCreate(BaseModel):
    """Request model for creating a new tenant."""

    tenant_id: str
    webhook_url: HttpUrl


class TenantResources(BaseModel):
    """Tenant resource identifiers."""

    group: str
    channel_id: str | None = None
    monitor_id: str | None = None
    role: str


class TenantResponse(BaseModel):
    """Response model for tenant provisioning."""

    status: str  # "success" | "error"
    tenant_id: str
    resources: TenantResources
    already_existed: bool = False


class TenantStatus(BaseModel):
    """Response model for tenant status check."""

    tenant_id: str
    group_exists: bool
    channel_exists: bool
    monitor_exists: bool
    role_exists: bool


class TenantDeleteResponse(BaseModel):
    """Response model for tenant deletion."""

    status: str  # "success" | "error"
    tenant_id: str
    message: str


class ErrorResponse(BaseModel):
    """Standard error response model."""

    status: str = "error"
    message: str
    detail: str | None = None


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    version: str
