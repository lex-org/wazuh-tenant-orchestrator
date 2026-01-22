"""
Tenant CRUD endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException

from api.config import settings
from api.dependencies import verify_api_key
from api.schemas import (
    ErrorResponse,
    TenantCreate,
    TenantDeleteResponse,
    TenantResources,
    TenantResponse,
    TenantStatus,
)
from core.exceptions import ConfigurationError, OpenSearchAPIError, WazuhAPIError
from core.logger import logger
from core.opensearch_client import OpenSearchClient
from core.utils import validate_tenant_name, validate_webhook_url
from core.wazuh_client import WazuhClient

router = APIRouter()


@router.post(
    "/tenants",
    response_model=TenantResponse,
    responses={
        401: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def create_tenant(
    tenant: TenantCreate,
    _: str = Depends(verify_api_key),
) -> TenantResponse:
    """
    Provision a new tenant.

    Creates the following resources:
    - Wazuh agent group
    - OpenSearch notification channel
    - OpenSearch alerting monitor
    - OpenSearch DLS role for data isolation
    """
    # Validate tenant_id
    if not validate_tenant_name(tenant.tenant_id):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid tenant_id: '{tenant.tenant_id}'. "
            "Must be 3-64 alphanumeric characters, hyphens, or underscores."
        )

    # Validate webhook_url (additional validation beyond Pydantic)
    if not validate_webhook_url(str(tenant.webhook_url)):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid webhook_url: '{tenant.webhook_url}'. "
            "Must be a valid HTTP/HTTPS URL."
        )

    verify_ssl = settings.SSL_VERIFY
    already_existed = False
    channel_id = None
    monitor_id = None

    try:
        # 1. Create Wazuh agent group
        logger.info(f"API: Starting provisioning for tenant: {tenant.tenant_id}")
        w_client = WazuhClient(verify_ssl=verify_ssl)
        group_result = w_client.create_group(tenant.tenant_id)
        if group_result.get("already_exists"):
            already_existed = True

        # 2. Create OpenSearch notification channel
        os_client = OpenSearchClient(verify_ssl=verify_ssl)
        channel_result = os_client.create_notification_channel(
            tenant.tenant_id, str(tenant.webhook_url)
        )
        channel_id = channel_result.get("config_id")
        if channel_result.get("already_exists"):
            already_existed = True

        # 3. Create OpenSearch monitor
        monitor_result = os_client.create_tenant_monitor(tenant.tenant_id, channel_id)
        if isinstance(monitor_result, dict):
            if monitor_result.get("already_exists"):
                already_existed = True
            monitor_id = monitor_result.get("monitor_id")
        else:
            monitor_id = monitor_result

        # 4. Create OpenSearch DLS role
        role_result = os_client.create_tenant_role(tenant.tenant_id)
        if isinstance(role_result, dict) and role_result.get("already_exists"):
            already_existed = True

        logger.info(f"API: Provisioning completed for tenant: {tenant.tenant_id}")

        return TenantResponse(
            status="success",
            tenant_id=tenant.tenant_id,
            resources=TenantResources(
                group=tenant.tenant_id,
                channel_id=channel_id,
                monitor_id=monitor_id,
                role=f"{tenant.tenant_id}_role",
            ),
            already_existed=already_existed,
        )

    except ConfigurationError as e:
        logger.error(f"API: Configuration error for tenant {tenant.tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except WazuhAPIError as e:
        logger.error(f"API: Wazuh API error for tenant {tenant.tenant_id}: {e}")
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {e}")
    except OpenSearchAPIError as e:
        logger.error(f"API: OpenSearch API error for tenant {tenant.tenant_id}: {e}")
        raise HTTPException(status_code=502, detail=f"OpenSearch API error: {e}")


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantStatus,
    responses={
        401: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def get_tenant_status(
    tenant_id: str,
    _: str = Depends(verify_api_key),
) -> TenantStatus:
    """
    Check tenant provisioning status.

    Returns the existence status of each tenant resource.
    """
    verify_ssl = settings.SSL_VERIFY

    try:
        w_client = WazuhClient(verify_ssl=verify_ssl)
        os_client = OpenSearchClient(verify_ssl=verify_ssl)

        return TenantStatus(
            tenant_id=tenant_id,
            group_exists=w_client.group_exists(tenant_id),
            channel_exists=os_client.channel_exists(tenant_id) is not None,
            monitor_exists=os_client.monitor_exists(tenant_id) is not None,
            role_exists=os_client.role_exists(tenant_id),
        )

    except ConfigurationError as e:
        logger.error(f"API: Configuration error checking tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except WazuhAPIError as e:
        logger.error(f"API: Wazuh API error checking tenant {tenant_id}: {e}")
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {e}")
    except OpenSearchAPIError as e:
        logger.error(f"API: OpenSearch API error checking tenant {tenant_id}: {e}")
        raise HTTPException(status_code=502, detail=f"OpenSearch API error: {e}")


@router.delete(
    "/tenants/{tenant_id}",
    response_model=TenantDeleteResponse,
    responses={
        401: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
    },
)
async def delete_tenant(
    tenant_id: str,
    _: str = Depends(verify_api_key),
) -> TenantDeleteResponse:
    """
    Remove tenant resources.

    Deletes all resources associated with the tenant:
    - Wazuh agent group
    - OpenSearch notification channel
    - OpenSearch alerting monitor
    - OpenSearch DLS role
    """
    verify_ssl = settings.SSL_VERIFY
    deleted_resources = []

    try:
        logger.info(f"API: Starting deletion for tenant: {tenant_id}")

        # 1. Delete Wazuh agent group
        w_client = WazuhClient(verify_ssl=verify_ssl)
        if w_client.delete_group(tenant_id):
            deleted_resources.append("group")

        # 2. Delete OpenSearch resources
        os_client = OpenSearchClient(verify_ssl=verify_ssl)

        if os_client.delete_tenant_monitor(tenant_id):
            deleted_resources.append("monitor")

        if os_client.delete_notification_channel(tenant_id):
            deleted_resources.append("channel")

        if os_client.delete_tenant_role(tenant_id):
            deleted_resources.append("role")

        logger.info(f"API: Deletion completed for tenant: {tenant_id}")

        return TenantDeleteResponse(
            status="success",
            tenant_id=tenant_id,
            message=f"Deleted resources: {', '.join(deleted_resources)}",
        )

    except ConfigurationError as e:
        logger.error(f"API: Configuration error deleting tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except WazuhAPIError as e:
        logger.error(f"API: Wazuh API error deleting tenant {tenant_id}: {e}")
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {e}")
    except OpenSearchAPIError as e:
        logger.error(f"API: OpenSearch API error deleting tenant {tenant_id}: {e}")
        raise HTTPException(status_code=502, detail=f"OpenSearch API error: {e}")
