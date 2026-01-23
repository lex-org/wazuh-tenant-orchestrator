"""
OpenSearch API client for multi-tenant provisioning.

Handles creation of notification channels, monitors, index templates,
and Document Level Security (DLS) roles for tenant isolation.
"""
import json
import os
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.exceptions import OpenSearchAPIError
from core.logger import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT: tuple[int, int] = (10, 30)

DEFAULT_RETRIES: int = 3
DEFAULT_BACKOFF_FACTOR: float = 1.0
RETRY_STATUS_CODES: list[int] = [429, 500, 502, 503, 504]


class OpenSearchClient:
    """
    Client for interacting with the OpenSearch API.

    Provides methods for creating tenant-specific resources:
    - Notification channels (webhooks)
    - Alerting monitors
    - Index templates
    - DLS roles for data isolation

    All methods are idempotent — safe to call multiple times.

    Attributes:
        host: OpenSearch hostname.
        port: OpenSearch API port.
        base_url: Full base URL for API requests.
        verify_ssl: Whether to verify SSL certificates.
    """

    def __init__(self, verify_ssl: bool = True) -> None:
        """
        Initialize the OpenSearch client.

        Args:
            verify_ssl: Whether to verify SSL certificates. Set to False
                       for self-signed certificates in development.
        """
        load_dotenv()
        self.host: str = os.getenv('OPENSEARCH_HOST', 'localhost')
        self.port: str = os.getenv('OPENSEARCH_PORT', '9200')
        self.user: str = os.getenv('OPENSEARCH_USER', 'admin')
        self.password: str = os.getenv('OPENSEARCH_PASSWORD', 'SecretPassword')
        self.base_url: str = f"https://{self.host}:{self.port}"
        self.verify_ssl: bool = verify_ssl

        timeout_str = os.getenv('OPENSEARCH_TIMEOUT')
        if timeout_str:
            try:
                timeout_val = int(timeout_str)
                self.timeout: tuple[int, int] = (timeout_val, timeout_val)
            except ValueError:
                self.timeout = DEFAULT_TIMEOUT
        else:
            self.timeout = DEFAULT_TIMEOUT

        retry_strategy = Retry(
            total=DEFAULT_RETRIES,
            backoff_factor=DEFAULT_BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_CODES,
            allowed_methods=["GET", "POST", "PUT"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def channel_exists(self, tenant_id: str) -> str | None:
        """
        Check if a notification channel for the tenant already exists.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            The channel config_id if exists, None otherwise.
        """
        url = f"{self.base_url}/_plugins/_notifications/configs"
        channel_name = f"Channel-{tenant_id}"

        try:
            response = self.session.get(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if response.status_code == 200:
                configs = response.json().get('config_list', [])
                for config in configs:
                    if config.get('config', {}).get('name') == channel_name:
                        return config.get('config_id')
            return None
        except requests.exceptions.RequestException:
            return None

    def create_notification_channel(
        self, tenant_id: str, webhook_url: str
    ) -> dict[str, Any]:
        """
        Create a webhook notification channel for a specific tenant.

        This method is idempotent — returns existing channel if already exists.

        Args:
            tenant_id: The tenant identifier (used in channel name).
            webhook_url: The URL to send notifications to.

        Returns:
            API response dict with config_id, or existing channel info.

        Raises:
            OpenSearchAPIError: If channel creation fails.
        """
        existing_id = self.channel_exists(tenant_id)
        if existing_id:
            logger.info(
                f"Notification channel for '{tenant_id}' already exists, "
                "skipping creation"
            )
            return {"config_id": existing_id, "already_exists": True}

        url = f"{self.base_url}/_plugins/_notifications/configs"

        payload = {
            "config": {
                "name": f"Channel-{tenant_id}",
                "description": f"Webhook channel for {tenant_id}",
                "config_type": "webhook",
                "is_enabled": True,
                "webhook": {
                    "url": webhook_url
                }
            }
        }

        response = self.session.post(
            url,
            auth=(self.user, self.password),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout
        )

        if response.status_code in [200, 201]:
            logger.info(f"Notification channel for {tenant_id} created.")
            return response.json()
        else:
            logger.error(
                f"Failed to create notification channel: "
                f"{response.status_code} - {response.text}"
            )
            raise OpenSearchAPIError(
                f"Failed to create notification channel for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )

    def monitor_exists(self, tenant_id: str) -> str | None:
        """
        Check if a monitor for the tenant already exists.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            The monitor ID if exists, None otherwise.
        """
        url = f"{self.base_url}/_plugins/_alerting/monitors/_search"
        monitor_name = f"Monitor-{tenant_id}"

        query = {
            "query": {
                "term": {
                    "monitor.name.keyword": monitor_name
                }
            }
        }

        try:
            response = self.session.post(
                url,
                auth=(self.user, self.password),
                json=query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                if hits:
                    return hits[0].get('_id')
            return None
        except requests.exceptions.RequestException:
            return None

    def create_tenant_monitor(
        self, tenant_id: str, channel_id: str
    ) -> dict[str, Any] | str:
        """
        Create a Monitor that watches logs from a specific Wazuh agent group.

        The monitor:
        - Searches only in tenant-specific indices (wazuh-alerts-{tenant_id}-*)
        - Filters by agent.group to ensure proper isolation
        - Triggers notifications to the specified channel

        This method is idempotent — skips creation if monitor already exists.

        Args:
            tenant_id: The tenant identifier.
            channel_id: The notification channel ID to link alerts to.

        Returns:
            Monitor ID on success, or {"already_exists": True} if exists.

        Raises:
            OpenSearchAPIError: If monitor creation fails.
        """
        existing_id = self.monitor_exists(tenant_id)
        if existing_id:
            logger.info(f"Monitor for '{tenant_id}' already exists, skipping creation")
            return {"monitor_id": existing_id, "already_exists": True}

        url = f"{self.base_url}/_plugins/_alerting/monitors"

        query_filter = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"manager.name": "wazuh-manager"}},
                        {"term": {"agent.group": tenant_id}}
                    ]
                }
            }
        }

        payload = {
            "type": "monitor",
            "name": f"Monitor-{tenant_id}",
            "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{
                "search": {
                    "indices": [f"wazuh-alerts-{tenant_id}-*"],
                    "query": query_filter
                }
            }],
            "triggers": [{
                "name": f"Trigger-{tenant_id}",
                "severity": "1",
                "condition": {
                    "script": {
                        "source": "ctx.results[0].hits.total.value > 0",
                        "lang": "painless"
                    }
                },
                "actions": [{
                    "name": "Send-Alert",
                    "destination_id": channel_id,
                    "message_template": {
                        "source": (
                            "Alert detected for {{ctx.monitor.name}}: "
                            "{{ctx.results.0.hits.total.value}} events found."
                        )
                    }
                }]
            }]
        }

        response = self.session.post(
            url,
            auth=(self.user, self.password),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout
        )

        if response.status_code in [200, 201]:
            logger.info(f"Monitor for {tenant_id} created successfully.")
            return response.json().get('_id')
        else:
            logger.error(f"Error creating Monitor: {response.text}")
            raise OpenSearchAPIError(
                f"Failed to create monitor for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )

    def _index_template_exists(self, tenant_id: str) -> bool:
        """
        Check if an index template for the tenant already exists.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True if template exists, False otherwise.
        """
        url = f"{self.base_url}/_index_template/template_{tenant_id}"

        try:
            response = self.session.get(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def create_tenant_index_template(self, tenant_id: str) -> dict[str, Any] | bool:
        """
        Create an Index Template for tenant-specific log indices.

        Ensures that logs for this tenant go into separate, optimized indices
        with appropriate settings for shard count and lifecycle management.

        This method is idempotent — skips creation if template already exists.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True on success, or {"already_exists": True} if exists.

        Raises:
            OpenSearchAPIError: If template creation fails.
        """
        if self._index_template_exists(tenant_id):
            logger.info(
                f"Index template for '{tenant_id}' already exists, skipping creation"
            )
            return {"already_exists": True}

        url = f"{self.base_url}/_index_template/template_{tenant_id}"

        payload = {
            "index_patterns": [f"wazuh-alerts-{tenant_id}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "index.lifecycle.name": "tenant_retention_policy"
                },
                "mappings": {
                    "properties": {
                        "agent.group": {"type": "keyword"}
                    }
                }
            },
            "priority": 100
        }

        response = self.session.put(
            url,
            auth=(self.user, self.password),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout
        )

        if response.status_code in [200, 201]:
            logger.info(f"Index Template for {tenant_id} created.")
            return True
        else:
            logger.error(
                f"Failed to create index template for {tenant_id}: {response.text}"
            )
            raise OpenSearchAPIError(
                f"Failed to create index template for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )

    def role_exists(self, tenant_id: str) -> bool:
        """
        Check if a DLS role for the tenant already exists.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True if role exists, False otherwise.
        """
        url = f"{self.base_url}/_plugins/_security/api/roles/{tenant_id}_role"

        try:
            response = self.session.get(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def create_tenant_role(self, tenant_id: str) -> dict[str, Any] | bool:
        """
        Create an OpenSearch role with Document Level Security (DLS).

        DLS ensures that users with this role can only see documents
        where agent.group matches their tenant ID, providing data isolation
        at the query level.

        This method is idempotent — skips creation if role already exists.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True on success, or {"already_exists": True} if exists.

        Raises:
            OpenSearchAPIError: If role creation fails.
        """
        if self.role_exists(tenant_id):
            logger.info(
                f"DLS role for '{tenant_id}' already exists, skipping creation"
            )
            return {"already_exists": True}

        url = f"{self.base_url}/_plugins/_security/api/roles/{tenant_id}_role"

        dls_query = json.dumps({"term": {"agent.group.keyword": tenant_id}})

        payload = {
            "cluster_permissions": ["read"],
            "index_permissions": [{
                "index_patterns": ["wazuh-alerts-*"],
                "allowed_actions": ["read", "search"],
                "dls": dls_query
            }]
        }

        response = self.session.put(
            url,
            auth=(self.user, self.password),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout
        )

        if response.status_code in [200, 201]:
            logger.info(f"DLS role for {tenant_id} created successfully.")
            return True
        else:
            logger.error(f"Error creating role: {response.text}")
            raise OpenSearchAPIError(
                f"Failed to create DLS role for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )

    def delete_notification_channel(self, tenant_id: str) -> bool:
        """
        Delete a notification channel for the tenant.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True if channel was deleted or didn't exist.

        Raises:
            OpenSearchAPIError: If channel deletion fails.
        """
        channel_id = self.channel_exists(tenant_id)
        if not channel_id:
            logger.info(
                f"Notification channel for '{tenant_id}' does not exist, nothing to delete"
            )
            return True

        url = f"{self.base_url}/_plugins/_notifications/configs/{channel_id}"

        try:
            response = self.session.delete(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection error during channel deletion: {e}")
            raise OpenSearchAPIError(
                f"Failed to delete notification channel for '{tenant_id}': {e}"
            )

        if response.status_code in [200, 204]:
            logger.info(f"Successfully deleted notification channel for: {tenant_id}")
            return True
        else:
            logger.error(f"Error deleting notification channel: {response.text}")
            raise OpenSearchAPIError(
                f"Failed to delete notification channel for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )

    def delete_tenant_monitor(self, tenant_id: str) -> bool:
        """
        Delete a monitor for the tenant.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True if monitor was deleted or didn't exist.

        Raises:
            OpenSearchAPIError: If monitor deletion fails.
        """
        monitor_id = self.monitor_exists(tenant_id)
        if not monitor_id:
            logger.info(f"Monitor for '{tenant_id}' does not exist, nothing to delete")
            return True

        url = f"{self.base_url}/_plugins/_alerting/monitors/{monitor_id}"

        try:
            response = self.session.delete(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection error during monitor deletion: {e}")
            raise OpenSearchAPIError(f"Failed to delete monitor for '{tenant_id}': {e}")

        if response.status_code in [200, 204]:
            logger.info(f"Successfully deleted monitor for: {tenant_id}")
            return True
        else:
            logger.error(f"Error deleting monitor: {response.text}")
            raise OpenSearchAPIError(
                f"Failed to delete monitor for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )

    def delete_tenant_role(self, tenant_id: str) -> bool:
        """
        Delete a DLS role for the tenant.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True if role was deleted or didn't exist.

        Raises:
            OpenSearchAPIError: If role deletion fails.
        """
        if not self.role_exists(tenant_id):
            logger.info(f"DLS role for '{tenant_id}' does not exist, nothing to delete")
            return True

        url = f"{self.base_url}/_plugins/_security/api/roles/{tenant_id}_role"

        try:
            response = self.session.delete(
                url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection error during role deletion: {e}")
            raise OpenSearchAPIError(f"Failed to delete DLS role for '{tenant_id}': {e}")

        if response.status_code in [200, 204]:
            logger.info(f"Successfully deleted DLS role for: {tenant_id}")
            return True
        else:
            logger.error(f"Error deleting role: {response.text}")
            raise OpenSearchAPIError(
                f"Failed to delete DLS role for '{tenant_id}': "
                f"{response.status_code} - {response.text}"
            )
