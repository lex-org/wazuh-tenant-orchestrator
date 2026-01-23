"""
Wazuh API client for agent group management.

Handles authentication, version detection, and group creation with
support for multiple Wazuh API versions via configuration.
"""
import json
import os
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.exceptions import ConfigurationError, WazuhAPIError
from core.logger import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT: tuple[int, int] = (10, 30)

DEFAULT_RETRIES: int = 3
DEFAULT_BACKOFF_FACTOR: float = 1.0
RETRY_STATUS_CODES: list[int] = [429, 500, 502, 503, 504]


class WazuhClient:
    """
    Client for interacting with the Wazuh Manager API.

    Handles JWT authentication and provides methods for group management.
    Supports multiple Wazuh versions through API_SPEC.json configuration.

    Attributes:
        host: Wazuh Manager hostname.
        port: Wazuh Manager API port.
        base_url: Full base URL for API requests.
        verify_ssl: Whether to verify SSL certificates.
        token: JWT authentication token.
        version: Detected Wazuh version (e.g., "4.10.x").
    """

    def __init__(self, verify_ssl: bool = True) -> None:
        """
        Initialize the client by loading configuration and authenticating.

        Args:
            verify_ssl: Whether to verify SSL certificates. Set to False
                       for self-signed certificates in development.

        Raises:
            ConfigurationError: If API_SPEC.json is missing or invalid.
            WazuhAPIError: If authentication fails.
        """
        load_dotenv()
        self.host: str = os.getenv('WAZUH_HOST', 'localhost')
        self.port: str = os.getenv('WAZUH_PORT', '55000')
        self.user: str | None = os.getenv('WAZUH_USER')
        self.password: str | None = os.getenv('WAZUH_PASSWORD')
        self.base_url: str = f"https://{self.host}:{self.port}"
        self.verify_ssl: bool = verify_ssl

        self.token: str | None = None
        self.headers: dict[str, str] = {}
        self.api_spec: dict[str, Any] = self._load_api_spec()

        timeout_str = os.getenv('WAZUH_TIMEOUT')
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
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.authenticate()
        self.version: str = self._get_wazuh_version()
        logger.info(f"Detected Wazuh version: {self.version}")

    def _load_api_spec(self) -> dict[str, Any]:
        """
        Load the API mapping from the JSON configuration file.

        Returns:
            Dictionary containing version-specific API configurations.

        Raises:
            ConfigurationError: If file is missing or contains invalid JSON.
        """
        spec_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'API_SPEC.json'
        )
        try:
            with open(spec_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"API_SPEC.json not found at {spec_path}")
            raise ConfigurationError(f"Required config file not found: {spec_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in API_SPEC.json: {e}")
            raise ConfigurationError(f"Invalid JSON in config file: {spec_path}")

    def authenticate(self) -> bool:
        """
        Obtain a JWT token and prepare headers for subsequent API calls.

        Returns:
            True if authentication succeeded.

        Raises:
            WazuhAPIError: If authentication fails or connection cannot be established.
        """
        auth_url = f"{self.base_url}/security/user/authenticate"
        try:
            response = self.session.get(
                auth_url,
                auth=(self.user, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during authentication: {e}")
            raise WazuhAPIError(
                f"Failed to connect to Wazuh API at {self.base_url}: {e}"
            )

        if response.status_code == 200:
            self.token = response.json().get('data', {}).get('token')
            self.headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            }
            logger.info(f"Successfully authenticated with {self.host}")
            return True
        elif response.status_code == 401:
            logger.error("Authentication failed: Invalid credentials")
            raise WazuhAPIError("Wazuh authentication failed: Invalid credentials")
        else:
            logger.error(
                f"Authentication failed: {response.status_code} - {response.text}"
            )
            raise WazuhAPIError(
                f"Wazuh authentication failed: {response.status_code} - {response.text}"
            )

    def _get_wazuh_version(self) -> str:
        """
        Query Wazuh for its version and normalize it for API spec matching.

        Transforms version strings like "4.10.1" to "4.10.x" to match
        the keys in API_SPEC.json.

        Returns:
            Normalized version string (e.g., "4.10.x") or "default" on failure.
        """
        try:
            res = self.session.get(
                f"{self.base_url}/info",
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if res.status_code == 200:
                full_version = res.json()['data']['version']
                return ".".join(full_version.split('.')[:2]) + ".x"
            return "default"
        except requests.exceptions.RequestException:
            return "default"

    def group_exists(self, group_id: str) -> bool:
        """
        Check if a Wazuh agent group already exists.

        Args:
            group_id: The group name to check.

        Returns:
            True if group exists, False otherwise or on error.
        """
        url = f"{self.base_url}/groups"
        try:
            response = self.session.get(
                url,
                headers=self.headers,
                params={"search": group_id},
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if response.status_code == 200:
                groups = response.json().get('data', {}).get('affected_items', [])
                return any(g.get('name') == group_id for g in groups)
            return False
        except requests.exceptions.RequestException:
            return False

    def create_group(self, group_id: str) -> dict[str, Any]:
        """
        Create a Wazuh agent group using version-appropriate API calls.

        This method is idempotent — if the group already exists, it returns
        successfully without attempting to create a duplicate.

        Args:
            group_id: The name for the new agent group.

        Returns:
            API response dict, or {"already_exists": True} if group exists.

        Raises:
            WazuhAPIError: If group creation fails.
        """
        if self.group_exists(group_id):
            logger.info(f"Group '{group_id}' already exists, skipping creation")
            return {"already_exists": True}

        spec = self.api_spec['wazuh_api_versions'].get(
            self.version,
            self.api_spec['wazuh_api_versions']['default']
        )
        config = spec.get('create_group', {})
        url = f"{self.base_url}/groups"

        if config.get('use_body'):
            payload = {config['payload_key']: group_id}
            response = self.session.post(
                url,
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        else:
            params = {config['query_key']: group_id}
            response = self.session.post(
                url,
                headers=self.headers,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

        if response.status_code == 200:
            logger.info(f"Successfully created Wazuh group: {group_id}")
            return response.json()
        else:
            logger.error(f"Error creating group: {response.text}")
            raise WazuhAPIError(
                f"Failed to create group '{group_id}': "
                f"{response.status_code} - {response.text}"
            )

    def delete_group(self, group_id: str) -> bool:
        """
        Delete a Wazuh agent group.

        Args:
            group_id: The name of the group to delete.

        Returns:
            True if group was deleted or didn't exist.

        Raises:
            WazuhAPIError: If group deletion fails.
        """
        if not self.group_exists(group_id):
            logger.info(f"Group '{group_id}' does not exist, nothing to delete")
            return True

        url = f"{self.base_url}/groups"
        params = {"groups_list": group_id}

        try:
            response = self.session.delete(
                url,
                headers=self.headers,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection error during group deletion: {e}")
            raise WazuhAPIError(f"Failed to delete group '{group_id}': {e}")

        if response.status_code == 200:
            logger.info(f"Successfully deleted Wazuh group: {group_id}")
            return True
        else:
            logger.error(f"Error deleting group: {response.text}")
            raise WazuhAPIError(
                f"Failed to delete group '{group_id}': "
                f"{response.status_code} - {response.text}"
            )


if __name__ == "__main__":
    client = WazuhClient()
    if client.token:
        client.create_group("Test_Client_Orchestrator")
