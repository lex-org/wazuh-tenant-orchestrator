import requests
import os
import urllib3
import json
from dotenv import load_dotenv
from core.logger import logger
from core.exceptions import *

# Disable SSL warnings for self-signed certificates (common in test/Docker environments)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhClient:
    def __init__(self):
        """Initialize the client by loading configuration and authenticating."""
        load_dotenv()
        self.host = os.getenv('WAZUH_HOST', 'localhost')
        self.port = os.getenv('WAZUH_PORT', '55000')
        self.user = os.getenv('WAZUH_USER')
        self.password = os.getenv('WAZUH_PASSWORD')
        self.base_url = f"https://{self.host}:{self.port}"

        self.token = None
        self.headers = {}
        self.api_spec = self._load_api_spec()

        # --- STARTUP FLOW ---
        # 1. Authentication (generates token and populates self.headers)
        self.authenticate()
        # 2. Version detection (needed to choose the strategy from JSON)
        self.version = self._get_wazuh_version()
        logger.info(f"Detected Wazuh version: {self.version}")

    def _load_api_spec(self):
        """Load the API mapping from the JSON file."""
        spec_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'API_SPEC.json')
        try:
            with open(spec_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"API_SPEC.json not found at {spec_path}")
            raise ConfigurationError(f"Required config file not found: {spec_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in API_SPEC.json: {e}")
            raise ConfigurationError(f"Invalid JSON in config file: {spec_path}")

    def authenticate(self):
        """Obtain JWT token and prepare headers for subsequent calls."""
        auth_url = f"{self.base_url}/security/user/authenticate"
        try:
            response = requests.get(
                auth_url,
                auth=(self.user, self.password),
                verify=False
            )
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during authentication: {e}")
            raise WazuhAPIError(f"Failed to connect to Wazuh API at {self.base_url}: {e}")

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
            logger.error(f"Authentication failed: {response.status_code} - {response.text}")
            raise WazuhAPIError(f"Wazuh authentication failed: {response.status_code} - {response.text}")

    def _get_wazuh_version(self):
        """Query Wazuh for its version and normalize it (e.g., 4.10.x)."""
        try:
            res = requests.get(f"{self.base_url}/info", headers=self.headers, verify=False)
            if res.status_code == 200:
                full_version = res.json()['data']['version']
                # Transform "4.10.1" to "4.10.x" for JSON mapping
                return ".".join(full_version.split('.')[:2]) + ".x"
            return "default"
        except:
            return "default"

    def _group_exists(self, group_id):
        """Check if a Wazuh group already exists."""
        url = f"{self.base_url}/groups"
        try:
            response = requests.get(
                url,
                headers=self.headers,
                params={"search": group_id},
                verify=False
            )
            if response.status_code == 200:
                groups = response.json().get('data', {}).get('affected_items', [])
                return any(g.get('name') == group_id for g in groups)
            return False
        except requests.exceptions.RequestException:
            # If check fails, attempt creation anyway
            return False

    def create_group(self, group_id):
        """Create a group using API_SPEC strategy, with idempotency."""
        # 1. Idempotency check
        if self._group_exists(group_id):
            logger.info(f"Group '{group_id}' already exists, skipping creation")
            return {"already_exists": True}

        # 2. Get version-specific config or fall back to default
        spec = self.api_spec['wazuh_api_versions'].get(
            self.version,
            self.api_spec['wazuh_api_versions']['default']
        )
        config = spec.get('create_group', {})
        url = f"{self.base_url}/groups"

        # 3. Apply strategy: Body (newer versions) or Params (older versions)
        if config.get('use_body'):
            payload = {config['payload_key']: group_id}
            response = requests.post(url, headers=self.headers, json=payload, verify=False)
        else:
            params = {config['query_key']: group_id}
            response = requests.post(url, headers=self.headers, params=params, verify=False)

        if response.status_code == 200:
            logger.info(f"Successfully created Wazuh group: {group_id}")
            return response.json()
        else:
            logger.error(f"Error creating group: {response.text}")
            raise WazuhAPIError(f"Failed to create group '{group_id}': {response.status_code} - {response.text}")



# --- Example usage ---
if __name__ == "__main__":
    client = WazuhClient()
    # If authentication succeeded in __init__
    if client.token:
        client.create_group("Test_Client_Orchestrator")
