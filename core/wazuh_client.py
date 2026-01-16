import requests
import os
import urllib3
import json
from dotenv import load_dotenv

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
        if self.authenticate():
            # 2. Version detection (needed to choose the strategy from JSON)
            self.version = self._get_wazuh_version()
            print(f"Detected Wazuh version: {self.version}")
        else:
            print("Critical error: Unable to authenticate. Using default version.")
            self.version = "default"

    def _load_api_spec(self):
        """Load the API mapping from the JSON file."""
        try:
            spec_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'API_SPEC.json')
            with open(spec_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("Warning: API_SPEC.json not found! Make sure it exists in config/")
            return {"wazuh_api_versions": {"default": {}}}

    def authenticate(self):
        """Obtain JWT token and prepare headers for subsequent calls."""
        auth_url = f"{self.base_url}/security/user/authenticate"
        try:
            response = requests.get(
                auth_url,
                auth=(self.user, self.password),
                verify=False
            )
            if response.status_code == 200:
                self.token = response.json().get('data', {}).get('token')
                # Populate headers to be used throughout the script
                self.headers = {
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
                }
                print(f"Successfully authenticated with {self.host}")
                return True
            return False
        except Exception as e:
            print(f"Connection error during authentication: {e}")
            return False

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

    def create_group(self, group_id):
        """Create a group using the strategy defined in API_SPEC.json for the current version."""
        # Get version-specific config or fall back to default
        spec = self.api_spec['wazuh_api_versions'].get(
            self.version,
            self.api_spec['wazuh_api_versions']['default']
        )
        config = spec.get('create_group', {})

        url = f"{self.base_url}/groups"

        # Apply strategy: Body (newer versions) or Params (older versions)
        if config.get('use_body'):
            payload = {config['payload_key']: group_id}
            response = requests.post(url, headers=self.headers, json=payload, verify=False)
        else:
            params = {config['query_key']: group_id}
            response = requests.post(url, headers=self.headers, params=params, verify=False)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error creating group: {response.text}")
            return None

# --- Example usage ---
if __name__ == "__main__":
    client = WazuhClient()
    # If authentication succeeded in __init__
    if client.token:
        client.create_group("Test_Client_Orchestrator")
