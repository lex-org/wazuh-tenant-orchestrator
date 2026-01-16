import requests
import os
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenSearchClient:
    def __init__(self):
        load_dotenv()
        # Default OpenSearch credentials in Wazuh Docker setup
        self.host = os.getenv('OPENSEARCH_HOST', 'localhost')
        self.port = os.getenv('OPENSEARCH_PORT', '9200')
        self.user = os.getenv('OPENSEARCH_USER', 'admin')
        self.password = os.getenv('OPENSEARCH_PASSWORD', 'SecretPassword')
        self.base_url = f"https://{self.host}:{self.port}"

    def create_notification_channel(self, tenant_id, webhook_url):
        """
        Create a webhook notification channel for a specific tenant.
        This is the bridge to your ticketing system.
        """
        # OpenSearch Notifications plugin endpoint
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

        response = requests.post(
            url,
            auth=(self.user, self.password),
            json=payload,
            verify=False
        )

        if response.status_code in [200, 201]:
            print(f"Notification channel for {tenant_id} created.")
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None


    def create_tenant_monitor(self, tenant_id, channel_id):
        """
        Create a Monitor that watches only logs from the specific Wazuh group
        and links it to the notification channel created earlier.
        """
        url = f"{self.base_url}/_plugins/_alerting/monitors"

        # This query filters Wazuh logs by the specific group
        query_filter = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"manager.name": "wazuh-manager"}},  # Logs from Wazuh
                        {"term": {"agent.group": tenant_id}}          # Filter by YOUR group
                    ]
                }
            }
        }

        payload = {
            "type": "monitor",
            "name": f"Monitor-{tenant_id}",
            "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},  # Check every minute
            "inputs": [{
                "search": {
                    "indices": [f"wazuh-alerts-{tenant_id}-*"],  # Targeted scan
                    "query": query_filter
                }
            }],
            "triggers": [{
                "name": f"Trigger-{tenant_id}",
                "severity": "1",
                "condition": {
                    "script": {"source": "ctx.results[0].hits.total.value > 0", "lang": "painless"}
                },
                "actions": [{
                    "name": "Send-Alert",
                    "destination_id": channel_id,  # Link to the channel created earlier
                    "message_template": {
                        "source": "Alert detected for {{ctx.monitor.name}}: {{ctx.results.0.hits.total.value}} events found."
                    }
                }]
            }]
        }

        response = requests.post(url, auth=(self.user, self.password), json=payload, verify=False)

        if response.status_code in [200, 201]:
            print(f"Monitor for {tenant_id} created successfully.")
            return response.json().get('_id')
        else:
            print(f"Error creating Monitor: {response.text}")
            return None


    def create_tenant_index_template(self, tenant_id):
        """
        Create an Index Template for the tenant. Ensures that customer logs
        end up in separate, optimized indices.
        """
        url = f"{self.base_url}/_index_template/template_{tenant_id}"

        payload = {
            "index_patterns": [f"wazuh-alerts-{tenant_id}-*"],  # Tenant index pattern
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "index.lifecycle.name": "tenant_retention_policy"  # Optional: for deleting old logs
                },
                "mappings": {
                    "properties": {
                        "agent.group": {"type": "keyword"}
                    }
                }
            },
            "priority": 100  # High priority to override generic template
        }

        response = requests.put(url, auth=(self.user, self.password), json=payload, verify=False)

        if response.status_code in [200, 201]:
            print(f"Index Template for {tenant_id} created.")
            return True
        return False


    def create_tenant_role(self, tenant_id):
        """
        Create an OpenSearch role with Document Level Security (DLS)
        to restrict log visibility to only the tenant's group.
        """
        url = f"{self.base_url}/_plugins/_security/api/roles/{tenant_id}_role"

        payload = {
            "cluster_permissions": ["read"],
            "index_permissions": [{
                "index_patterns": ["wazuh-alerts-*"],
                "allowed_actions": ["read", "search"],
                # Apply Document Level Security here
                "dls": {
                    "term": {
                        "agent.group.keyword": tenant_id
                    }
                }
            }]
        }

        response = requests.put(url, auth=(self.user, self.password), json=payload, verify=False)

        if response.status_code in [200, 201]:
            print(f"DLS role for {tenant_id} created successfully.")
            return True
        else:
            print(f"Error creating role: {response.text}")
            return False

# Quick test
if __name__ == "__main__":
    os_client = OpenSearchClient()
    # Example: link a hypothetical tenant to your backend
    os_client.create_notification_channel("Test_Client", "http://host.docker.internal:8000/api/v1/tickets")
