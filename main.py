from core.wazuh_client import WazuhClient
from core.opensearch_client import OpenSearchClient
import argparse
import re
import sys

def main():
    # 1. Configure command line arguments
    parser = argparse.ArgumentParser(description="Wazuh Multi-tenant Provisioning Tool")
    parser.add_argument("--tenant", required=True, help="Customer/tenant name")
    parser.add_argument("--webhook", required=True, help="URL to send alerts to")
    args = parser.parse_args()

    def validate_tenant_name(name):
        """
        Verifica che il nome del tenant sia sicuro.
        Accetta solo caratteri alfanumerici, trattini e underscore.
        """
        # Pattern: ^ (inizio), [a-zA-Z0-9_-] (caratteri ammessi), + (uno o più), $ (fine)
        pattern = r"^[a-zA-Z0-9_-]+$"

        if not re.match(pattern, name):
            print(f"❌ ERRORE: Il nome tenant '{name}' non è valido.")
            print("Usa solo lettere, numeri, underscores o trattini (senza spazi).")
            return False
        return True

    if not validate_tenant_name(args.tenant):
        sys.exit(1)

    print(f"--- Starting provisioning for: {args.tenant} ---")

    # 2. Wazuh operation
    w_client = WazuhClient()
    w_res = w_client.create_group(args.tenant)
    if w_res:
        print(f"Wazuh group '{args.tenant}' created.")

    # 3. OpenSearch operation: Notification channel
    os_client = OpenSearchClient()
    os_res = os_client.create_notification_channel(args.tenant, args.webhook)
    if os_res:
        # Get the ID of the newly created channel
        channel_id = os_res.get('config_id')
        print(f"OpenSearch channel configured (ID: {channel_id}).")

        # 4. OpenSearch operation: Monitor
        monitor_id = os_client.create_tenant_monitor(args.tenant, channel_id)
        if monitor_id:
            print(f"Monitor created for {args.tenant}.")

    # 5. OpenSearch operation: Security and Roles (DLS)
    role_success = os_client.create_tenant_role(args.tenant)
    if role_success:
        print(f"Data isolation (DLS) configured for {args.tenant}.")

    print(f"--- Provisioning completed successfully! ---")

if __name__ == "__main__":
    main()
