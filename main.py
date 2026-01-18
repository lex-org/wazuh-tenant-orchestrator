from core.wazuh_client import WazuhClient
from core.opensearch_client import OpenSearchClient
from core.logger import logger
from core.exceptions import ConfigurationError, WazuhAPIError, OpenSearchAPIError
import argparse
import sys
from core.utils import *
import os

def main():

    parser = argparse.ArgumentParser(description="Wazuh Multi-tenant Orchestrator")
    parser.add_argument("--tenant", required=True, help="Tenant ID (alphanumeric)")
    parser.add_argument("--webhook", required=True, help="Notification Webhook URL")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    # 1. Input Validation
    if not validate_tenant_name(args.tenant):
        sys.exit(1)

    # 2. SSL Verification Logic
    # If --insecure is used, verify=False.
    # Otherwise, it takes the value from .env (defaulting to True for security)
    env_verify = str_to_bool(os.getenv("SSL_VERIFY", "True"))
    verify_ssl = False if args.insecure else env_verify

    logger.info(f"Starting provisioning for: {args.tenant}")

    try:
        # 2. Wazuh operation
        w_client = WazuhClient()
        w_client.create_group(args.tenant)

        # 3. OpenSearch operation: Notification channel
        os_client = OpenSearchClient()
        os_res = os_client.create_notification_channel(args.tenant, args.webhook)
        channel_id = os_res.get('config_id')

        # 4. OpenSearch operation: Monitor
        os_client.create_tenant_monitor(args.tenant, channel_id)

        # 5. OpenSearch operation: Security and Roles (DLS)
        os_client.create_tenant_role(args.tenant)

        logger.info("Provisioning completed successfully!")

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except WazuhAPIError as e:
        logger.error(f"Wazuh API error: {e}")
        sys.exit(1)
    except OpenSearchAPIError as e:
        logger.error(f"OpenSearch API error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
