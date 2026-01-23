"""
Wazuh Tenant Orchestrator CLI.

A command-line tool for automated multi-tenant provisioning on Wazuh SIEM.
Creates agent groups, notification channels, monitors, and DLS roles
with a single command.
"""
import argparse
import os
import sys

from core.exceptions import ConfigurationError, OpenSearchAPIError, WazuhAPIError
from core.logger import logger
from core.opensearch_client import OpenSearchClient
from core.utils import str_to_bool, validate_tenant_name, validate_webhook_url
from core.wazuh_client import WazuhClient


def main() -> None:
    """
    Main entry point for the Wazuh Tenant Orchestrator.

    Parses command-line arguments and orchestrates the provisioning
    workflow across Wazuh and OpenSearch.
    """
    parser = argparse.ArgumentParser(
        description="Wazuh Multi-tenant Orchestrator"
    )
    parser.add_argument(
        "--tenant",
        required=True,
        help="Tenant ID (alphanumeric, hyphens, underscores only)"
    )
    parser.add_argument(
        "--webhook",
        required=True,
        help="Notification Webhook URL (must be http:// or https://)"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification (not recommended for production)"
    )
    args = parser.parse_args()

    if not validate_tenant_name(args.tenant):
        sys.exit(1)

    if not validate_webhook_url(args.webhook):
        sys.exit(1)

    env_verify = str_to_bool(os.getenv("SSL_VERIFY", "True"))
    verify_ssl = False if args.insecure else env_verify

    if not verify_ssl:
        logger.warning(
            "SSL verification is disabled. This is insecure for production use."
        )

    logger.info(f"Starting provisioning for: {args.tenant}")

    try:
        w_client = WazuhClient(verify_ssl=verify_ssl)
        w_client.create_group(args.tenant)

        os_client = OpenSearchClient(verify_ssl=verify_ssl)
        os_res = os_client.create_notification_channel(args.tenant, args.webhook)
        channel_id = os_res.get('config_id')

        os_client.create_tenant_monitor(args.tenant, channel_id)

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
