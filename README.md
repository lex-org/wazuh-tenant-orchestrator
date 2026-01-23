# Wazuh Tenant Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A CLI tool for automated multi-tenant provisioning on Wazuh SIEM. Designed for MSPs (Managed Service Providers) and SOCs managing multiple customers on a single Wazuh instance.

## Problem

When managing multiple tenants on a single Wazuh deployment, you need to manually:
- Create separate agent groups for each customer
- Configure dedicated notification channels
- Set up monitors with tenant-specific filters
- Create roles with data isolation (Document Level Security)

This is repetitive, error-prone, and doesn't scale.

## Solution

With a single command, this tool automates the entire tenant provisioning workflow:

```bash
python main.py --tenant "CustomerX" --webhook "https://your-ticketing-system.com/api/alerts"
```

This creates:
1. **Wazuh Agent Group** - Isolates agents by customer
2. **OpenSearch Notification Channel** - Webhook to your ticketing/alerting system
3. **OpenSearch Monitor** - Filters alerts by `agent.group` and triggers notifications
4. **OpenSearch Role with DLS** - Document Level Security for data isolation

## Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Wazuh Agent   │ ───▶ │  Wazuh Manager  │ ───▶ │   OpenSearch    │
│  (group: X)     │      │                 │      │                 │
└─────────────────┘      └─────────────────┘      └────────┬────────┘
                                                           │
                                                    Monitor filters
                                                    agent.group = X
                                                           │
                                                           ▼
                                                 ┌─────────────────┐
                                                 │  Webhook → SOC  │
                                                 │  Ticketing      │
                                                 └─────────────────┘
```

## Prerequisites

- Python 3.11+
- Access to Wazuh Manager API (port 55000)
- Access to OpenSearch API (port 9200)
- Valid credentials for both services

## Installation

```bash
poetry install
```

## Configuration

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Edit `.env` with your credentials:

```env
# Wazuh Manager
WAZUH_HOST=your-wazuh-manager.com
WAZUH_PORT=55000
WAZUH_USER=wazuh-api-user
WAZUH_PASSWORD=your-password

# OpenSearch
OPENSEARCH_HOST=your-opensearch.com
OPENSEARCH_PORT=9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your-password

# SSL Verification (default: True)
SSL_VERIFY=True
```

### SSL Verification

By default, SSL certificate verification is **enabled** for security. If you're testing locally with self-signed certificates, you can disable it:

```bash
# Option 1: Use the --insecure flag
python main.py --tenant "Test" --webhook "https://example.com" --insecure

# Option 2: Set in .env file
SSL_VERIFY=False
```

> ⚠️ **Warning:** Only disable SSL verification in development/testing environments. Always use valid certificates in production.

## Usage

### Basic provisioning

```bash
python main.py --tenant "CustomerName" --webhook "https://your-webhook-url.com"
```

### With Poetry

```bash
poetry run python main.py --tenant "CustomerName" --webhook "https://your-webhook-url.com"
```

### Example

```bash
# Provision a new tenant called "Acme Corp" with alerts going to your SOC platform
python main.py --tenant "AcmeCorp" --webhook "https://soc.example.com/api/v1/alerts"
```

Output:
```
--- Starting provisioning for: AcmeCorp ---
Successfully authenticated with Wazuh
Group 'AcmeCorp' created successfully.
Notification channel for AcmeCorp created.
OpenSearch channel configured (ID: abc123).
Monitor for AcmeCorp created successfully.
DLS role for AcmeCorp created successfully.
Multi-tenancy completed for AcmeCorp.
--- Provisioning completed successfully! ---
```

## Filebeat Configuration for Multi-tenancy

> **Important:** To fully leverage the index isolation created by this tool, you need to configure Filebeat to route logs based on the tenant.

### 1. Modify filebeat.yml

On the Wazuh Manager server, locate the `output.elasticsearch` (or `output.opensearch`) section and modify the index logic as follows:

```yaml
output.elasticsearch:
  hosts: ["https://localhost:9200"]
  # This line tells Filebeat to use the group name in the index name
  index: "wazuh-alerts-%{[agent.group]}-4.x-%{+yyyy.MM.dd}"
```

### 2. Why is this necessary?

| Benefit | Description |
|---------|-------------|
| **Dynamic Routing** | Without this line, all logs would end up in the generic "melting pot" index |
| **Template Matching** | Using `%{[agent.group]}`, Filebeat creates indices that match exactly the Index Templates created by this script (e.g., `wazuh-alerts-AcmeCorp-*`) |
| **Performance** | This enables the targeted search we configured in the OpenSearch Monitors |

## Project Structure

```
wazuh-tenant-orchestrator/
├── core/
│   ├── wazuh_client.py      # Wazuh API client (auth, groups)
│   └── opensearch_client.py # OpenSearch client (channels, monitors, roles)
├── api/
│   ├── main.py              # FastAPI application
│   ├── routes/              # REST endpoints
│   └── schemas.py           # Request/response models
├── tests/                   # Unit tests
├── main.py                  # CLI entry point
├── .env.example             # Configuration template
└── pyproject.toml           # Python dependencies (Poetry)
```

## Development

### Install dev dependencies

```bash
poetry install --with dev
```

### Run tests

```bash
poetry run pytest
```

## Contributing

Contributions welcome - open an issue or submit a PR.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source security platform
- [OpenSearch](https://opensearch.org/) - Open source search and analytics
