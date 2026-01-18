"""
conftest.py - Shared Test Configuration
========================================

This file is automatically loaded by pytest. It contains "fixtures" - reusable
pieces of setup code shared across multiple test files.

KEY CONCEPTS:
- @pytest.fixture: Decorator that marks a function as a fixture
- Fixtures are "injected" into tests by adding them as function parameters
- monkeypatch: Built-in pytest fixture to safely modify environment variables
"""
import pytest
from unittest.mock import Mock


# =============================================================================
# FIXTURE: Sample test data
# =============================================================================
@pytest.fixture
def sample_tenant():
    """
    Provides sample tenant data for tests.

    Usage in a test:
        def test_something(sample_tenant):
            tenant_id = sample_tenant["id"]  # "test_tenant"
    """
    return {
        "id": "test_tenant",
        "webhook_url": "https://example.com/webhook"
    }


# =============================================================================
# FIXTURE: Mock environment variables
# =============================================================================
@pytest.fixture
def mock_env_vars(monkeypatch):
    """
    Sets fake environment variables so tests don't need real credentials.

    'monkeypatch' is a pytest built-in that safely modifies things
    and automatically restores them after each test.
    """
    monkeypatch.setenv("WAZUH_HOST", "localhost")
    monkeypatch.setenv("WAZUH_PORT", "55000")
    monkeypatch.setenv("WAZUH_USER", "test_user")
    monkeypatch.setenv("WAZUH_PASSWORD", "test_password")
    monkeypatch.setenv("OPENSEARCH_HOST", "localhost")
    monkeypatch.setenv("OPENSEARCH_PORT", "9200")
    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "admin_password")


# =============================================================================
# HELPER FUNCTION: Create mock responses easily
# =============================================================================
def create_mock_response(status_code, json_data=None, text=""):
    """
    Helper to create fake HTTP responses.

    Args:
        status_code: HTTP status (200, 401, 500, etc.)
        json_data: What response.json() should return
        text: What response.text should return (for error messages)

    Returns:
        A Mock object that behaves like a requests.Response
    """
    mock_response = Mock()
    mock_response.status_code = status_code
    mock_response.text = text
    if json_data:
        mock_response.json.return_value = json_data
    return mock_response


# =============================================================================
# FIXTURES: Wazuh API mock responses
# =============================================================================
@pytest.fixture
def mock_wazuh_auth_success():
    """Simulates successful Wazuh authentication (200 + token)."""
    return create_mock_response(200, {
        "data": {"token": "fake_jwt_token_for_testing"}
    })


@pytest.fixture
def mock_wazuh_auth_failure():
    """Simulates failed authentication (401 Invalid credentials)."""
    return create_mock_response(401, text="Invalid credentials")


@pytest.fixture
def mock_wazuh_version():
    """Simulates Wazuh version endpoint response."""
    return create_mock_response(200, {
        "data": {"version": "4.10.1"}
    })


@pytest.fixture
def mock_wazuh_group_not_found():
    """Simulates: group search returns empty (group doesn't exist)."""
    return create_mock_response(200, {
        "data": {"affected_items": [], "total_affected_items": 0}
    })


@pytest.fixture
def mock_wazuh_group_exists():
    """Simulates: group search finds existing group."""
    return create_mock_response(200, {
        "data": {
            "affected_items": [{"name": "test_tenant"}],
            "total_affected_items": 1
        }
    })


@pytest.fixture
def mock_wazuh_group_created():
    """Simulates successful group creation."""
    return create_mock_response(200, {
        "data": {"affected_items": ["test_tenant"], "total_affected_items": 1}
    })


# =============================================================================
# FIXTURES: OpenSearch API mock responses
# =============================================================================
@pytest.fixture
def mock_opensearch_success():
    """Generic successful OpenSearch response."""
    return create_mock_response(200, {"status": "ok"})


@pytest.fixture
def mock_opensearch_channel_created():
    """Simulates successful notification channel creation."""
    return create_mock_response(200, {"config_id": "channel_123"})


@pytest.fixture
def mock_opensearch_no_channels():
    """Simulates: no notification channels exist."""
    return create_mock_response(200, {"config_list": []})


@pytest.fixture
def mock_opensearch_monitor_created():
    """Simulates successful monitor creation."""
    return create_mock_response(200, {"_id": "monitor_456"})


@pytest.fixture
def mock_opensearch_monitor_not_found():
    """Simulates: monitor search returns no hits."""
    return create_mock_response(200, {
        "hits": {"total": {"value": 0}, "hits": []}
    })


@pytest.fixture
def mock_opensearch_role_created():
    """Simulates successful role creation."""
    return create_mock_response(200, {"status": "CREATED"})


@pytest.fixture
def mock_opensearch_404():
    """Simulates: resource not found (useful for idempotency checks)."""
    return create_mock_response(404, text="Not found")
