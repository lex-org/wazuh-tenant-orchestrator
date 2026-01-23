import pytest
from unittest.mock import Mock


@pytest.fixture
def sample_tenant():
    return {
        "id": "test_tenant",
        "webhook_url": "https://example.com/webhook"
    }


@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("WAZUH_HOST", "localhost")
    monkeypatch.setenv("WAZUH_PORT", "55000")
    monkeypatch.setenv("WAZUH_USER", "test_user")
    monkeypatch.setenv("WAZUH_PASSWORD", "test_password")
    monkeypatch.setenv("OPENSEARCH_HOST", "localhost")
    monkeypatch.setenv("OPENSEARCH_PORT", "9200")
    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "admin_password")


def create_mock_response(status_code, json_data=None, text=""):
    mock_response = Mock()
    mock_response.status_code = status_code
    mock_response.text = text
    if json_data:
        mock_response.json.return_value = json_data
    return mock_response


@pytest.fixture
def mock_wazuh_auth_success():
    return create_mock_response(200, {
        "data": {"token": "fake_jwt_token_for_testing"}
    })


@pytest.fixture
def mock_wazuh_auth_failure():
    return create_mock_response(401, text="Invalid credentials")


@pytest.fixture
def mock_wazuh_version():
    return create_mock_response(200, {
        "data": {"version": "4.10.1"}
    })


@pytest.fixture
def mock_wazuh_group_not_found():
    return create_mock_response(200, {
        "data": {"affected_items": [], "total_affected_items": 0}
    })


@pytest.fixture
def mock_wazuh_group_exists():
    return create_mock_response(200, {
        "data": {
            "affected_items": [{"name": "test_tenant"}],
            "total_affected_items": 1
        }
    })


@pytest.fixture
def mock_wazuh_group_created():
    return create_mock_response(200, {
        "data": {"affected_items": ["test_tenant"], "total_affected_items": 1}
    })


@pytest.fixture
def mock_opensearch_success():
    return create_mock_response(200, {"status": "ok"})


@pytest.fixture
def mock_opensearch_channel_created():
    return create_mock_response(200, {"config_id": "channel_123"})


@pytest.fixture
def mock_opensearch_no_channels():
    return create_mock_response(200, {"config_list": []})


@pytest.fixture
def mock_opensearch_monitor_created():
    return create_mock_response(200, {"_id": "monitor_456"})


@pytest.fixture
def mock_opensearch_monitor_not_found():
    return create_mock_response(200, {
        "hits": {"total": {"value": 0}, "hits": []}
    })


@pytest.fixture
def mock_opensearch_role_created():
    return create_mock_response(200, {"status": "CREATED"})


@pytest.fixture
def mock_opensearch_404():
    return create_mock_response(404, text="Not found")
