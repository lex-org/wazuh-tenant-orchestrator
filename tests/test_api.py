import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.config import settings
from core.exceptions import WazuhAPIError, OpenSearchAPIError, ConfigurationError


@pytest.fixture
def test_client():
    return TestClient(app)


@pytest.fixture
def valid_api_key(monkeypatch):
    monkeypatch.setenv("API_KEY", "test-api-key-12345")
    settings.API_KEY = "test-api-key-12345"
    return "test-api-key-12345"


@pytest.fixture
def mock_wazuh_client():
    mock = MagicMock()
    mock.group_exists.return_value = False
    mock.create_group.return_value = {"data": {"affected_items": ["test_tenant"]}}
    mock.delete_group.return_value = True
    return mock


@pytest.fixture
def mock_opensearch_client():
    mock = MagicMock()
    mock.channel_exists.return_value = None
    mock.monitor_exists.return_value = None
    mock.role_exists.return_value = False
    mock.create_notification_channel.return_value = {"config_id": "channel_123"}
    mock.create_tenant_monitor.return_value = "monitor_456"
    mock.create_tenant_role.return_value = True
    mock.delete_notification_channel.return_value = True
    mock.delete_tenant_monitor.return_value = True
    mock.delete_tenant_role.return_value = True
    return mock


class TestHealthEndpoint:

    def test_health_check_returns_ok(self, test_client):
        response = test_client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestAuthentication:

    def test_missing_api_key_returns_422(self, test_client, valid_api_key):
        response = test_client.get("/api/v1/tenants/test_tenant")

        assert response.status_code == 422

    def test_invalid_api_key_returns_401(self, test_client, valid_api_key):
        response = test_client.get(
            "/api/v1/tenants/test_tenant",
            headers={"X-API-Key": "wrong-key"}
        )

        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_valid_api_key_allows_access(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.get(
                    "/api/v1/tenants/test_tenant",
                    headers={"X-API-Key": valid_api_key}
                )

        assert response.status_code == 200


class TestCreateTenant:

    def test_create_tenant_success(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.post(
                    "/api/v1/tenants",
                    headers={"X-API-Key": valid_api_key},
                    json={
                        "tenant_id": "test_tenant",
                        "webhook_url": "https://example.com/webhook"
                    }
                )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["tenant_id"] == "test_tenant"
        assert data["resources"]["group"] == "test_tenant"
        assert data["resources"]["channel_id"] == "channel_123"
        assert data["resources"]["role"] == "test_tenant_role"

    def test_create_tenant_already_exists(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        mock_wazuh_client.create_group.return_value = {"already_exists": True}
        mock_opensearch_client.create_notification_channel.return_value = {
            "config_id": "channel_123",
            "already_exists": True
        }
        mock_opensearch_client.create_tenant_monitor.return_value = {
            "monitor_id": "monitor_456",
            "already_exists": True
        }
        mock_opensearch_client.create_tenant_role.return_value = {"already_exists": True}

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.post(
                    "/api/v1/tenants",
                    headers={"X-API-Key": valid_api_key},
                    json={
                        "tenant_id": "test_tenant",
                        "webhook_url": "https://example.com/webhook"
                    }
                )

        assert response.status_code == 200
        data = response.json()
        assert data["already_existed"] is True

    def test_create_tenant_invalid_tenant_id(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.post(
                    "/api/v1/tenants",
                    headers={"X-API-Key": valid_api_key},
                    json={
                        "tenant_id": "ab",
                        "webhook_url": "https://example.com/webhook"
                    }
                )

        assert response.status_code == 422
        assert "Invalid tenant_id" in response.json()["detail"]

    def test_create_tenant_invalid_webhook_url(self, test_client, valid_api_key):
        response = test_client.post(
            "/api/v1/tenants",
            headers={"X-API-Key": valid_api_key},
            json={
                "tenant_id": "test_tenant",
                "webhook_url": "not-a-valid-url"
            }
        )

        assert response.status_code == 422

    def test_create_tenant_wazuh_error_returns_502(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client
    ):
        mock_wazuh_client.create_group.side_effect = WazuhAPIError("Connection failed")

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            response = test_client.post(
                "/api/v1/tenants",
                headers={"X-API-Key": valid_api_key},
                json={
                    "tenant_id": "test_tenant",
                    "webhook_url": "https://example.com/webhook"
                }
            )

        assert response.status_code == 502
        assert "Wazuh API error" in response.json()["detail"]

    def test_create_tenant_opensearch_error_returns_502(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        mock_opensearch_client.create_notification_channel.side_effect = OpenSearchAPIError(
            "Connection failed"
        )

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.post(
                    "/api/v1/tenants",
                    headers={"X-API-Key": valid_api_key},
                    json={
                        "tenant_id": "test_tenant",
                        "webhook_url": "https://example.com/webhook"
                    }
                )

        assert response.status_code == 502
        assert "OpenSearch API error" in response.json()["detail"]


class TestGetTenantStatus:

    def test_get_tenant_status_all_exist(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        mock_wazuh_client.group_exists.return_value = True
        mock_opensearch_client.channel_exists.return_value = "channel_123"
        mock_opensearch_client.monitor_exists.return_value = "monitor_456"
        mock_opensearch_client.role_exists.return_value = True

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.get(
                    "/api/v1/tenants/test_tenant",
                    headers={"X-API-Key": valid_api_key}
                )

        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == "test_tenant"
        assert data["group_exists"] is True
        assert data["channel_exists"] is True
        assert data["monitor_exists"] is True
        assert data["role_exists"] is True

    def test_get_tenant_status_none_exist(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        mock_wazuh_client.group_exists.return_value = False
        mock_opensearch_client.channel_exists.return_value = None
        mock_opensearch_client.monitor_exists.return_value = None
        mock_opensearch_client.role_exists.return_value = False

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.get(
                    "/api/v1/tenants/nonexistent_tenant",
                    headers={"X-API-Key": valid_api_key}
                )

        assert response.status_code == 200
        data = response.json()
        assert data["group_exists"] is False
        assert data["channel_exists"] is False
        assert data["monitor_exists"] is False
        assert data["role_exists"] is False

    def test_get_tenant_status_partial_resources(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        mock_wazuh_client.group_exists.return_value = True
        mock_opensearch_client.channel_exists.return_value = "channel_123"
        mock_opensearch_client.monitor_exists.return_value = None
        mock_opensearch_client.role_exists.return_value = False

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.get(
                    "/api/v1/tenants/partial_tenant",
                    headers={"X-API-Key": valid_api_key}
                )

        assert response.status_code == 200
        data = response.json()
        assert data["group_exists"] is True
        assert data["channel_exists"] is True
        assert data["monitor_exists"] is False
        assert data["role_exists"] is False


class TestDeleteTenant:

    def test_delete_tenant_success(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.delete(
                    "/api/v1/tenants/test_tenant",
                    headers={"X-API-Key": valid_api_key}
                )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["tenant_id"] == "test_tenant"
        assert "group" in data["message"]
        assert "channel" in data["message"]
        assert "monitor" in data["message"]
        assert "role" in data["message"]

    def test_delete_tenant_wazuh_error_returns_502(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client
    ):
        mock_wazuh_client.delete_group.side_effect = WazuhAPIError("Delete failed")

        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            response = test_client.delete(
                "/api/v1/tenants/test_tenant",
                headers={"X-API-Key": valid_api_key}
            )

        assert response.status_code == 502
        assert "Wazuh API error" in response.json()["detail"]

    def test_delete_nonexistent_tenant_succeeds(
        self,
        test_client,
        valid_api_key,
        mock_wazuh_client,
        mock_opensearch_client
    ):
        with patch('api.routes.tenants.WazuhClient', return_value=mock_wazuh_client):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.delete(
                    "/api/v1/tenants/nonexistent_tenant",
                    headers={"X-API-Key": valid_api_key}
                )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


class TestExceptionHandlers:

    def test_configuration_error_returns_500(
        self,
        test_client,
        valid_api_key,
        mock_opensearch_client
    ):
        with patch('api.routes.tenants.WazuhClient', side_effect=ConfigurationError("Config missing")):
            with patch('api.routes.tenants.OpenSearchClient', return_value=mock_opensearch_client):
                response = test_client.post(
                    "/api/v1/tenants",
                    headers={"X-API-Key": valid_api_key},
                    json={
                        "tenant_id": "test_tenant",
                        "webhook_url": "https://example.com/webhook"
                    }
                )

        assert response.status_code == 500
