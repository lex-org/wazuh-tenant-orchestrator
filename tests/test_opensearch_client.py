import pytest
from unittest.mock import patch, Mock, MagicMock
from core.opensearch_client import OpenSearchClient
from core.exceptions import OpenSearchAPIError


def create_mock_session():
    mock_session = MagicMock()
    return mock_session


class TestCreateNotificationChannel:

    @patch('core.opensearch_client.requests')
    def test_creates_channel_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_no_channels,
        mock_opensearch_channel_created
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_no_channels
        mock_session.post.return_value = mock_opensearch_channel_created
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_notification_channel("test_tenant", "https://webhook.example.com")

        assert result["config_id"] == "channel_123"
        mock_session.post.assert_called_once()

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_channel_exists(
        self,
        mock_requests,
        mock_env_vars
    ):
        existing_channel_response = Mock()
        existing_channel_response.status_code = 200
        existing_channel_response.json.return_value = {
            "config_list": [
                {
                    "config_id": "existing_channel_id",
                    "config": {"name": "Channel-test_tenant"}
                }
            ]
        }

        mock_session = create_mock_session()
        mock_session.get.return_value = existing_channel_response
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_notification_channel("test_tenant", "https://webhook.example.com")

        assert result["already_exists"] is True
        assert result["config_id"] == "existing_channel_id"
        mock_session.post.assert_not_called()

    @patch('core.opensearch_client.requests')
    def test_api_error_raises_exception(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_no_channels
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_no_channels
        error_response = Mock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"
        mock_session.post.return_value = error_response
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        with pytest.raises(OpenSearchAPIError) as exc_info:
            client.create_notification_channel("test_tenant", "https://webhook.example.com")

        assert "Failed to create notification channel" in str(exc_info.value)


class TestCreateTenantMonitor:

    @patch('core.opensearch_client.requests')
    def test_creates_monitor_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_monitor_not_found,
        mock_opensearch_monitor_created
    ):
        mock_session = create_mock_session()
        mock_session.post.side_effect = [
            mock_opensearch_monitor_not_found,
            mock_opensearch_monitor_created
        ]
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_tenant_monitor("test_tenant", "channel_123")

        assert result == "monitor_456"
        assert mock_session.post.call_count == 2

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_monitor_exists(
        self,
        mock_requests,
        mock_env_vars
    ):
        monitor_exists_response = Mock()
        monitor_exists_response.status_code = 200
        monitor_exists_response.json.return_value = {
            "hits": {"total": {"value": 1}, "hits": [{"_id": "existing_monitor"}]}
        }

        mock_session = create_mock_session()
        mock_session.post.return_value = monitor_exists_response
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_tenant_monitor("test_tenant", "channel_123")

        assert result["already_exists"] is True
        assert mock_session.post.call_count == 1


class TestCreateTenantIndexTemplate:

    @patch('core.opensearch_client.requests')
    def test_creates_template_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_404,
        mock_opensearch_success
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_404
        mock_session.put.return_value = mock_opensearch_success
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_tenant_index_template("test_tenant")

        assert result is True
        mock_session.put.assert_called_once()

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_template_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_success
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_success
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_tenant_index_template("test_tenant")

        assert result["already_exists"] is True
        mock_session.put.assert_not_called()


class TestCreateTenantRole:

    @patch('core.opensearch_client.requests')
    def test_creates_role_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_404,
        mock_opensearch_role_created
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_404
        mock_session.put.return_value = mock_opensearch_role_created
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_tenant_role("test_tenant")

        assert result is True
        mock_session.put.assert_called_once()

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_role_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_success
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_success
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        result = client.create_tenant_role("test_tenant")

        assert result["already_exists"] is True
        mock_session.put.assert_not_called()

    @patch('core.opensearch_client.requests')
    def test_api_error_raises_exception(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_404
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_404
        error_response = Mock()
        error_response.status_code = 403
        error_response.text = "Forbidden"
        mock_session.put.return_value = error_response
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        with pytest.raises(OpenSearchAPIError) as exc_info:
            client.create_tenant_role("test_tenant")

        assert "Failed to create DLS role" in str(exc_info.value)


class TestOpenSearchClientWorkflow:

    @patch('core.opensearch_client.requests')
    def test_full_tenant_provisioning_workflow(
        self,
        mock_requests,
        mock_env_vars
    ):
        no_channel = Mock(status_code=200, json=Mock(return_value={"config_list": []}))
        channel_created = Mock(status_code=200, json=Mock(return_value={"config_id": "ch_123"}))
        no_monitor = Mock(status_code=200, json=Mock(return_value={"hits": {"total": {"value": 0}}}))
        monitor_created = Mock(status_code=200, json=Mock(return_value={"_id": "mon_456"}))
        no_template = Mock(status_code=404)
        template_created = Mock(status_code=200)
        no_role = Mock(status_code=404)
        role_created = Mock(status_code=200)

        mock_session = create_mock_session()
        mock_session.get.side_effect = [no_channel, no_template, no_role]
        mock_session.post.side_effect = [channel_created, no_monitor, monitor_created]
        mock_session.put.side_effect = [template_created, role_created]
        mock_requests.Session.return_value = mock_session

        client = OpenSearchClient()
        channel_result = client.create_notification_channel("new_tenant", "https://webhook.url")
        monitor_result = client.create_tenant_monitor("new_tenant", channel_result["config_id"])
        template_result = client.create_tenant_index_template("new_tenant")
        role_result = client.create_tenant_role("new_tenant")

        assert channel_result["config_id"] == "ch_123"
        assert monitor_result == "mon_456"
        assert template_result is True
        assert role_result is True
