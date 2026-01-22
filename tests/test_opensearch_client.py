"""
test_opensearch_client.py - Tests for core/opensearch_client.py
===============================================================

Tests the OpenSearch client including idempotency checks for:
- Notification channels
- Monitors
- Index templates
- DLS roles

MOCKING requests.Session:
-------------------------
The OpenSearch client uses requests.Session() for retry logic. We need to:
1. Mock requests.Session to return a mock session object
2. Mock session.get/post/put methods on that mock session
"""
import pytest
from unittest.mock import patch, Mock, MagicMock
from core.opensearch_client import OpenSearchClient
from core.exceptions import OpenSearchAPIError


def create_mock_session():
    """
    Create a mock Session object that can be configured in tests.

    Returns a MagicMock that acts like requests.Session() with
    get, post, put methods that can be configured with return_value
    or side_effect.
    """
    mock_session = MagicMock()
    return mock_session


# =============================================================================
# TESTS FOR: create_notification_channel()
# =============================================================================

class TestCreateNotificationChannel:
    """Tests for notification channel creation with idempotency."""

    @patch('core.opensearch_client.requests')
    def test_creates_channel_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_no_channels,
        mock_opensearch_channel_created
    ):
        """
        Test creating a new notification channel.

        FLOW:
        1. _channel_exists() -> returns None (not found)
        2. POST to create channel
        3. Returns response with config_id
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_no_channels
        mock_session.post.return_value = mock_opensearch_channel_created
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_notification_channel("test_tenant", "https://webhook.example.com")

        # ASSERT
        assert result["config_id"] == "channel_123"
        mock_session.post.assert_called_once()

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_channel_exists(
        self,
        mock_requests,
        mock_env_vars
    ):
        """
        Test idempotency: existing channel is not recreated.
        """
        # ARRANGE: Mock response with existing channel
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

        # ACT
        client = OpenSearchClient()
        result = client.create_notification_channel("test_tenant", "https://webhook.example.com")

        # ASSERT
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
        """
        Test that API errors raise OpenSearchAPIError.
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_no_channels
        error_response = Mock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"
        mock_session.post.return_value = error_response
        mock_requests.Session.return_value = mock_session

        # ACT & ASSERT
        client = OpenSearchClient()
        with pytest.raises(OpenSearchAPIError) as exc_info:
            client.create_notification_channel("test_tenant", "https://webhook.example.com")

        assert "Failed to create notification channel" in str(exc_info.value)


# =============================================================================
# TESTS FOR: create_tenant_monitor()
# =============================================================================

class TestCreateTenantMonitor:
    """Tests for monitor creation with idempotency."""

    @patch('core.opensearch_client.requests')
    def test_creates_monitor_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_monitor_not_found,
        mock_opensearch_monitor_created
    ):
        """
        Test creating a new monitor.
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.post.side_effect = [
            mock_opensearch_monitor_not_found,  # _monitor_exists() search
            mock_opensearch_monitor_created  # actual creation
        ]
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_tenant_monitor("test_tenant", "channel_123")

        # ASSERT
        assert result == "monitor_456"
        assert mock_session.post.call_count == 2

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_monitor_exists(
        self,
        mock_requests,
        mock_env_vars
    ):
        """
        Test idempotency: existing monitor is not recreated.
        """
        # ARRANGE: Mock search response with existing monitor
        monitor_exists_response = Mock()
        monitor_exists_response.status_code = 200
        monitor_exists_response.json.return_value = {
            "hits": {"total": {"value": 1}, "hits": [{"_id": "existing_monitor"}]}
        }

        mock_session = create_mock_session()
        mock_session.post.return_value = monitor_exists_response
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_tenant_monitor("test_tenant", "channel_123")

        # ASSERT
        assert result["already_exists"] is True
        # Only one POST call (the search), not two (search + create)
        assert mock_session.post.call_count == 1


# =============================================================================
# TESTS FOR: create_tenant_index_template()
# =============================================================================

class TestCreateTenantIndexTemplate:
    """Tests for index template creation with idempotency."""

    @patch('core.opensearch_client.requests')
    def test_creates_template_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_404,
        mock_opensearch_success
    ):
        """
        Test creating a new index template.
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_404  # template doesn't exist
        mock_session.put.return_value = mock_opensearch_success
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_tenant_index_template("test_tenant")

        # ASSERT
        assert result is True
        mock_session.put.assert_called_once()

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_template_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_success
    ):
        """
        Test idempotency: existing template is not recreated.
        """
        # ARRANGE: GET returns 200 (template exists)
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_success
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_tenant_index_template("test_tenant")

        # ASSERT
        assert result["already_exists"] is True
        mock_session.put.assert_not_called()


# =============================================================================
# TESTS FOR: create_tenant_role()
# =============================================================================

class TestCreateTenantRole:
    """Tests for DLS role creation with idempotency."""

    @patch('core.opensearch_client.requests')
    def test_creates_role_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_404,
        mock_opensearch_role_created
    ):
        """
        Test creating a new DLS role.
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_404
        mock_session.put.return_value = mock_opensearch_role_created
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_tenant_role("test_tenant")

        # ASSERT
        assert result is True
        mock_session.put.assert_called_once()

    @patch('core.opensearch_client.requests')
    def test_skips_creation_when_role_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_success
    ):
        """
        Test idempotency: existing role is not recreated.
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_success
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        result = client.create_tenant_role("test_tenant")

        # ASSERT
        assert result["already_exists"] is True
        mock_session.put.assert_not_called()

    @patch('core.opensearch_client.requests')
    def test_api_error_raises_exception(
        self,
        mock_requests,
        mock_env_vars,
        mock_opensearch_404
    ):
        """
        Test that API errors raise OpenSearchAPIError.
        """
        # ARRANGE
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_opensearch_404
        error_response = Mock()
        error_response.status_code = 403
        error_response.text = "Forbidden"
        mock_session.put.return_value = error_response
        mock_requests.Session.return_value = mock_session

        # ACT & ASSERT
        client = OpenSearchClient()
        with pytest.raises(OpenSearchAPIError) as exc_info:
            client.create_tenant_role("test_tenant")

        assert "Failed to create DLS role" in str(exc_info.value)


# =============================================================================
# INTEGRATION-STYLE TEST (tests multiple methods together)
# =============================================================================

class TestOpenSearchClientWorkflow:
    """
    Tests that simulate a real provisioning workflow.

    While still using mocks, these tests verify that multiple
    methods work together correctly.
    """

    @patch('core.opensearch_client.requests')
    def test_full_tenant_provisioning_workflow(
        self,
        mock_requests,
        mock_env_vars
    ):
        """
        Test the complete provisioning flow for a new tenant.
        """
        # ARRANGE: Set up responses for each step
        no_channel = Mock(status_code=200, json=Mock(return_value={"config_list": []}))
        channel_created = Mock(status_code=200, json=Mock(return_value={"config_id": "ch_123"}))
        no_monitor = Mock(status_code=200, json=Mock(return_value={"hits": {"total": {"value": 0}}}))
        monitor_created = Mock(status_code=200, json=Mock(return_value={"_id": "mon_456"}))
        no_template = Mock(status_code=404)
        template_created = Mock(status_code=200)
        no_role = Mock(status_code=404)
        role_created = Mock(status_code=200)

        # Configure mock session
        mock_session = create_mock_session()
        mock_session.get.side_effect = [no_channel, no_template, no_role]
        mock_session.post.side_effect = [channel_created, no_monitor, monitor_created]
        mock_session.put.side_effect = [template_created, role_created]
        mock_requests.Session.return_value = mock_session

        # ACT
        client = OpenSearchClient()
        channel_result = client.create_notification_channel("new_tenant", "https://webhook.url")
        monitor_result = client.create_tenant_monitor("new_tenant", channel_result["config_id"])
        template_result = client.create_tenant_index_template("new_tenant")
        role_result = client.create_tenant_role("new_tenant")

        # ASSERT
        assert channel_result["config_id"] == "ch_123"
        assert monitor_result == "mon_456"
        assert template_result is True
        assert role_result is True
