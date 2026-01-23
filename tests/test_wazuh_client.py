import pytest
from unittest.mock import patch, Mock, MagicMock
from core.wazuh_client import WazuhClient
from core.exceptions import WazuhAPIError, ConfigurationError


def create_mock_session():
    mock_session = MagicMock()
    return mock_session


class TestWazuhClientInit:

    @patch('core.wazuh_client.requests')
    def test_successful_authentication(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success,
        mock_wazuh_version
    ):
        mock_session = create_mock_session()
        mock_session.get.side_effect = [
            mock_wazuh_auth_success,
            mock_wazuh_version
        ]
        mock_requests.Session.return_value = mock_session

        client = WazuhClient()

        assert client.token == "fake_jwt_token_for_testing"
        assert "Authorization" in client.headers
        assert client.headers["Authorization"] == "Bearer fake_jwt_token_for_testing"
        assert client.version == "4.10.x"

    @patch('core.wazuh_client.requests')
    def test_authentication_failure_raises_error(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_failure
    ):
        mock_session = create_mock_session()
        mock_session.get.return_value = mock_wazuh_auth_failure
        mock_requests.Session.return_value = mock_session

        with pytest.raises(WazuhAPIError) as exc_info:
            WazuhClient()

        assert "Invalid credentials" in str(exc_info.value)

    @patch('core.wazuh_client.requests')
    def test_connection_error_raises_wazuh_api_error(
        self,
        mock_requests,
        mock_env_vars
    ):
        mock_session = create_mock_session()
        mock_session.get.side_effect = ConnectionError("Connection refused")
        mock_requests.Session.return_value = mock_session
        mock_requests.exceptions.ConnectionError = ConnectionError

        with pytest.raises(WazuhAPIError) as exc_info:
            WazuhClient()

        assert "Failed to connect" in str(exc_info.value)


class TestCreateGroup:

    @patch('core.wazuh_client.requests')
    def test_create_group_when_not_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success,
        mock_wazuh_version,
        mock_wazuh_group_not_found,
        mock_wazuh_group_created
    ):
        mock_session = create_mock_session()
        mock_session.get.side_effect = [
            mock_wazuh_auth_success,
            mock_wazuh_version,
            mock_wazuh_group_not_found
        ]
        mock_session.post.return_value = mock_wazuh_group_created
        mock_requests.Session.return_value = mock_session

        client = WazuhClient()
        result = client.create_group("test_tenant")

        assert result["data"]["total_affected_items"] == 1
        mock_session.post.assert_called_once()

    @patch('core.wazuh_client.requests')
    def test_create_group_skips_when_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success,
        mock_wazuh_version,
        mock_wazuh_group_exists
    ):
        mock_session = create_mock_session()
        mock_session.get.side_effect = [
            mock_wazuh_auth_success,
            mock_wazuh_version,
            mock_wazuh_group_exists
        ]
        mock_requests.Session.return_value = mock_session

        client = WazuhClient()
        result = client.create_group("test_tenant")

        assert result["already_exists"] is True
        mock_session.post.assert_not_called()

    @patch('core.wazuh_client.requests')
    def test_create_group_api_error_raises_exception(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success,
        mock_wazuh_version,
        mock_wazuh_group_not_found
    ):
        mock_session = create_mock_session()
        mock_session.get.side_effect = [
            mock_wazuh_auth_success,
            mock_wazuh_version,
            mock_wazuh_group_not_found
        ]
        error_response = Mock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"
        mock_session.post.return_value = error_response
        mock_requests.Session.return_value = mock_session

        client = WazuhClient()
        with pytest.raises(WazuhAPIError) as exc_info:
            client.create_group("test_tenant")

        assert "Failed to create group" in str(exc_info.value)
        assert "500" in str(exc_info.value)


class TestApiSpecVersionHandling:

    @patch('core.wazuh_client.requests')
    def test_version_detection_normalizes_to_minor(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success
    ):
        version_response = Mock()
        version_response.status_code = 200
        version_response.json.return_value = {"data": {"version": "4.10.1"}}

        mock_session = create_mock_session()
        mock_session.get.side_effect = [
            mock_wazuh_auth_success,
            version_response
        ]
        mock_requests.Session.return_value = mock_session

        client = WazuhClient()

        assert client.version == "4.10.x"

    @patch('core.wazuh_client.requests')
    def test_unknown_version_falls_back_to_default(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success
    ):
        version_response = Mock()
        version_response.status_code = 200
        version_response.json.return_value = {"data": {"version": "99.99.99"}}

        mock_session = create_mock_session()
        mock_session.get.side_effect = [
            mock_wazuh_auth_success,
            version_response
        ]
        mock_requests.Session.return_value = mock_session

        client = WazuhClient()

        assert client.version == "99.99.x"


class TestConfigurationErrors:

    @patch('core.wazuh_client.requests')
    def test_missing_api_spec_raises_configuration_error(
        self,
        mock_requests,
        mock_env_vars
    ):
        with patch.object(
            WazuhClient,
            '_load_api_spec',
            side_effect=ConfigurationError("Required config file not found: API_SPEC.json")
        ):
            with pytest.raises(ConfigurationError) as exc_info:
                WazuhClient()

            assert "not found" in str(exc_info.value)
