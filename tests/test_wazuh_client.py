"""
test_wazuh_client.py - Tests for core/wazuh_client.py
=====================================================

This file demonstrates MOCKING - the key technique for testing code
that makes external API calls.

KEY CONCEPTS:
-------------
1. @patch: Decorator that replaces a function/object with a mock
2. Mock objects: Fake objects we control completely
3. side_effect: Make a mock return different values on each call
4. assert_called_with: Verify the mock was called with specific arguments

IMPORTANT - WHERE TO PATCH:
---------------------------
You patch where the function is USED, not where it's DEFINED.

Example:
    # wazuh_client.py imports requests and uses requests.get()
    import requests
    response = requests.get(url)

    # In tests, we patch 'core.wazuh_client.requests' (where it's used)
    # NOT 'requests' (where it's defined)
    @patch('core.wazuh_client.requests')
"""
import pytest
from unittest.mock import patch, Mock
from core.wazuh_client import WazuhClient
from core.exceptions import WazuhAPIError, ConfigurationError


# =============================================================================
# TESTS FOR: WazuhClient initialization and authentication
# =============================================================================

class TestWazuhClientInit:
    """Tests for WazuhClient.__init__() and authenticate()."""

    @patch('core.wazuh_client.requests')
    def test_successful_authentication(
        self,
        mock_requests,  # This is the patched 'requests' module
        mock_env_vars,  # Fixture from conftest.py
        mock_wazuh_auth_success,  # Fixture: fake 200 response with token
        mock_wazuh_version  # Fixture: fake version response
    ):
        """
        Test that WazuhClient authenticates successfully and stores the token.

        WHAT WE'RE TESTING:
        - Client calls the auth endpoint
        - Client extracts and stores the token from response
        - Client sets up headers with the token
        """
        # ARRANGE: Configure mock to return our fake responses
        # side_effect lets us return different responses for sequential calls
        mock_requests.get.side_effect = [
            mock_wazuh_auth_success,  # 1st call: authenticate()
            mock_wazuh_version  # 2nd call: _get_wazuh_version()
        ]

        # ACT: Create the client (this triggers __init__ -> authenticate)
        client = WazuhClient()

        # ASSERT: Verify our code handled the response correctly
        assert client.token == "fake_jwt_token_for_testing"
        assert "Authorization" in client.headers
        assert client.headers["Authorization"] == "Bearer fake_jwt_token_for_testing"
        assert client.version == "4.10.x"  # "4.10.1" -> "4.10.x"

    @patch('core.wazuh_client.requests')
    def test_authentication_failure_raises_error(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_failure  # Fixture: fake 401 response
    ):
        """
        Test that invalid credentials raise WazuhAPIError.

        WHAT WE'RE TESTING:
        - When API returns 401, our code raises WazuhAPIError
        - The error message is helpful
        """
        # ARRANGE: Configure mock to return 401
        mock_requests.get.return_value = mock_wazuh_auth_failure

        # ACT & ASSERT: Verify exception is raised
        with pytest.raises(WazuhAPIError) as exc_info:
            WazuhClient()

        # Verify the error message contains useful info
        assert "Invalid credentials" in str(exc_info.value)

    @patch('core.wazuh_client.requests')
    def test_connection_error_raises_wazuh_api_error(
        self,
        mock_requests,
        mock_env_vars
    ):
        """
        Test that connection failures are handled gracefully.

        WHAT WE'RE TESTING:
        - When server is unreachable, our code catches the error
        - It raises our custom WazuhAPIError (not raw ConnectionError)
        """
        # ARRANGE: Make requests.get() raise ConnectionError
        mock_requests.get.side_effect = ConnectionError("Connection refused")
        mock_requests.exceptions.ConnectionError = ConnectionError

        # ACT & ASSERT
        with pytest.raises(WazuhAPIError) as exc_info:
            WazuhClient()

        assert "Failed to connect" in str(exc_info.value)


# =============================================================================
# TESTS FOR: create_group() with idempotency
# =============================================================================

class TestCreateGroup:
    """Tests for WazuhClient.create_group()."""

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
        """
        Test creating a group that doesn't exist yet.

        FLOW BEING TESTED:
        1. _group_exists() checks -> returns False (group not found)
        2. create_group() makes POST request
        3. Returns success response
        """
        # ARRANGE
        mock_requests.get.side_effect = [
            mock_wazuh_auth_success,  # authenticate()
            mock_wazuh_version,  # _get_wazuh_version()
            mock_wazuh_group_not_found  # _group_exists() check
        ]
        mock_requests.post.return_value = mock_wazuh_group_created

        # ACT
        client = WazuhClient()
        result = client.create_group("test_tenant")

        # ASSERT
        assert result["data"]["total_affected_items"] == 1
        # Verify POST was called (group was created)
        mock_requests.post.assert_called_once()

    @patch('core.wazuh_client.requests')
    def test_create_group_skips_when_exists(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success,
        mock_wazuh_version,
        mock_wazuh_group_exists  # Group already exists
    ):
        """
        Test idempotency: existing group is not recreated.

        FLOW BEING TESTED:
        1. _group_exists() checks -> returns True (group found)
        2. create_group() skips creation
        3. Returns {"already_exists": True}
        """
        # ARRANGE
        mock_requests.get.side_effect = [
            mock_wazuh_auth_success,
            mock_wazuh_version,
            mock_wazuh_group_exists  # _group_exists() finds the group
        ]

        # ACT
        client = WazuhClient()
        result = client.create_group("test_tenant")

        # ASSERT
        assert result["already_exists"] is True
        # Verify POST was NOT called (no creation attempted)
        mock_requests.post.assert_not_called()

    @patch('core.wazuh_client.requests')
    def test_create_group_api_error_raises_exception(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success,
        mock_wazuh_version,
        mock_wazuh_group_not_found
    ):
        """
        Test that API errors during creation raise WazuhAPIError.
        """
        # ARRANGE
        mock_requests.get.side_effect = [
            mock_wazuh_auth_success,
            mock_wazuh_version,
            mock_wazuh_group_not_found
        ]
        # Simulate API error on POST
        error_response = Mock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"
        mock_requests.post.return_value = error_response

        # ACT & ASSERT
        client = WazuhClient()
        with pytest.raises(WazuhAPIError) as exc_info:
            client.create_group("test_tenant")

        assert "Failed to create group" in str(exc_info.value)
        assert "500" in str(exc_info.value)


# =============================================================================
# TESTS FOR: API_SPEC version handling
# =============================================================================

class TestApiSpecVersionHandling:
    """Tests for version-specific API behavior."""

    @patch('core.wazuh_client.requests')
    def test_version_detection_normalizes_to_minor(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success
    ):
        """
        Test that "4.10.1" is normalized to "4.10.x" for API_SPEC lookup.
        """
        # ARRANGE: Return version "4.10.1"
        version_response = Mock()
        version_response.status_code = 200
        version_response.json.return_value = {"data": {"version": "4.10.1"}}

        mock_requests.get.side_effect = [
            mock_wazuh_auth_success,
            version_response
        ]

        # ACT
        client = WazuhClient()

        # ASSERT: Should be normalized to "4.10.x"
        assert client.version == "4.10.x"

    @patch('core.wazuh_client.requests')
    def test_unknown_version_falls_back_to_default(
        self,
        mock_requests,
        mock_env_vars,
        mock_wazuh_auth_success
    ):
        """
        Test that unknown versions fall back to 'default' in API_SPEC.
        """
        # ARRANGE: Return version that's not in API_SPEC
        version_response = Mock()
        version_response.status_code = 200
        version_response.json.return_value = {"data": {"version": "99.99.99"}}

        mock_requests.get.side_effect = [
            mock_wazuh_auth_success,
            version_response
        ]

        # ACT
        client = WazuhClient()

        # ASSERT: Version is set, and API_SPEC will use "default"
        assert client.version == "99.99.x"


# =============================================================================
# TESTS FOR: Configuration errors
# =============================================================================

class TestConfigurationErrors:
    """Tests for configuration-related error handling."""

    @patch('core.wazuh_client.requests')
    def test_missing_api_spec_raises_configuration_error(
        self,
        mock_requests,
        mock_env_vars
    ):
        """
        Test that missing API_SPEC.json raises ConfigurationError.

        NOTE: We use a more targeted patch here. Patching builtins.open
        globally would break other code (like load_dotenv).
        Instead, we patch the specific method that opens the file.
        """
        # ARRANGE: Patch only the _load_api_spec method to raise the error
        with patch.object(
            WazuhClient,
            '_load_api_spec',
            side_effect=ConfigurationError("Required config file not found: API_SPEC.json")
        ):
            # ACT & ASSERT
            with pytest.raises(ConfigurationError) as exc_info:
                WazuhClient()

            assert "not found" in str(exc_info.value)
