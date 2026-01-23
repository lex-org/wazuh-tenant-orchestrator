import pytest
from core.utils import validate_tenant_name, str_to_bool, validate_webhook_url


class TestValidateTenantName:

    def test_valid_alphanumeric_name_returns_true(self):
        valid_names = [
            "tenant1",
            "my_tenant",
            "my-tenant",
            "Tenant_123",
            "abc",
            "UPPERCASE",
            "MixedCase123",
        ]

        for name in valid_names:
            result = validate_tenant_name(name)
            assert result is True, f"Expected True for '{name}', got {result}"

    def test_invalid_name_too_short_returns_false(self):
        short_names = ["a", "ab", ""]

        for name in short_names:
            result = validate_tenant_name(name)
            assert result is False, f"Expected False for '{name}', got {result}"

    def test_invalid_name_too_long_returns_false(self):
        long_name = "a" * 65

        result = validate_tenant_name(long_name)

        assert result is False

    def test_invalid_name_with_spaces_returns_false(self):
        invalid_name = "my tenant"

        result = validate_tenant_name(invalid_name)

        assert result is False

    def test_invalid_name_with_special_chars_returns_false(self):
        invalid_names = [
            "tenant@123",
            "tenant!name",
            "tenant.name",
            "tenant/name",
            "tenant\\name",
            "tenant;drop table",
            "<script>alert('xss')</script>",
        ]

        for name in invalid_names:
            result = validate_tenant_name(name)
            assert result is False, f"Expected False for '{name}', got {result}"

    def test_empty_string_returns_false(self):
        result = validate_tenant_name("")
        assert result is False

    def test_none_input_raises_error(self):
        with pytest.raises(TypeError):
            validate_tenant_name(None)


class TestStrToBool:

    def test_true_values_return_true(self):
        true_values = ["true", "True", "TRUE", "1", "yes", "Yes", "YES"]

        for value in true_values:
            result = str_to_bool(value)
            assert result is True, f"Expected True for '{value}'"

    def test_false_values_return_false(self):
        false_values = ["false", "False", "FALSE", "0", "no", "No", "NO", "", "random"]

        for value in false_values:
            result = str_to_bool(value)
            assert result is False, f"Expected False for '{value}'"

    def test_non_string_input_is_converted(self):
        assert str_to_bool(1) is True
        assert str_to_bool(0) is False


@pytest.mark.parametrize("input_name,expected", [
    ("valid_tenant", True),
    ("tenant-123", True),
    ("UPPERCASE", True),
    ("has space", False),
    ("special@char", False),
    ("", False),
])
def test_validate_tenant_name_parametrized(input_name, expected):
    result = validate_tenant_name(input_name)
    assert result == expected


class TestValidateWebhookUrl:

    def test_valid_https_url_returns_true(self):
        valid_urls = [
            "https://example.com/webhook",
            "https://api.example.com/v1/alerts",
            "https://localhost:8080/hook",
            "https://192.168.1.1:9000/api",
        ]

        for url in valid_urls:
            result = validate_webhook_url(url)
            assert result is True, f"Expected True for '{url}'"

    def test_valid_http_url_returns_true(self):
        valid_urls = [
            "http://localhost:8000/webhook",
            "http://127.0.0.1:5000/api",
        ]

        for url in valid_urls:
            result = validate_webhook_url(url)
            assert result is True, f"Expected True for '{url}'"

    def test_invalid_url_without_scheme_returns_false(self):
        invalid_urls = [
            "example.com/webhook",
            "www.example.com/hook",
            "ftp://example.com/file",
        ]

        for url in invalid_urls:
            result = validate_webhook_url(url)
            assert result is False, f"Expected False for '{url}'"

    def test_invalid_url_without_host_returns_false(self):
        invalid_urls = [
            "https://",
            "http://",
            "https:///path",
        ]

        for url in invalid_urls:
            result = validate_webhook_url(url)
            assert result is False, f"Expected False for '{url}'"

    def test_random_string_returns_false(self):
        invalid_inputs = [
            "not-a-url",
            "just some text",
            "",
        ]

        for input_val in invalid_inputs:
            result = validate_webhook_url(input_val)
            assert result is False, f"Expected False for '{input_val}'"
