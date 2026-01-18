"""
test_utils.py - Tests for core/utils.py
=======================================

This is the simplest test file because utils.py has pure functions
that don't call external APIs - no mocking needed!

HOW TO READ A TEST:
-------------------
Each test function follows the "AAA" pattern:
    1. ARRANGE - Set up the test data
    2. ACT     - Call the function being tested
    3. ASSERT  - Verify the result is what we expect

TEST NAMING CONVENTION:
-----------------------
test_<function_name>_<scenario>_<expected_result>

Example: test_validate_tenant_name_with_valid_input_returns_true
         ^^^^                    ^^^^^^^^^^^^^^^  ^^^^^^^^^^^^
         prefix                  scenario         expected result
"""
import pytest
from core.utils import validate_tenant_name, str_to_bool


# =============================================================================
# TESTS FOR: validate_tenant_name()
# =============================================================================

class TestValidateTenantName:
    """
    Group related tests in a class for better organization.
    The class name should start with 'Test'.
    """

    def test_valid_alphanumeric_name_returns_true(self):
        """Valid tenant names should return True."""
        # ARRANGE: Define valid inputs
        valid_names = [
            "tenant1",
            "my_tenant",
            "my-tenant",
            "Tenant_123",
            "a",  # single character
            "UPPERCASE",
            "MixedCase123",
        ]

        # ACT & ASSERT: Each valid name should return True
        for name in valid_names:
            result = validate_tenant_name(name)
            assert result is True, f"Expected True for '{name}', got {result}"

    def test_invalid_name_with_spaces_returns_false(self):
        """Names with spaces should be rejected."""
        # ARRANGE
        invalid_name = "my tenant"

        # ACT
        result = validate_tenant_name(invalid_name)

        # ASSERT
        assert result is False

    def test_invalid_name_with_special_chars_returns_false(self):
        """Names with special characters should be rejected."""
        invalid_names = [
            "tenant@123",
            "tenant!name",
            "tenant.name",
            "tenant/name",
            "tenant\\name",
            "tenant;drop table",  # SQL injection attempt
            "<script>alert('xss')</script>",  # XSS attempt
        ]

        for name in invalid_names:
            result = validate_tenant_name(name)
            assert result is False, f"Expected False for '{name}', got {result}"

    def test_empty_string_returns_false(self):
        """Empty strings should be rejected."""
        result = validate_tenant_name("")
        assert result is False

    def test_none_input_raises_error(self):
        """
        Passing None should raise an error.

        pytest.raises() is used to verify that an exception is raised.
        """
        with pytest.raises(TypeError):
            validate_tenant_name(None)


# =============================================================================
# TESTS FOR: str_to_bool()
# =============================================================================

class TestStrToBool:
    """Tests for the str_to_bool helper function."""

    def test_true_values_return_true(self):
        """Various 'truthy' strings should return True."""
        true_values = ["true", "True", "TRUE", "1", "yes", "Yes", "YES"]

        for value in true_values:
            result = str_to_bool(value)
            assert result is True, f"Expected True for '{value}'"

    def test_false_values_return_false(self):
        """Various 'falsy' strings should return False."""
        false_values = ["false", "False", "FALSE", "0", "no", "No", "NO", "", "random"]

        for value in false_values:
            result = str_to_bool(value)
            assert result is False, f"Expected False for '{value}'"

    def test_non_string_input_is_converted(self):
        """Non-string inputs should be converted to string first."""
        # The function does str(value).lower()
        assert str_to_bool(1) is True  # "1" -> True
        assert str_to_bool(0) is False  # "0" -> False


# =============================================================================
# PARAMETRIZED TESTS (Advanced - but very useful!)
# =============================================================================

@pytest.mark.parametrize("input_name,expected", [
    ("valid_tenant", True),
    ("tenant-123", True),
    ("UPPERCASE", True),
    ("has space", False),
    ("special@char", False),
    ("", False),
])
def test_validate_tenant_name_parametrized(input_name, expected):
    """
    PARAMETRIZED TEST: Run the same test with different inputs.

    @pytest.mark.parametrize creates multiple test cases from one function.
    This is equivalent to writing 6 separate tests!

    The decorator takes:
    - A string with comma-separated parameter names: "input_name,expected"
    - A list of tuples with the actual values for each test case
    """
    result = validate_tenant_name(input_name)
    assert result == expected
