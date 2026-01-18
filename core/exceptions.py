class OrchestratorError(Exception):
    """Base class for all exceptions in this project."""
    pass

class WazuhAPIError(OrchestratorError):
    """Raised when Wazuh API returns an error or is unreachable."""
    pass

class OpenSearchAPIError(OrchestratorError):
    """Raised when OpenSearch API returns an error or is unreachable."""
    pass

class ConfigurationError(OrchestratorError):
    """Raised when there are issues with .env or API_SPEC.json."""
    pass