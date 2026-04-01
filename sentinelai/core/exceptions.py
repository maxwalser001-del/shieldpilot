"""Custom exception hierarchy for ShieldPilot."""


class SentinelError(Exception):
    """Base exception for all ShieldPilot errors."""
    pass


class CommandBlockedError(SentinelError):
    """Raised when a command is blocked by the risk engine."""

    def __init__(self, command: str, score: int, reason: str = ""):
        self.command = command
        self.score = score
        self.reason = reason
        super().__init__(
            f"Command blocked (score={score}): {reason or command}"
        )


class ConfigError(SentinelError):
    """Raised when configuration is invalid or cannot be loaded."""
    pass


class SandboxError(SentinelError):
    """Raised when sandboxed execution fails."""
    pass


class LogIntegrityError(SentinelError):
    """Raised when log chain integrity verification fails."""

    def __init__(self, entry_id: int, expected_hash: str, actual_hash: str):
        self.entry_id = entry_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        super().__init__(
            f"Log integrity violation at entry {entry_id}: "
            f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
        )


class AuthenticationError(SentinelError):
    """Raised when authentication fails."""
    pass


class RateLimitError(SentinelError):
    """Raised when rate limits are exceeded."""

    def __init__(self, limit_type: str, limit: int):
        self.limit_type = limit_type
        self.limit = limit
        super().__init__(f"Rate limit exceeded: {limit_type} (limit: {limit})")


class PluginError(SentinelError):
    """Raised when a plugin fails to load or execute."""

    def __init__(self, plugin_name: str, reason: str):
        self.plugin_name = plugin_name
        self.reason = reason
        super().__init__(f"Plugin error [{plugin_name}]: {reason}")
