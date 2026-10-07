class PrivacydError(Exception):
    """Base class. Messages must never contain request content."""

    code = "privacy_engine_error"


class ConfigError(PrivacydError):
    code = "config_error"


class SecretLeakError(PrivacydError):
    """A secret value was about to be persisted or emitted."""

    code = "secret_leak_blocked"


class TeacherError(PrivacydError):
    code = "teacher_failure"


class InvalidRequestError(PrivacydError):
    code = "invalid_request"
