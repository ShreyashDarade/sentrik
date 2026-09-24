"""Security check framework and built-in checks."""

# Import built-ins so they self-register on package import.
from app.checks import (  # noqa: F401
    bola,
    business_logic,
    headers,
    open_redirect,
    sqli,
    xss,
)
from app.checks.base import (
    BaseCheck,
    CheckContext,
    CheckError,
    RawEvidence,
    RawFinding,
    registry,
)

__all__ = [
    "BaseCheck",
    "CheckContext",
    "CheckError",
    "RawEvidence",
    "RawFinding",
    "registry",
]
