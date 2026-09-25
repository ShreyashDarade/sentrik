"""Security check framework and built-in checks."""

# Import built-ins so they self-register on package import.
from app.checks import bola as bola
from app.checks import business_logic as business_logic
from app.checks import flow as flow
from app.checks import headers as headers
from app.checks import llm_redteam as llm_redteam
from app.checks import open_redirect as open_redirect
from app.checks import sqli as sqli
from app.checks import xss as xss
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
