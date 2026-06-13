"""zyxelctl — a small client for the Zyxel router web configurator.

Currently supports logging in and managing port-forward rules.
"""

from .client import (
    LoginError,
    RuleNotFoundError,
    ZyxelError,
    ZyxelRouter,
)

__version__ = "0.2.0"

__all__ = [
    "ZyxelRouter",
    "ZyxelError",
    "LoginError",
    "RuleNotFoundError",
    "__version__",
]
