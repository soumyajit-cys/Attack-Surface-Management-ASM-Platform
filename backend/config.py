"""Legacy config module -- kept as a re-export shim during the rewrite.

All settings now live in :mod:`app.core.config` (validated, fail-fast).
Importing ``settings`` from here keeps every existing module and test
working against the single validated instance.
"""

from app.core.config import (  # noqa: F401
    ConfigError,
    Settings,
    get_settings,
    settings,
)
