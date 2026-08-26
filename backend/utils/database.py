"""Legacy database module -- kept as a re-export shim during the rewrite.

Re-exports the *same objects* from :mod:`app.db.session` so dependency
overrides in tests apply uniformly to legacy and v1 routes.
"""

from app.db.session import (  # noqa: F401
    SessionLocal,
    build_engine,
    engine,
    get_db,
)
