"""Database engine and session management.

Owns the engine for the whole application. The legacy ``utils.database``
module re-exports ``engine`` / ``SessionLocal`` / ``get_db`` from here so the
test-suite's ``dependency_overrides[get_db]`` applies to both legacy and v1
routes (same function identity).

Pooling: ``NullPool`` while testing (matches the per-test engine fixtures),
sane ``QueuePool`` sizing otherwise.
"""

from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import settings


def _normalize_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def build_engine(database_url: str | None = None) -> Engine:
    url = _normalize_url(database_url or settings.database_url)
    if settings.is_testing:
        return create_engine(url, poolclass=NullPool, future=True)
    return create_engine(
        url,
        poolclass=QueuePool,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )


engine: Engine = build_engine()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


@event.listens_for(Engine, "connect")
def _set_search_path(dbapi_connection: Any, _: Any) -> None:  # pragma: no cover
    """Placeholder hook for per-connection tuning (kept intentionally small)."""
    return None


def get_db() -> Generator[Session, None, None]:
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
