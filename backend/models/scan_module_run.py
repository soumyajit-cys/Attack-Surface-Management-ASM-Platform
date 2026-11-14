from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
)

from sqlalchemy.sql import func

from models.base import Base


class ScanModuleRun(Base):

    __tablename__ = "scan_module_runs"

    id = Column(Integer, primary_key=True)

    scan_id = Column(
        Integer,
        ForeignKey("scan_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    module = Column(String, nullable=False)

    host = Column(String, nullable=False)

    status = Column(String, nullable=False)

    truncated = Column(Boolean, server_default="false", nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )