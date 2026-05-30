from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime
)

from sqlalchemy.sql import func

from models.base import Base


class ScanHistory(Base):

    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True)

    target = Column(String)

    status = Column(String)

    started_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


    