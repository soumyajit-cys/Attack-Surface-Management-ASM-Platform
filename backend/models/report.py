from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime
)

from sqlalchemy.sql import func

from models.base import Base


class Report(Base):

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)

    asset_id = Column(Integer)

    filename = Column(String)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )