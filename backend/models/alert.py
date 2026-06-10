from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime
)

from sqlalchemy.sql import func

from models.base import Base


class Alert(Base):

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)

    title = Column(String)

    severity = Column(String)

    message = Column(Text)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    read = Column(Integer, default=0)

    