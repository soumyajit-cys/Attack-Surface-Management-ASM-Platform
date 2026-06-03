from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    ForeignKey,
    DateTime
)

from sqlalchemy.sql import func

from models.base import Base


class Finding(Base):

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id")
    )

    title = Column(String)

    severity = Column(String)

    category = Column(String)

    description = Column(Text)

    recommendation = Column(Text)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    