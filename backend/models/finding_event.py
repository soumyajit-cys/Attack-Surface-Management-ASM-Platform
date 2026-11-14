from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    Text,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class FindingEvent(Base):

    __tablename__ = "finding_events"

    id = Column(Integer, primary_key=True)

    finding_id = Column(
        Integer,
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    event_type = Column(String, nullable=False)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    old_value = Column(Text, nullable=True)

    new_value = Column(Text, nullable=True)

    comment = Column(Text, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )