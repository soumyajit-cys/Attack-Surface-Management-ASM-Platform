from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    ForeignKey,
    DateTime
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class Finding(Base):

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    asset_id = Column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    title = Column(String, nullable=False)

    severity = Column(String, nullable=False)

    category = Column(String)

    description = Column(Text)

    recommendation = Column(Text)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    organization = relationship(
        "Organization",
        back_populates="findings"
    )

    asset = relationship(
        "Asset",
        back_populates="findings"
    )