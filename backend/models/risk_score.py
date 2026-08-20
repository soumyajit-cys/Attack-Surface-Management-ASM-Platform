from sqlalchemy import (
    Column,
    Integer,
    Float,
    ForeignKey,
    DateTime
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class RiskScore(Base):

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    score = Column(Float)

    exposure = Column(Float)

    severity = Column(Float)

    confidence = Column(Float)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    asset = relationship(
        "Asset",
        back_populates="risk_scores"
    )