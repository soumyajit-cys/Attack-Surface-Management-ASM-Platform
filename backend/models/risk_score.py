from sqlalchemy import (
    Column,
    Integer,
    ForeignKey,
    Float
)

from models.base import Base


class RiskScore(Base):

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id")
    )

    score = Column(Float)

    exposure = Column(Float)

    severity = Column(Float)

    confidence = Column(Float)


    