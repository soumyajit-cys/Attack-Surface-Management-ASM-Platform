from sqlalchemy import (
    Column,
    Integer,
    ForeignKey,
    DateTime,
    JSON
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class AssetSnapshot(Base):

    __tablename__ = "asset_snapshots"

    id = Column(Integer, primary_key=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        index=True
    )

    snapshot = Column(JSON)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    asset = relationship(
        "Asset",
        back_populates="snapshots"
    )