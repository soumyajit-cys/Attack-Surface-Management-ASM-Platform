from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    Float,
    UniqueConstraint,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class AssetTechnology(Base):

    __tablename__ = "asset_technologies"

    __table_args__ = (
        UniqueConstraint(
            "subdomain_id",
            "name",
            name="uq_asset_technologies_subdomain_name",
        ),
    )

    id = Column(Integer, primary_key=True)

    subdomain_id = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String, nullable=False)

    category = Column(String)

    version = Column(String)

    confidence = Column(Float)

    matched_pattern = Column(String)

    status_code = Column(Integer)

    first_seen = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    last_seen = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    subdomain = relationship(
        "Subdomain",
        back_populates="asset_technologies",
    )