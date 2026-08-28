from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class Asset(Base):

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    name = Column(String, nullable=False)

    criticality = Column(String, default="dev", nullable=False)

    exposure = Column(String, default="internet", nullable=False)

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
        back_populates="assets"
    )

    domains = relationship(
        "Domain",
        back_populates="asset",
        cascade="all, delete-orphan"
    )

    findings = relationship(
        "Finding",
        back_populates="asset",
        cascade="all, delete-orphan"
    )

    risk_scores = relationship(
        "RiskScore",
        back_populates="asset",
        cascade="all, delete-orphan"
    )

    snapshots = relationship(
        "AssetSnapshot",
        back_populates="asset",
        cascade="all, delete-orphan"
    )

    scan_history = relationship(
        "ScanHistory",
        back_populates="asset"
    )

    scan_policies = relationship(
        "ScanPolicy",
        back_populates="asset",
        cascade="all, delete-orphan"
    )