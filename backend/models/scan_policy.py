from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
    Enum as SQLEnum,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class ScanScope(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    FULL = "full"


class ScanFrequency(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM_CRON = "custom_cron"


class ScanPolicy(Base):

    __tablename__ = "scan_policies"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    asset_id = Column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String, nullable=False)

    frequency = Column(
        SQLEnum(ScanFrequency),
        default=ScanFrequency.WEEKLY,
        nullable=False,
    )

    cron_expression = Column(String, nullable=True)

    scope = Column(
        SQLEnum(ScanScope),
        default=ScanScope.FULL,
        nullable=False,
    )

    is_active = Column(Boolean, default=True, nullable=False)

    last_run_at = Column(DateTime(timezone=True), nullable=True)

    next_run_at = Column(DateTime(timezone=True), nullable=True)

    created_by = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    organization = relationship("Organization", back_populates="scan_policies")
    asset = relationship("Asset", back_populates="scan_policies")
    creator = relationship("User", foreign_keys=[created_by])