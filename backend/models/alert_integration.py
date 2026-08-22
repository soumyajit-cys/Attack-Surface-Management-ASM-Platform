from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
    Text,
    Enum as SQLEnum,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class AlertChannel(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    EMAIL = "email"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertIntegration(Base):

    __tablename__ = "alert_integrations"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String, nullable=False)

    channel = Column(
        SQLEnum(AlertChannel),
        nullable=False,
    )

    webhook_url = Column(String, nullable=False)

    secret = Column(String, nullable=True)

    min_severity = Column(
        SQLEnum(AlertSeverity),
        default=AlertSeverity.HIGH,
        nullable=False,
    )

    is_active = Column(Boolean, default=True, nullable=False)

    last_triggered_at = Column(DateTime(timezone=True), nullable=True)

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

    organization = relationship("Organization")
    creator = relationship("User", foreign_keys=[created_by])


class EmailDigestConfig(Base):

    __tablename__ = "email_digest_configs"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )

    frequency = Column(String, default="weekly", nullable=False)

    day_of_week = Column(Integer, default=1, nullable=False)

    hour_utc = Column(Integer, default=9, nullable=False)

    recipient_emails = Column(Text, nullable=False)

    min_severity = Column(
        SQLEnum(AlertSeverity),
        default=AlertSeverity.MEDIUM,
        nullable=False,
    )

    is_active = Column(Boolean, default=False, nullable=False)

    last_sent_at = Column(DateTime(timezone=True), nullable=True)

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

    organization = relationship("Organization")
    creator = relationship("User", foreign_keys=[created_by])