from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class Organization(Base):

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)

    name = Column(String, unique=True, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    users = relationship(
        "User",
        back_populates="organization"
    )

    assets = relationship(
        "Asset",
        back_populates="organization"
    )

    findings = relationship(
        "Finding",
        back_populates="organization"
    )

    scan_history = relationship(
        "ScanHistory",
        back_populates="organization"
    )

    alerts = relationship(
        "Alert",
        back_populates="organization"
    )

    reports = relationship(
        "Report",
        back_populates="organization"
    )

    audit_logs = relationship(
        "AuditLog",
        back_populates="organization"
    )