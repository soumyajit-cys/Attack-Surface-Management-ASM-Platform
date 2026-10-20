from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    ForeignKey,
    DateTime,
    Index
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class AuditLog(Base):

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    actor = Column(String)

    action = Column(String)

    ip_address = Column(String(64), nullable=True)

    details = Column(Text)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    # Indexes backing the audit-log viewer's filters (migration
    # e5f6a7b8c9d1): composite org+time for the default page query, plus
    # single-column action / ip_address filters.
    __table_args__ = (
        Index("ix_audit_logs_org_created", "organization_id", "created_at"),
    )

    organization = relationship(
        "Organization",
        back_populates="audit_logs"
    )