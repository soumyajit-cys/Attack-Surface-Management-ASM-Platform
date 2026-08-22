import secrets
from datetime import datetime, timedelta, timezone
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


class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Invitation(Base):

    __tablename__ = "invitations"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    email = Column(String, nullable=False, index=True)

    role = Column(String, default="viewer", nullable=False)

    token = Column(String, unique=True, nullable=False, index=True)

    status = Column(
        SQLEnum(InvitationStatus),
        default=InvitationStatus.PENDING,
        nullable=False,
    )

    invited_by = Column(
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

    expires_at = Column(DateTime(timezone=True), nullable=False)

    accepted_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship(
        "Organization",
        back_populates="invitations"
    )

    inviter = relationship("User", foreign_keys=[invited_by])


class APIKey(Base):

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String, nullable=False)

    key_hash = Column(String, unique=True, nullable=False, index=True)

    key_prefix = Column(String, nullable=False)

    scopes = Column(String, default="read", nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    last_used_at = Column(DateTime(timezone=True), nullable=True)

    expires_at = Column(DateTime(timezone=True), nullable=True)

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

    organization = relationship(
        "Organization",
        back_populates="api_keys"
    )

    creator = relationship("User", foreign_keys=[created_by])

    @staticmethod
    def generate_key() -> tuple[str, str]:
        prefix = "sk"
        random_part = secrets.token_urlsafe(32)
        full_key = f"{prefix}_{random_part}"
        key_hash = secrets.token_urlsafe(32)
        return full_key, key_hash


Organization.invitations = relationship(
    "Invitation",
    back_populates="organization",
    cascade="all, delete-orphan"
)

Organization.api_keys = relationship(
    "APIKey",
    back_populates="organization",
    cascade="all, delete-orphan"
)