from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from app.core.crypto import EncryptedText
from models.base import Base


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    username = Column(String, unique=True, nullable=False)

    email = Column(String, unique=True, nullable=False)

    password_hash = Column(String, nullable=False)

    role = Column(String, default="viewer", nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    # TOTP 2FA (Phase 1.5.4). totp_secret is EncryptedText at the app layer;
    # pending secrets (enabled=False) activate only after /confirm.
    totp_secret = Column(EncryptedText, nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_last_step = Column(BigInteger, nullable=True)

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
        back_populates="users"
    )