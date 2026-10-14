"""Single-use TOTP recovery codes (Phase 1.5.4).

Codes are 16 base32 chars (80 bits), shown once, stored as SHA-256 hex.
A fast hash is deliberate here (per decision 1.5.4.3): the codes carry
80 bits of entropy and each verification burns at most ten constant-time
comparisons, so bcrypt's cost buys nothing and would 10x the attempt cost.
"""

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func

from models.base import Base


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    code_hash = Column(String, nullable=False, unique=True)

    used_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
