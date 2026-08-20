from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class SSLResult(Base):

    __tablename__ = "ssl_results"

    id = Column(Integer, primary_key=True)

    subdomain_id = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    issuer = Column(String)

    tls_version = Column(String)

    cipher = Column(String)

    expires_at = Column(DateTime)

    self_signed = Column(Boolean)

    risk_level = Column(String)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    subdomain = relationship(
        "Subdomain",
        back_populates="ssl_results"
    )