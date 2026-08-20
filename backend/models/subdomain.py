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


class Subdomain(Base):

    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True)

    domain_id = Column(
        Integer,
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    subdomain = Column(String, nullable=False)

    ip_address = Column(String)

    source = Column(String)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    domain = relationship(
        "Domain",
        back_populates="subdomains"
    )

    ports = relationship(
        "Port",
        back_populates="subdomain",
        cascade="all, delete-orphan"
    )

    ssl_results = relationship(
        "SSLResult",
        back_populates="subdomain",
        cascade="all, delete-orphan"
    )