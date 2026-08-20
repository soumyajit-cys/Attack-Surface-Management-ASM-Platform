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


class Domain(Base):

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    asset_id = Column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        index=True
    )

    domain = Column(String, unique=True, nullable=False)

    registrar = Column(String)

    asn = Column(String)

    hosting_provider = Column(String)

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
        back_populates="assets",
        overlaps="assets"
    )

    asset = relationship(
        "Asset",
        back_populates="domains"
    )

    subdomains = relationship(
        "Subdomain",
        back_populates="domain",
        cascade="all, delete-orphan"
    )

    dns_records = relationship(
        "DNSRecord",
        back_populates="domain",
        cascade="all, delete-orphan"
    )