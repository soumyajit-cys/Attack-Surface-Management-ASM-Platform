from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    UniqueConstraint,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from models.base import Base


class VerifiedDomain(Base):
    """Domain ownership verification state, per organization.

    A scan may run only when the target domain — or a parent domain — has a
    row here with status ``verified`` (and unexpired ``expires_at``), or a
    still-valid ``grandfathered`` grace row created by the Phase 1 migration
    for pre-existing assets/policies. ``grandfathered`` is surfaced
    distinctly in UI/API so it is never mistaken for ``verified``.
    """

    __tablename__ = "verified_domains"

    __table_args__ = (
        UniqueConstraint("organization_id", "domain", name="uq_verified_domains_org_domain"),
    )

    id = Column(Integer, primary_key=True)

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Normalized lowercase domain (no trailing dot). Never a public suffix.
    domain = Column(String, nullable=False)

    # Verification method: "dns_txt" or "http_file".
    method = Column(String, nullable=False)

    # pending / verified / failed / expired / grandfathered.
    status = Column(String, nullable=False, default="pending")

    # Challenge token: DNS TXT value suffix, or HTTP filename + body marker.
    token = Column(String, nullable=False)

    verified_at = Column(DateTime(timezone=True), nullable=True)

    expires_at = Column(DateTime(timezone=True), nullable=True)

    last_checked_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    organization = relationship(
        "Organization",
        back_populates="verified_domains",
    )
