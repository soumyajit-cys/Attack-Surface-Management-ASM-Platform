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


class Port(Base):

    __tablename__ = "ports"

    id = Column(Integer, primary_key=True)

    subdomain_id = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    port = Column(Integer, nullable=False)

    service = Column(String)

    protocol = Column(String)

    status = Column(String)

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
        back_populates="ports"
    )