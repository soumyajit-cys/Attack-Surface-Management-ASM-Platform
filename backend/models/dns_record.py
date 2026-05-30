from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime
)

from sqlalchemy.sql import func

from models.base import Base


class DNSRecord(Base):

    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True)

    domain_id = Column(
        Integer,
        ForeignKey("domains.id")
    )

    record_type = Column(String)

    value = Column(String)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )