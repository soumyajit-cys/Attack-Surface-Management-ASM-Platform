from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    Table,
)

from sqlalchemy.sql import func

from models.base import Base


subdomain_ips = Table(
    "subdomain_ips",
    Base.metadata,
    Column(
        "subdomain_id",
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "ip_address",
        String(45),
        primary_key=True,
    ),
    Column(
        "created_at",
        DateTime(timezone=True),
        server_default=func.now(),
    ),
)