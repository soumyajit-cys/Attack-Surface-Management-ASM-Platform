from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey
)

from models.base import Base


class Port(Base):

    __tablename__ = "ports"

    id = Column(Integer, primary_key=True)

    subdomain_id = Column(
        Integer,
        ForeignKey("subdomains.id")
    )

    port = Column(Integer)

    service = Column(String)

    protocol = Column(String)

    status = Column(String)


    