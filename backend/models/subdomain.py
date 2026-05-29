from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey
)

from models.base import Base


class Subdomain(Base):

    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True)

    domain_id = Column(
        Integer,
        ForeignKey("domains.id")
    )

    subdomain = Column(String)

    ip_address = Column(String)

    source = Column(String)



    