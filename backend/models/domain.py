from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey
)

from sqlalchemy.orm import relationship

from models.base import Base


class Domain(Base):

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id")
    )

    domain = Column(String, unique=True)

    registrar = Column(String)

    asn = Column(String)

    hosting_provider = Column(String)

    asset = relationship("Asset")







    