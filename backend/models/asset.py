from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from models.base import Base


class Asset(Base):

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)

    organization = Column(String)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


    