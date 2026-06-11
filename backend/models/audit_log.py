from sqlalchemy import (
    Column,
    Integer,
    String,
    Text
)

from models.base import Base


class AuditLog(Base):

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)

    actor = Column(String)

    action = Column(String)

    details = Column(Text)


    