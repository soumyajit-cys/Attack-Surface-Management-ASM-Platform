from sqlalchemy import Column, Integer, String, Boolean
from models.base import Base


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    username = Column(String, unique=True, nullable=False)

    email = Column(String, unique=True, nullable=False)

    password_hash = Column(String, nullable=False)

    role = Column(String, default="viewer")

    is_active = Column(Boolean, default=True)