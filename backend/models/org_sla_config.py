from sqlalchemy import (
    Column,
    Integer,
    ForeignKey,
)

from models.base import Base


class OrgSlaConfig(Base):

    __tablename__ = "org_sla_config"

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )

    critical_days = Column(Integer, server_default="7", nullable=False)

    high_days = Column(Integer, server_default="14", nullable=False)

    medium_days = Column(Integer, server_default="30", nullable=False)

    low_days = Column(Integer, server_default="90", nullable=False)