from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ScanPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    asset_id: int
    frequency: str = Field(default="weekly", pattern="^(daily|weekly|monthly|custom_cron)$")
    cron_expression: Optional[str] = Field(default=None, max_length=100)
    scope: str = Field(default="full", pattern="^(passive|active|full)$")


class ScanPolicyUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    frequency: Optional[str] = Field(default=None, pattern="^(daily|weekly|monthly|custom_cron)$")
    cron_expression: Optional[str] = Field(default=None, max_length=100)
    scope: Optional[str] = Field(default=None, pattern="^(passive|active|full)$")
    is_active: Optional[bool] = None


class ScanPolicyResponse(BaseModel):
    id: int
    organization_id: int
    asset_id: int
    name: str
    frequency: str
    cron_expression: Optional[str]
    scope: str
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    created_by: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True