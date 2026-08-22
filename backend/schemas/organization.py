from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)


class OrganizationResponse(BaseModel):
    id: int
    name: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class InvitationCreate(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class InvitationResponse(BaseModel):
    id: int
    organization_id: int
    email: str
    role: str
    status: str
    invited_by: Optional[int]
    created_at: datetime
    expires_at: datetime
    accepted_at: Optional[datetime]

    class Config:
        from_attributes = True


class InvitationAccept(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class APIKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    scopes: str = Field(default="read", pattern="^(read|write|admin|read,write|read,admin|write,admin|read,write,admin)$")
    expires_days: Optional[int] = Field(default=None, ge=1, le=3650)


class APIKeyResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    key_prefix: str
    scopes: str
    is_active: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_by: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreatedResponse(APIKeyResponse):
    key: str


class APIKeyUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    scopes: Optional[str] = Field(default=None, pattern="^(read|write|admin|read,write|read,admin|write,admin|read,write,admin)$")
    is_active: Optional[bool] = None