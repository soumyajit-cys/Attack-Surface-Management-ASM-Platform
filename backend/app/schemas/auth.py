"""v1 API schemas."""

from pydantic import BaseModel, EmailStr, Field

from app.core.permissions import Permission


class UserOut(BaseModel):

    id: int
    username: str
    email: EmailStr
    role: str
    organization_id: int
    organization_name: str | None = None
    permissions: list[str] = Field(default_factory=list)


class TokenBundle(BaseModel):

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


class MessageOut(BaseModel):

    message: str
