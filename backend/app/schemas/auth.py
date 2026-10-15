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
    totp_enabled: bool = False


class TokenBundle(BaseModel):

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


class MfaChallenge(BaseModel):
    """Password-OK response for 2FA users: no usable credential inside."""

    mfa_required: Literal[True] = True
    challenge: str


class RestrictedToken(BaseModel):
    """Limited-scope token for forced enrollment (scope='enroll_2fa')."""

    scope: Literal["enroll_2fa"]
    token: str


class MessageOut(BaseModel):

    message: str
