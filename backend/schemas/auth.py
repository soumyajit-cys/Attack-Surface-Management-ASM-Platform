from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    organization: str = Field(min_length=2, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MfaChallenge(BaseModel):
    """Password-OK response for 2FA users: no usable credential inside."""

    mfa_required: Literal[True] = True
    challenge: str


class RestrictedToken(BaseModel):
    """Limited-scope token for forced enrollment (scope='enroll_2fa')."""

    scope: Literal["enroll_2fa"]
    token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str
    access_token: str | None = None


class UnlockAccountRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)


class EnrollRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str | None = Field(default=None, min_length=6, max_length=32)


class ConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class ReauthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=32)


class Login2FARequest(BaseModel):
    challenge: str = Field(min_length=1)
    code: str = Field(min_length=1, max_length=32)


class Reset2FARequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)