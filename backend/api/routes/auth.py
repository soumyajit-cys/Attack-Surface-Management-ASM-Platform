from fastapi import APIRouter

from schemas.auth import (
    RegisterRequest,
    LoginRequest
)

from auth.security import hash_password

from auth.jwt import create_access_token

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


@router.post("/register")

async def register(
    data: RegisterRequest
):

    password = hash_password(data.password)

    return {
        "message": "registered"
    }


@router.post("/login")

async def login(
    data: LoginRequest
):

    token = create_access_token(
        {"sub": data.username}
    )

    return {
        "access_token": token
    }