"""Aggregates all v1 routers under ``/api/v1``."""

from fastapi import APIRouter

from app.api.v1 import auth

api_v1_router = APIRouter()
api_v1_router.include_router(auth.router, prefix="/v1")
