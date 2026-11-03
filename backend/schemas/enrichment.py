"""Schemas for enrichment provider management (Phase 2.1).

The API key is *never* returned by any response and never logged.
``has_key`` reports only whether a key is configured.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional


class EnrichmentProviderResponse(BaseModel):
    """Public view of a provider: key presence + active state only."""

    name: str
    provider_type: str
    has_key: bool
    is_active: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class EnrichmentProviderUpsert(BaseModel):
    """Request to set/rotate a provider's encrypted key and active flag."""

    provider_type: str = Field(min_length=1, max_length=64)
    api_key: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Plaintext API key. Omit to leave the existing key unchanged.",
    )
    is_active: bool = True
    acknowledge_data_sharing: bool = Field(
        default=False,
        description="Must be true to enable any third-party provider "
        "(data leaves the platform). Required when is_active=true.",
    )


class EnrichmentProviderList(BaseModel):
    items: list[EnrichmentProviderResponse]
