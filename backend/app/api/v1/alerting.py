"""``/api/v1/alerting`` -- alert integrations + email digests."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from models import (
    AlertChannel,
    AlertIntegration,
    AlertSeverity,
    EmailDigestConfig,
)

from app.core.audit import record_audit
from app.core.errors import (
    AppError,
    BadRequestError,
    ConflictError,
    NotFoundError,
)
from app.core.permissions import Permission
from app.api.deps import Principal, current_principal, require_permissions_dep
from app.db.session import get_db
from utils.ssrf_guard import is_allowed_target

router = APIRouter(prefix="/alerting", tags=["alerting"])

_ALERT_ADMIN_DEP = require_permissions_dep(Permission.ALERT_MANAGE)


class AlertIntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    channel: AlertChannel
    webhook_url: HttpUrl
    secret: str | None = None
    min_severity: AlertSeverity = AlertSeverity.HIGH


class AlertIntegrationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    webhook_url: HttpUrl | None = None
    secret: str | None = None
    min_severity: AlertSeverity | None = None
    is_active: bool | None = None


class EmailDigestConfigCreate(BaseModel):
    frequency: str = Field(default="weekly", pattern="^(daily|weekly|monthly)$")
    day_of_week: int = Field(default=1, ge=0, le=6)
    hour_utc: int = Field(default=9, ge=0, le=23)
    recipient_emails: str = Field(min_length=3)
    min_severity: AlertSeverity = AlertSeverity.MEDIUM


class EmailDigestConfigUpdate(BaseModel):
    frequency: str | None = Field(default=None, pattern="^(daily|weekly|monthly)$")
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    hour_utc: int | None = Field(default=None, ge=0, le=23)
    recipient_emails: str | None = None
    min_severity: AlertSeverity | None = None
    is_active: bool | None = None


class AlertIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    channel: AlertChannel
    webhook_url: str
    min_severity: AlertSeverity
    is_active: bool
    last_triggered_at: datetime | None
    created_by: int | None
    created_at: datetime | None
    updated_at: datetime | None

    class Config:
        from_attributes = True


class EmailDigestConfigResponse(BaseModel):
    id: int
    organization_id: int
    frequency: str
    day_of_week: int
    hour_utc: int
    recipient_emails: str
    min_severity: AlertSeverity
    is_active: bool
    last_sent_at: datetime | None
    created_by: int | None
    created_at: datetime | None
    updated_at: datetime | None

    class Config:
        from_attributes = True


def _check_webhook(url: str) -> None:
    if not is_allowed_target(url):
        raise BadRequestError(
            "Webhook URL not allowed (private/cloud metadata IP)",
            code="webhook_target_not_allowed",
        )


@router.post("/integrations", response_model=AlertIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(
    request: Request,
    data: AlertIntegrationCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    _check_webhook(str(data.webhook_url))

    integration = AlertIntegration(
        organization_id=principal.organization_id,
        name=data.name,
        channel=data.channel,
        webhook_url=str(data.webhook_url),
        secret=data.secret,
        min_severity=data.min_severity,
        created_by=principal.user.id,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="alerting.integration_created",
        details={"name": data.name},
        request=request,
    )
    db.commit()

    return integration


@router.get("/integrations", response_model=list[AlertIntegrationResponse])
async def list_integrations(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    return (
        db.query(AlertIntegration)
        .filter(AlertIntegration.organization_id == principal.organization_id)
        .order_by(AlertIntegration.created_at.desc())
        .all()
    )


@router.get("/integrations/{integration_id}", response_model=AlertIntegrationResponse)
async def get_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == principal.organization_id,
    ).first()
    if not integration:
        raise NotFoundError("Integration not found", code="integration_not_found")
    return integration


@router.patch("/integrations/{integration_id}", response_model=AlertIntegrationResponse)
async def update_integration(
    integration_id: int,
    data: AlertIntegrationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == principal.organization_id,
    ).first()
    if not integration:
        raise NotFoundError("Integration not found", code="integration_not_found")

    if data.name is not None:
        integration.name = data.name
    if data.webhook_url is not None:
        _check_webhook(str(data.webhook_url))
        integration.webhook_url = str(data.webhook_url)
    if data.secret is not None:
        integration.secret = data.secret
    if data.min_severity is not None:
        integration.min_severity = data.min_severity
    if data.is_active is not None:
        integration.is_active = data.is_active

    integration.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(integration)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="alerting.integration_updated",
        details={"integration_id": integration_id},
        request=request,
    )
    db.commit()

    return integration


@router.delete("/integrations/{integration_id}")
async def delete_integration(
    integration_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == principal.organization_id,
    ).first()
    if not integration:
        raise NotFoundError("Integration not found", code="integration_not_found")

    db.delete(integration)
    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="alerting.integration_deleted",
        details={"integration_id": integration_id},
        request=request,
    )
    db.commit()

    return {"message": "Integration deleted"}


@router.post("/integrations/{integration_id}/test")
async def test_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    from models import Asset, Finding
    from services.alerts.alerting_service import (
        send_discord_alert,
        send_slack_alert,
    )

    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == principal.organization_id,
    ).first()
    if not integration:
        raise NotFoundError("Integration not found", code="integration_not_found")

    test_finding = Finding(
        organization_id=principal.organization_id,
        asset_id=1,
        title="Test Alert from SentinelASM",
        severity="high",
        category="test",
        description="This is a test alert to verify the integration is working.",
        recommendation="No action needed.",
    )
    test_asset = Asset(
        organization_id=principal.organization_id,
        name="test-asset.example.com",
    )

    success = False
    if integration.channel == AlertChannel.SLACK:
        success = await send_slack_alert(str(integration.webhook_url), test_finding, test_asset)
    elif integration.channel == AlertChannel.DISCORD:
        success = await send_discord_alert(str(integration.webhook_url), test_finding, test_asset)

    if not success:
        raise AppError(
            "Failed to send test alert",
            code="test_alert_failed",
        )

    return {"message": "Test alert sent successfully"}


@router.post("/digest", response_model=EmailDigestConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_digest_config(
    request: Request,
    data: EmailDigestConfigCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    existing = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == principal.organization_id
    ).first()
    if existing:
        raise ConflictError(
            "Digest config already exists for this organization",
            code="digest_config_exists",
        )

    config = EmailDigestConfig(
        organization_id=principal.organization_id,
        frequency=data.frequency,
        day_of_week=data.day_of_week,
        hour_utc=data.hour_utc,
        recipient_emails=data.recipient_emails,
        min_severity=data.min_severity,
        created_by=principal.user.id,
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="alerting.digest_created",
        details={"frequency": data.frequency},
        request=request,
    )
    db.commit()

    return config


@router.get("/digest", response_model=EmailDigestConfig)
async def get_digest_config(
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == principal.organization_id
    ).first()
    if not config:
        raise NotFoundError("Digest config not found", code="digest_config_not_found")
    return config


@router.patch("/digest", response_model=EmailDigestConfig)
async def update_digest_config(
    data: EmailDigestConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == principal.organization_id
    ).first()
    if not config:
        raise NotFoundError("Digest config not found", code="digest_config_not_found")

    if data.frequency is not None:
        config.frequency = data.frequency
    if data.day_of_week is not None:
        config.day_of_week = data.day_of_week
    if data.hour_utc is not None:
        config.hour_utc = data.hour_utc
    if data.recipient_emails is not None:
        config.recipient_emails = data.recipient_emails
    if data.min_severity is not None:
        config.min_severity = data.min_severity
    if data.is_active is not None:
        config.is_active = data.is_active

    config.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(config)

    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="alerting.digest_updated",
        details={"id": config.id},
        request=request,
    )
    db.commit()

    return config


@router.delete("/digest")
async def delete_digest_config(
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(_ALERT_ADMIN_DEP),
):
    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == principal.organization_id
    ).first()
    if not config:
        raise NotFoundError("Digest config not found", code="digest_config_not_found")

    db.delete(config)
    record_audit(
        db,
        organization_id=principal.organization_id,
        actor=principal.user.username,
        action="alerting.digest_deleted",
        details={"id": config.id},
        request=request,
    )
    db.commit()

    return {"message": "Digest config deleted"}