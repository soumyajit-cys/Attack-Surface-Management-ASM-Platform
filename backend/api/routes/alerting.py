from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl, EmailStr, Field
from typing import Optional, List
from datetime import datetime, timezone

from auth.dependencies import get_current_user
from auth.roles import ROLE_ADMIN, require_roles
from models import AlertIntegration, AlertChannel, EmailDigestConfig, AlertSeverity, User
from schemas.organization import OrganizationResponse
from utils.database import get_db
from utils.ssrf_guard import is_allowed_target

router = APIRouter(
    prefix="/alerting",
    tags=["alerting"],
)


class AlertIntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    channel: AlertChannel
    webhook_url: HttpUrl
    secret: Optional[str] = None
    min_severity: AlertSeverity = AlertSeverity.HIGH


class AlertIntegrationUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    webhook_url: Optional[HttpUrl] = None
    secret: Optional[str] = None
    min_severity: Optional[AlertSeverity] = None
    is_active: Optional[bool] = None


class AlertIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    name: str
    channel: AlertChannel
    webhook_url: str
    min_severity: AlertSeverity
    is_active: bool
    last_triggered_at: Optional[datetime]
    created_by: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EmailDigestConfigCreate(BaseModel):
    frequency: str = Field(default="weekly", pattern="^(daily|weekly|monthly)$")
    day_of_week: int = Field(default=1, ge=0, le=6)
    hour_utc: int = Field(default=9, ge=0, le=23)
    recipient_emails: str = Field(min_length=3)
    min_severity: AlertSeverity = AlertSeverity.MEDIUM


class EmailDigestConfigUpdate(BaseModel):
    frequency: Optional[str] = Field(default=None, pattern="^(daily|weekly|monthly)$")
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    recipient_emails: Optional[str] = None
    min_severity: Optional[AlertSeverity] = None
    is_active: Optional[bool] = None


class EmailDigestConfigResponse(BaseModel):
    id: int
    organization_id: int
    frequency: str
    day_of_week: int
    hour_utc: int
    recipient_emails: str
    min_severity: AlertSeverity
    is_active: bool
    last_sent_at: Optional[datetime]
    created_by: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.post("/integrations", response_model=AlertIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(
    data: AlertIntegrationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    if not is_allowed_target(str(data.webhook_url)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Webhook URL not allowed (private/cloud metadata IP)",
        )

    integration = AlertIntegration(
        organization_id=user.organization_id,
        name=data.name,
        channel=data.channel,
        webhook_url=str(data.webhook_url),
        secret=data.secret,
        min_severity=data.min_severity,
        created_by=user.id,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)

    return integration


@router.get("/integrations", response_model=List[AlertIntegrationResponse])
async def list_integrations(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    integrations = db.query(AlertIntegration).filter(
        AlertIntegration.organization_id == user.organization_id
    ).order_by(AlertIntegration.created_at.desc()).all()
    return integrations


@router.get("/integrations/{integration_id}", response_model=AlertIntegrationResponse)
async def get_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == user.organization_id,
    ).first()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found",
        )
    return integration


@router.patch("/integrations/{integration_id}", response_model=AlertIntegrationResponse)
async def update_integration(
    integration_id: int,
    data: AlertIntegrationUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == user.organization_id,
    ).first()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found",
        )

    if data.name is not None:
        integration.name = data.name
    if data.webhook_url is not None:
        if not is_allowed_target(str(data.webhook_url)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Webhook URL not allowed (private/cloud metadata IP)",
            )
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

    return integration


@router.delete("/integrations/{integration_id}")
async def delete_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == user.organization_id,
    ).first()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found",
        )

    db.delete(integration)
    db.commit()

    return {"message": "Integration deleted"}


@router.post("/integrations/{integration_id}/test")
async def test_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    from models import Finding, Asset
    from services.alerts.alerting_service import send_slack_alert, send_discord_alert, severity_meets_threshold

    integration = db.query(AlertIntegration).filter(
        AlertIntegration.id == integration_id,
        AlertIntegration.organization_id == user.organization_id,
    ).first()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found",
        )

    test_finding = Finding(
        organization_id=user.organization_id,
        asset_id=1,
        title="Test Alert from SentinelASM",
        severity="high",
        category="test",
        description="This is a test alert to verify the integration is working.",
        recommendation="No action needed.",
    )

    test_asset = Asset(
        organization_id=user.organization_id,
        name="test-asset.example.com",
    )

    success = False
    if integration.channel == AlertChannel.SLACK:
        success = await send_slack_alert(str(integration.webhook_url), test_finding, test_asset)
    elif integration.channel == AlertChannel.DISCORD:
        success = await send_discord_alert(str(integration.webhook_url), test_finding, test_asset)

    if success:
        return {"message": "Test alert sent successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send test alert",
        )


@router.post("/digest", response_model=EmailDigestConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_digest_config(
    data: EmailDigestConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    existing = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == user.organization_id
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Digest config already exists for this organization",
        )

    emails = [e.strip() for e in data.recipient_emails.split(",") if e.strip()]
    for email in emails:
        if "@" not in email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid email: {email}",
            )

    config = EmailDigestConfig(
        organization_id=user.organization_id,
        frequency=data.frequency,
        day_of_week=data.day_of_week,
        hour_utc=data.hour_utc,
        recipient_emails=data.recipient_emails,
        min_severity=data.min_severity,
        created_by=user.id,
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    return config


@router.get("/digest", response_model=EmailDigestConfigResponse)
async def get_digest_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == user.organization_id
    ).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digest config not found",
        )
    return config


@router.patch("/digest", response_model=EmailDigestConfigResponse)
async def update_digest_config(
    data: EmailDigestConfigUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == user.organization_id
    ).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digest config not found",
        )

    if data.frequency is not None:
        config.frequency = data.frequency
    if data.day_of_week is not None:
        config.day_of_week = data.day_of_week
    if data.hour_utc is not None:
        config.hour_utc = data.hour_utc
    if data.recipient_emails is not None:
        emails = [e.strip() for e in data.recipient_emails.split(",") if e.strip()]
        for email in emails:
            if "@" not in email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid email: {email}",
                )
        config.recipient_emails = data.recipient_emails
    if data.min_severity is not None:
        config.min_severity = data.min_severity
    if data.is_active is not None:
        config.is_active = data.is_active

    config.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(config)

    return config


@router.delete("/digest")
async def delete_digest_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == user.organization_id
    ).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digest config not found",
        )

    db.delete(config)
    db.commit()

    return {"message": "Digest config deleted"}


@router.post("/digest/test")
async def test_digest(
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(ROLE_ADMIN)),
):
    from services.alerts.alerting_service import send_email_digest

    config = db.query(EmailDigestConfig).filter(
        EmailDigestConfig.organization_id == user.organization_id
    ).first()
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Digest config not found",
        )

    sent = await send_email_digest(db, config)

    if sent:
        return {"message": "Test digest sent successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send test digest (no findings in period?)",
        )