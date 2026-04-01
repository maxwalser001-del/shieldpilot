"""Webhook notification service for ShieldPilot.

Sends notifications to Slack, Discord, or custom webhook URLs when
security incidents of high severity or above are detected.

Usage:
    service = WebhookService(session, config)
    service.notify_incident(incident_log)
"""

from __future__ import annotations

import html
import json
import logging
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

# Allowed URL schemes for webhook endpoints
_ALLOWED_WEBHOOK_SCHEMES = re.compile(r"^https?://", re.IGNORECASE)
# Valid email pattern (loose — just prevents obvious injection)
_EMAIL_PATTERN = re.compile(r"^[^@\s<>\"']+@[^@\s<>\"']+\.[^@\s<>\"']{2,}$")

logger = logging.getLogger(__name__)


# ── Models ───────────────────────────────────────────────────


class WebhookType(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    CUSTOM = "custom"


class WebhookConfig(BaseModel):
    """Configuration for a single webhook endpoint."""
    url: str
    type: WebhookType = WebhookType.CUSTOM
    enabled: bool = True
    min_severity: str = "high"  # minimum severity to trigger: low/medium/high/critical
    secret: Optional[str] = None  # HMAC signing secret for custom webhooks
    name: str = ""

    @validator("url")
    def _validate_url(cls, v: str) -> str:
        """Reject non-http(s) schemes to prevent SSRF via file://, ftp://, etc."""
        v = v.strip()
        if not _ALLOWED_WEBHOOK_SCHEMES.match(v):
            raise ValueError(
                "Webhook URL must use http:// or https:// (got unsupported scheme)"
            )
        return v

    @validator("name")
    def _sanitize_name(cls, v: str) -> str:
        """HTML-escape the display name to prevent XSS when rendered in the UI."""
        return html.escape(v, quote=True)


class WebhookPayload(BaseModel):
    """Universal payload sent to all webhook types."""
    event: str = "incident.created"
    incident_id: int
    severity: str
    category: str
    title: str
    description: str
    timestamp: str
    risk_score: Optional[int] = None
    tenant_id: Optional[str] = None


class WebhookDelivery(BaseModel):
    """Record of a webhook delivery attempt."""
    webhook_name: str
    webhook_type: str
    url: str
    status_code: Optional[int] = None
    success: bool = False
    error: Optional[str] = None
    delivered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── Severity ordering ────────────────────────────────────────


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_meets_threshold(severity: str, min_severity: str) -> bool:
    """Check if severity meets or exceeds the minimum threshold."""
    return _SEVERITY_ORDER.get(severity.lower(), 0) >= _SEVERITY_ORDER.get(min_severity.lower(), 2)


# ── Formatters (platform-specific payloads) ──────────────────


def format_slack_payload(payload: WebhookPayload) -> Dict[str, Any]:
    """Format webhook payload for Slack incoming webhook."""
    color = {
        "critical": "#F85149",
        "high": "#D29922",
        "medium": "#58A6FF",
        "low": "#8B949E",
    }.get(payload.severity.lower(), "#8B949E")

    return {
        "text": f"ShieldPilot Incident: {payload.title}",
        "attachments": [
            {
                "color": color,
                "title": f"[{payload.severity.upper()}] {payload.title}",
                "text": payload.description,
                "fields": [
                    {"title": "Category", "value": payload.category, "short": True},
                    {"title": "Severity", "value": payload.severity.upper(), "short": True},
                    {"title": "Incident ID", "value": str(payload.incident_id), "short": True},
                    {"title": "Risk Score", "value": str(payload.risk_score or "N/A"), "short": True},
                ],
                "ts": payload.timestamp,
                "footer": "ShieldPilot Security Platform",
            }
        ],
    }


def format_discord_payload(payload: WebhookPayload) -> Dict[str, Any]:
    """Format webhook payload for Discord webhook."""
    color_int = {
        "critical": 0xF85149,
        "high": 0xD29922,
        "medium": 0x58A6FF,
        "low": 0x8B949E,
    }.get(payload.severity.lower(), 0x8B949E)

    return {
        "content": f"**ShieldPilot Incident** [{payload.severity.upper()}]",
        "embeds": [
            {
                "title": payload.title,
                "description": payload.description,
                "color": color_int,
                "fields": [
                    {"name": "Category", "value": payload.category, "inline": True},
                    {"name": "Severity", "value": payload.severity.upper(), "inline": True},
                    {"name": "Incident ID", "value": str(payload.incident_id), "inline": True},
                ],
                "footer": {"text": "ShieldPilot Security Platform"},
                "timestamp": payload.timestamp,
            }
        ],
    }


def format_custom_payload(payload: WebhookPayload) -> Dict[str, Any]:
    """Format webhook payload for custom webhook endpoints."""
    return payload.dict()


# ── Service ──────────────────────────────────────────────────


class WebhookService:
    """Manages webhook notification delivery for incidents."""

    def __init__(self, session: Session, config: Any):
        self.session = session
        self.config = config
        self._webhooks = self._load_webhooks()

    def _load_webhooks(self) -> List[WebhookConfig]:
        """Load webhook configurations from config."""
        webhooks_config = getattr(self.config, "webhooks", None)
        if not webhooks_config:
            return []

        raw_hooks = getattr(webhooks_config, "endpoints", [])
        result = []
        for hook_data in raw_hooks:
            if isinstance(hook_data, dict):
                result.append(WebhookConfig(**hook_data))
            elif isinstance(hook_data, WebhookConfig):
                result.append(hook_data)
        return result

    def notify_incident(self, incident: Any) -> List[WebhookDelivery]:
        """Send notifications for an incident to all configured webhooks.

        Only sends to webhooks where the incident severity meets the
        minimum threshold configured for that webhook.

        Args:
            incident: IncidentLog database object with severity, category,
                      title, description, id, timestamp, tenant_id.

        Returns:
            List of WebhookDelivery records documenting each attempt.
        """
        deliveries: List[WebhookDelivery] = []

        severity = getattr(incident, "severity", "low")
        payload = WebhookPayload(
            incident_id=getattr(incident, "id", 0),
            severity=severity,
            category=getattr(incident, "category", ""),
            title=getattr(incident, "title", ""),
            description=getattr(incident, "description", ""),
            timestamp=getattr(incident, "timestamp", datetime.now(timezone.utc)).isoformat()
            if hasattr(incident, "timestamp") else datetime.now(timezone.utc).isoformat(),
            risk_score=getattr(incident, "risk_score", None),
            tenant_id=getattr(incident, "tenant_id", None),
        )

        for webhook in self._webhooks:
            if not webhook.enabled:
                continue
            if not _severity_meets_threshold(severity, webhook.min_severity):
                continue

            delivery = self._send(webhook, payload)
            deliveries.append(delivery)

        return deliveries

    def _send(self, webhook: WebhookConfig, payload: WebhookPayload) -> WebhookDelivery:
        """Send payload to a single webhook endpoint.

        Uses httpx for HTTP delivery. Falls back gracefully on errors.
        """
        # Format payload based on webhook type
        if webhook.type == WebhookType.SLACK:
            body = format_slack_payload(payload)
        elif webhook.type == WebhookType.DISCORD:
            body = format_discord_payload(payload)
        else:
            body = format_custom_payload(payload)

        try:
            import httpx

            headers = {"Content-Type": "application/json"}

            # HMAC signature for custom webhooks
            if webhook.secret and webhook.type == WebhookType.CUSTOM:
                import hashlib
                import hmac
                body_bytes = json.dumps(body, sort_keys=True).encode()
                sig = hmac.new(
                    webhook.secret.encode(), body_bytes, hashlib.sha256
                ).hexdigest()
                headers["X-ShieldPilot-Signature"] = f"sha256={sig}"

            with httpx.Client(timeout=10.0) as client:
                resp = client.post(webhook.url, json=body, headers=headers)

            success = 200 <= resp.status_code < 300
            if not success:
                logger.warning(
                    "Webhook delivery failed: %s -> %d",
                    webhook.name or webhook.url,
                    resp.status_code,
                )

            return WebhookDelivery(
                webhook_name=webhook.name or webhook.url,
                webhook_type=webhook.type.value,
                url=webhook.url,
                status_code=resp.status_code,
                success=success,
            )

        except Exception as e:
            logger.error("Webhook delivery error: %s -> %s", webhook.name or webhook.url, e)
            return WebhookDelivery(
                webhook_name=webhook.name or webhook.url,
                webhook_type=webhook.type.value,
                url=webhook.url,
                success=False,
                error=str(e),
            )

    def get_configured_webhooks(self) -> List[Dict[str, Any]]:
        """Return list of configured webhooks (without secrets)."""
        return [
            {
                "name": w.name,
                "type": w.type.value,
                "url": w.url[:20] + "..." if len(w.url) > 20 else w.url,
                "enabled": w.enabled,
                "min_severity": w.min_severity,
            }
            for w in self._webhooks
        ]
