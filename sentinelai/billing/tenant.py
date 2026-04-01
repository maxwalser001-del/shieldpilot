"""Tenant management for multi-tenant SaaS deployment.

Handles tenant creation, API key generation, and validation.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from sentinelai.logger.database import Tenant


class TenantManager:
    """Manages tenant accounts and API keys."""

    def __init__(self, session_factory):
        self._Session = session_factory

    def create_tenant(
        self,
        name: str,
        email: str,
        tier: str = "free",
    ) -> dict:
        """Create a new tenant and generate an API key.

        Returns dict with tenant_id and api_key (only shown once).
        """
        session = self._Session()
        try:
            tenant_id = str(uuid.uuid4())
            api_key = f"sk_sentinel_{secrets.token_urlsafe(32)}"
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

            tenant = Tenant(
                id=tenant_id,
                name=name,
                email=email,
                api_key_hash=api_key_hash,
                tier=tier,
                created_at=datetime.utcnow(),
                is_active=True,
            )
            session.add(tenant)
            session.commit()

            return {
                "tenant_id": tenant_id,
                "api_key": api_key,  # Only returned once at creation
                "name": name,
                "tier": tier,
            }
        finally:
            session.close()

    def validate_api_key(self, api_key: str) -> Optional[dict]:
        """Validate an API key and return tenant info if valid."""
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        session = self._Session()
        try:
            tenant = (
                session.query(Tenant)
                .filter(
                    Tenant.api_key_hash == api_key_hash,
                    Tenant.is_active == True,
                )
                .first()
            )

            if tenant is None:
                return None

            return {
                "tenant_id": tenant.id,
                "name": tenant.name,
                "tier": tenant.tier,
                "email": tenant.email,
            }
        finally:
            session.close()

    def get_tenant(self, tenant_id: str) -> Optional[dict]:
        """Get tenant info by ID."""
        session = self._Session()
        try:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return None
            return {
                "tenant_id": tenant.id,
                "name": tenant.name,
                "tier": tenant.tier,
                "email": tenant.email,
                "created_at": tenant.created_at.isoformat(),
                "is_active": tenant.is_active,
            }
        finally:
            session.close()

    def deactivate_tenant(self, tenant_id: str) -> bool:
        """Deactivate a tenant account."""
        session = self._Session()
        try:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return False
            tenant.is_active = False
            session.commit()
            return True
        finally:
            session.close()
