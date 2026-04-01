"""Team management service for ShieldPilot.

Handles team member invitations, role management, and member listing.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

VALID_ROLES = {"admin", "analyst", "viewer"}


class InviteCreate(BaseModel):
    """Request to invite a team member."""
    email: str = Field(..., min_length=5, max_length=256)
    role: str = Field("viewer")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v


class TeamMember(BaseModel):
    """Response model for a team member."""
    id: int
    username: str
    email: Optional[str]
    role: str
    is_active: bool
    created_at: str


class InviteResponse(BaseModel):
    """Response model for a team invite."""
    id: int
    email: str
    role: str
    created_at: str
    expires_at: str
    accepted: bool


class TeamService:
    """Manages team members and invitations."""

    def __init__(self, session: Session):
        self.session = session

    def list_members(self, tenant_id: Optional[str] = None) -> List[TeamMember]:
        """List all team members for a tenant."""
        from sentinelai.logger.database import User
        query = self.session.query(User)
        if tenant_id:
            query = query.filter(User.tenant_id == tenant_id)
        members = query.order_by(User.created_at.desc()).all()
        return [
            TeamMember(
                id=m.id,
                username=m.username,
                email=m.email,
                role=m.role,
                is_active=m.is_active,
                created_at=m.created_at.isoformat() if m.created_at else "",
            )
            for m in members
        ]

    def create_invite(
        self, data: InviteCreate, tenant_id: Optional[str], invited_by: int
    ) -> tuple[InviteResponse, str]:
        """Create a team invitation. Returns (response, raw_token)."""
        from sentinelai.logger.database import TeamInvite, User

        # Check if user already exists with this email in the tenant
        existing = self.session.query(User).filter(
            User.email == data.email, User.tenant_id == tenant_id
        ).first()
        if existing:
            raise ValueError("User with this email is already a team member")

        # Check for pending invite
        existing_invite = self.session.query(TeamInvite).filter(
            TeamInvite.email == data.email,
            TeamInvite.tenant_id == tenant_id,
            TeamInvite.accepted == False,
            TeamInvite.expires_at > datetime.now(timezone.utc),
        ).first()
        if existing_invite:
            raise ValueError("A pending invitation already exists for this email")

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        invite = TeamInvite(
            tenant_id=tenant_id,
            email=data.email,
            role=data.role,
            invited_by=invited_by,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        self.session.add(invite)
        self.session.commit()
        self.session.refresh(invite)

        logger.info("Created team invite for %s (role=%s)", data.email, data.role)

        resp = InviteResponse(
            id=invite.id,
            email=invite.email,
            role=invite.role,
            created_at=invite.created_at.isoformat(),
            expires_at=invite.expires_at.isoformat(),
            accepted=invite.accepted,
        )
        return resp, token

    def list_invites(self, tenant_id: Optional[str] = None) -> List[InviteResponse]:
        """List all pending invites for a tenant."""
        from sentinelai.logger.database import TeamInvite
        query = self.session.query(TeamInvite).filter(
            TeamInvite.accepted == False,
            TeamInvite.expires_at > datetime.now(timezone.utc),
        )
        if tenant_id:
            query = query.filter(TeamInvite.tenant_id == tenant_id)
        invites = query.order_by(TeamInvite.created_at.desc()).all()
        return [
            InviteResponse(
                id=inv.id,
                email=inv.email,
                role=inv.role,
                created_at=inv.created_at.isoformat(),
                expires_at=inv.expires_at.isoformat(),
                accepted=inv.accepted,
            )
            for inv in invites
        ]

    def revoke_invite(self, invite_id: int, tenant_id: Optional[str] = None) -> bool:
        """Delete a pending invite. Returns True if deleted."""
        from sentinelai.logger.database import TeamInvite
        query = self.session.query(TeamInvite).filter(TeamInvite.id == invite_id)
        if tenant_id:
            query = query.filter(TeamInvite.tenant_id == tenant_id)
        invite = query.first()
        if invite is None:
            return False
        self.session.delete(invite)
        self.session.commit()
        logger.info("Revoked invite %d", invite_id)
        return True

    def update_member_role(
        self, user_id: int, new_role: str, tenant_id: Optional[str] = None
    ) -> Optional[TeamMember]:
        """Update a team member's role."""
        if new_role not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        from sentinelai.logger.database import User
        query = self.session.query(User).filter(User.id == user_id)
        if tenant_id:
            query = query.filter(User.tenant_id == tenant_id)
        user = query.first()
        if user is None:
            return None
        if user.is_super_admin:
            raise ValueError("Cannot change role of super-admin")
        user.role = new_role
        self.session.commit()
        self.session.refresh(user)
        logger.info("Updated user %d role to %s", user_id, new_role)
        return TeamMember(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else "",
        )

    def remove_member(self, user_id: int, tenant_id: Optional[str] = None) -> bool:
        """Deactivate a team member (soft delete)."""
        from sentinelai.logger.database import User
        query = self.session.query(User).filter(User.id == user_id)
        if tenant_id:
            query = query.filter(User.tenant_id == tenant_id)
        user = query.first()
        if user is None:
            return False
        if user.is_super_admin:
            raise ValueError("Cannot remove super-admin")
        user.is_active = False
        self.session.commit()
        logger.info("Deactivated user %d", user_id)
        return True
