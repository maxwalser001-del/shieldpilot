"""Team management API endpoints.

Invite members, manage roles, list team members.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import get_current_user, get_db_session, require_admin
from sentinelai.services.team_service import (
    InviteCreate,
    InviteResponse,
    TeamMember,
    TeamService,
)

router = APIRouter(prefix="/api/teams", tags=["Teams"])


# ── Request models ────────────────────────────────────────────


class RoleUpdate(BaseModel):
    role: str


# ── Team Members ──────────────────────────────────────────────


@router.get(
    "/members",
    response_model=list[TeamMember],
    summary="List team members",
    description="Return all team members for the authenticated user's tenant, "
    "including their roles and profile information.",
    response_description="List of all team members for the current tenant",
)
def list_members(
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all team members."""
    service = TeamService(session)
    return service.list_members(tenant_id=user.tenant_id)


@router.patch(
    "/members/{user_id}/role",
    response_model=TeamMember,
    summary="Update member role",
    description="Change a team member's role (e.g. viewer, editor, admin). "
    "Requires admin privileges. Returns 400 for invalid roles.",
    response_description="Updated team member with new role",
)
def update_member_role(
    user_id: int,
    body: RoleUpdate,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Update a team member's role (admin only)."""
    service = TeamService(session)
    try:
        member = service.update_member_role(user_id, body.role, tenant_id=user.tenant_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_role", "message": str(e)},
        )
    if member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": "Member not found"},
        )
    return member


@router.delete(
    "/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove team member",
    description="Soft-delete a team member from the tenant. "
    "Requires admin privileges. Cannot remove yourself.",
    response_description="No content on success",
)
def remove_member(
    user_id: int,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Remove a team member (admin only). Soft-deletes the user."""
    service = TeamService(session)
    try:
        removed = service.remove_member(user_id, tenant_id=user.tenant_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "cannot_remove", "message": str(e)},
        )
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": "Member not found"},
        )


# ── Invitations ───────────────────────────────────────────────


@router.get(
    "/invites",
    response_model=list[InviteResponse],
    summary="List pending invitations",
    description="Return all pending (not yet accepted or revoked) team invitations. "
    "Requires admin privileges.",
    response_description="List of pending team invitations",
)
def list_invites(
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """List pending invitations (admin only)."""
    service = TeamService(session)
    return service.list_invites(tenant_id=user.tenant_id)


@router.post(
    "/invites",
    response_model=InviteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create team invitation",
    description="Send an email invitation to join the team. "
    "Requires admin privileges. Returns 409 if the email is already invited or a member.",
    response_description="Created invitation details",
)
def create_invite(
    body: InviteCreate,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Send a team invitation (admin only)."""
    from sentinelai.logger.database import User

    service = TeamService(session)
    try:
        # Look up inviter's user ID from DB
        db_user = session.query(User).filter(User.email == user.email).first()
        inviter_id = db_user.id if db_user else 0
        resp, _token = service.create_invite(body, tenant_id=user.tenant_id, invited_by=inviter_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "invite_conflict", "message": str(e)},
        )
    return resp


@router.delete(
    "/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke invitation",
    description="Revoke a pending team invitation so it can no longer be accepted. "
    "Requires admin privileges. Returns 404 if the invitation does not exist.",
    response_description="No content on success",
)
def revoke_invite(
    invite_id: int,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Revoke a pending invitation (admin only)."""
    service = TeamService(session)
    revoked = service.revoke_invite(invite_id, tenant_id=user.tenant_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": "Invite not found"},
        )
