"""Custom rule management API endpoints.

CRUD operations for user-defined detection patterns that integrate
with ShieldPilot's PromptScanner.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import get_current_user, get_db_session, require_admin
from sentinelai.services.rules_service import (
    RuleCreate,
    RuleResponse,
    RuleUpdate,
    RulesService,
)

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get(
    "",
    response_model=list[RuleResponse],
    summary="List custom rules",
    description="Return all custom detection rules for the authenticated user's tenant. "
    "Rules integrate with the PromptScanner to extend built-in detection patterns.",
    response_description="List of custom rules",
)
def list_rules(
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """List all custom rules for the current tenant."""
    service = RulesService(session)
    return service.list_rules(tenant_id=user.tenant_id)


@router.get(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Get custom rule",
    description="Retrieve a single custom detection rule by its ID. "
    "Returns 404 if the rule does not exist or belongs to another tenant.",
    response_description="The requested rule",
)
def get_rule(
    rule_id: int,
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a single custom rule by ID."""
    service = RulesService(session)
    rule = service.get_rule(rule_id, tenant_id=user.tenant_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": "Rule not found"},
        )
    return rule


@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create custom rule",
    description="Create a new custom detection rule for the tenant. "
    "Requires admin privileges. The rule is immediately active in the PromptScanner.",
    response_description="The newly created rule",
)
def create_rule(
    body: RuleCreate,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Create a new custom detection rule (admin only)."""
    service = RulesService(session)
    return service.create_rule(body, tenant_id=user.tenant_id)


@router.patch(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Update custom rule",
    description="Partially update an existing custom rule. "
    "Only supplied fields are modified. Requires admin privileges.",
    response_description="The updated rule",
)
def update_rule(
    rule_id: int,
    body: RuleUpdate,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Update an existing custom rule (admin only)."""
    service = RulesService(session)
    rule = service.update_rule(rule_id, body, tenant_id=user.tenant_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": "Rule not found"},
        )
    return rule


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete custom rule",
    description="Permanently delete a custom detection rule. "
    "Requires admin privileges. Returns 404 if the rule does not exist.",
    response_description="No content on success",
)
def delete_rule(
    rule_id: int,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Delete a custom rule (admin only)."""
    service = RulesService(session)
    deleted = service.delete_rule(rule_id, tenant_id=user.tenant_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": "Rule not found"},
        )
