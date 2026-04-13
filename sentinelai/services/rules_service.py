"""Custom rule management service for ShieldPilot.

Provides CRUD operations for user-defined detection rules and
integration with the PromptScanner via get_enabled_patterns().
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# -- Request/Response Models ---------------------------------------------------


class RuleCreate(BaseModel):
    """Request model for creating a custom rule."""
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    pattern: str = Field(..., min_length=1)
    severity: str = Field("medium")
    category: str = Field("custom", max_length=50)
    enabled: bool = True

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        if len(v) > 500:
            raise ValueError("Pattern too long (max 500 characters)")
        # Reject patterns with nested quantifiers that cause catastrophic backtracking (ReDoS)
        _redos_check = re.compile(r'\([^)]*[+*][^)]*\)[+*]')
        if _redos_check.search(v):
            raise ValueError("Pattern contains nested quantifiers — potential ReDoS risk")
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        return v


class RuleUpdate(BaseModel):
    """Request model for updating a custom rule."""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    pattern: Optional[str] = Field(None, min_length=1)
    severity: Optional[str] = None
    category: Optional[str] = Field(None, max_length=50)
    enabled: Optional[bool] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"low", "medium", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        return v


class RuleResponse(BaseModel):
    """Response model for a custom rule."""
    id: int
    name: str
    description: Optional[str]
    pattern: str
    severity: str
    category: str
    enabled: bool
    created_at: str
    updated_at: str


# -- Service -------------------------------------------------------------------


class RulesService:
    """CRUD service for custom detection rules."""

    def __init__(self, session: Session):
        self.session = session

    def list_rules(self, tenant_id: Optional[str] = None) -> List[RuleResponse]:
        """List all custom rules for a tenant."""
        from sentinelai.logger.database import CustomRule

        query = self.session.query(CustomRule)
        if tenant_id:
            query = query.filter(CustomRule.tenant_id == tenant_id)
        else:
            query = query.filter(CustomRule.tenant_id == None)  # noqa: E711
        rules = query.order_by(CustomRule.created_at.desc()).all()
        return [self._to_response(r) for r in rules]

    def get_rule(
        self, rule_id: int, tenant_id: Optional[str] = None
    ) -> Optional[RuleResponse]:
        """Get a single rule by ID."""
        rule = self._get_rule_model(rule_id, tenant_id)
        if rule is None:
            return None
        return self._to_response(rule)

    def create_rule(
        self,
        data: RuleCreate,
        tenant_id: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> RuleResponse:
        """Create a new custom rule."""
        from sentinelai.logger.database import CustomRule

        rule = CustomRule(
            tenant_id=tenant_id,
            name=data.name,
            description=data.description,
            pattern=data.pattern,
            severity=data.severity,
            category=data.category,
            enabled=data.enabled,
            created_by=user_id,
        )
        self.session.add(rule)
        self.session.commit()
        self.session.refresh(rule)
        logger.info("Created custom rule %d: %s", rule.id, rule.name)
        return self._to_response(rule)

    def update_rule(
        self,
        rule_id: int,
        data: RuleUpdate,
        tenant_id: Optional[str] = None,
    ) -> Optional[RuleResponse]:
        """Update an existing custom rule."""
        rule = self._get_rule_model(rule_id, tenant_id)
        if rule is None:
            return None
        if data.name is not None:
            rule.name = data.name
        if data.description is not None:
            rule.description = data.description
        if data.pattern is not None:
            rule.pattern = data.pattern
        if data.severity is not None:
            rule.severity = data.severity
        if data.category is not None:
            rule.category = data.category
        if data.enabled is not None:
            rule.enabled = data.enabled
        rule.updated_at = datetime.now(timezone.utc)
        self.session.commit()
        self.session.refresh(rule)
        logger.info("Updated custom rule %d: %s", rule.id, rule.name)
        return self._to_response(rule)

    def delete_rule(self, rule_id: int, tenant_id: Optional[str] = None) -> bool:
        """Delete a custom rule. Returns True if deleted."""
        rule = self._get_rule_model(rule_id, tenant_id)
        if rule is None:
            return False
        self.session.delete(rule)
        self.session.commit()
        logger.info("Deleted custom rule %d", rule_id)
        return True

    def get_enabled_patterns(
        self, tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all enabled rules as pattern dicts for scanner integration.

        Returns dicts with keys: name, pattern, severity, category
        that can be used alongside the built-in PATTERNS list.
        """
        from sentinelai.logger.database import CustomRule

        query = self.session.query(CustomRule).filter(CustomRule.enabled == True)  # noqa: E712
        if tenant_id:
            query = query.filter(CustomRule.tenant_id == tenant_id)
        else:
            query = query.filter(CustomRule.tenant_id == None)  # noqa: E711
        rules = query.all()
        return [
            {
                "name": f"custom:{r.name}",
                "pattern": r.pattern,
                "severity": r.severity,
                "category": r.category,
            }
            for r in rules
        ]

    def _get_rule_model(self, rule_id: int, tenant_id: Optional[str] = None):
        """Get the raw DB model for a rule."""
        from sentinelai.logger.database import CustomRule

        query = self.session.query(CustomRule).filter(CustomRule.id == rule_id)
        if tenant_id:
            query = query.filter(CustomRule.tenant_id == tenant_id)
        else:
            query = query.filter(CustomRule.tenant_id == None)  # noqa: E711
        return query.first()

    @staticmethod
    def _to_response(rule) -> RuleResponse:
        return RuleResponse(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            pattern=rule.pattern,
            severity=rule.severity,
            category=rule.category,
            enabled=rule.enabled,
            created_at=rule.created_at.isoformat() if rule.created_at else "",
            updated_at=rule.updated_at.isoformat() if rule.updated_at else "",
        )
