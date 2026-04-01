"""Multi-tenant data isolation service for ShieldPilot.

Provides tenant-scoped query helpers and a FastAPI dependency that
automatically filters all database queries by the current user's tenant_id.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Type, TypeVar

from sqlalchemy.orm import Query, Session

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TenantFilter:
    """Applies tenant_id filtering to SQLAlchemy queries.

    Usage:
        tf = TenantFilter(session, tenant_id="acme-corp")
        commands = tf.query(CommandLog).filter(...).all()

    For super-admins (tenant_id=None), queries are unfiltered.
    """

    def __init__(self, session: Session, tenant_id: Optional[str] = None):
        self.session = session
        self.tenant_id = tenant_id

    def query(self, model: Type[T], *args: Any) -> Query:
        """Create a tenant-scoped query.

        If tenant_id is set, automatically adds .filter(model.tenant_id == self.tenant_id).
        If tenant_id is None (super-admin or local-first), returns unfiltered query.
        """
        q = self.session.query(model, *args)
        if self.tenant_id is not None and hasattr(model, "tenant_id"):
            q = q.filter(model.tenant_id == self.tenant_id)
        return q

    def count(self, model: Type[T]) -> int:
        """Count records scoped to tenant."""
        return self.query(model).count()
