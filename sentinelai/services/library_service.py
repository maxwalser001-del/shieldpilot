"""Library service: business logic for library items, topics, and categories."""

from __future__ import annotations

import json
import re as _re
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import is_super_admin
from sentinelai.core.config import SentinelConfig
from sentinelai.logger.database import LibraryItem, LibraryTopic, User


class LibraryService:
    """Encapsulates all library business logic.

    Accepts a SQLAlchemy session and config as constructor params.
    Route handlers create the service, call methods, and handle session lifecycle.
    """

    def __init__(self, session: Session, config: SentinelConfig):
        self.session = session
        self.config = config

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def slugify(name: str) -> str:
        """Generate URL-friendly slug from name."""
        slug = name.lower().strip()
        slug = _re.sub(r'[^\w\s-]', '', slug)
        slug = _re.sub(r'[\s_]+', '-', slug)
        slug = _re.sub(r'-+', '-', slug).strip('-')
        return slug

    def can_access_full_content(self, user: TokenData, item_index: int) -> bool:
        """Check if user can access full_content for a library item.

        - Admins/super-admins: always full access
        - Pro/Enterprise/Unlimited: full access
        - Free: only first item (index 0)
        """
        if user.role == "admin" or is_super_admin(user, self.config):
            return True
        # Resolve tier from DB (not JWT) so upgrades take effect immediately
        from sentinelai.api.deps import get_user_tier_limits, get_logger
        user_tier, _limits = get_user_tier_limits(user, self.config, get_logger())
        if user_tier in ["pro", "pro_plus", "enterprise", "unlimited"]:
            return True
        return item_index == 0

    def serialize_item(
        self,
        item,
        index: int,
        user: TokenData,
        include_full_content: bool = True,
    ) -> dict:
        """Serialize a library item, applying paywall logic."""
        can_access = self.can_access_full_content(user, index)

        return {
            "id": item.id,
            "type": item.type,
            "title": item.title,
            "tags": json.loads(item.tags) if item.tags else [],
            "short_preview": item.short_preview,
            "full_content": item.full_content if (can_access and include_full_content) else None,
            "full_content_locked": not can_access,
            "access_level": "public" if can_access else "locked",
            "category": item.category,
            "display_order": item.display_order or 0,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
            "is_published": item.is_published,
            "topic_id": item.topic_id,
            "topic_name": item.topic.name if item.topic else item.category,
        }

    # ── Library Items ─────────────────────────────────────────

    def list_items(
        self,
        type: Optional[str],
        category: Optional[str],
        topic_id: Optional[int],
        limit: int,
        offset: int,
        user: TokenData,
    ) -> dict:
        """List published library items with paywall enforcement."""
        query = self.session.query(LibraryItem).options(
            joinedload(LibraryItem.topic)
        ).filter(LibraryItem.is_published == True)

        if type:
            query = query.filter(LibraryItem.type == type)

        if category:
            query = query.filter(LibraryItem.category == category)

        if topic_id is not None:
            child_ids = [
                t.id for t in
                self.session.query(LibraryTopic.id).filter(LibraryTopic.parent_id == topic_id).all()
            ]
            all_topic_ids = [topic_id] + child_ids
            query = query.filter(LibraryItem.topic_id.in_(all_topic_ids))

        query = query.order_by(LibraryItem.display_order, LibraryItem.created_at.desc())

        total = query.count()
        items = query.offset(offset).limit(limit).all()

        user_tier = getattr(user, "tier", "free")
        user_has_pro_access = (
            user.role == "admin"
            or is_super_admin(user, self.config)
            or user_tier in ["pro", "pro_plus", "enterprise", "unlimited"]
        )

        result_items = []
        for idx, item in enumerate(items):
            global_index = offset + idx
            result_items.append(self.serialize_item(item, global_index, user))

        return {
            "items": result_items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "pages": (total + limit - 1) // limit if limit > 0 else 0,
            "user_has_pro_access": user_has_pro_access,
        }

    def list_items_admin(
        self,
        type: Optional[str],
        topic_id: Optional[int],
        limit: int,
        offset: int,
        user: TokenData,
    ) -> dict:
        """List ALL library items including unpublished (admin only)."""
        query = self.session.query(LibraryItem).options(joinedload(LibraryItem.topic))

        if type:
            query = query.filter(LibraryItem.type == type)

        if topic_id is not None:
            child_ids = [
                t.id for t in
                self.session.query(LibraryTopic.id).filter(LibraryTopic.parent_id == topic_id).all()
            ]
            all_topic_ids = [topic_id] + child_ids
            query = query.filter(LibraryItem.topic_id.in_(all_topic_ids))

        query = query.order_by(LibraryItem.created_at.desc())

        total = query.count()
        items = query.offset(offset).limit(limit).all()

        result_items = []
        for idx, item in enumerate(items):
            result_items.append(self.serialize_item(item, 0, user))

        return {
            "items": result_items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "pages": (total + limit - 1) // limit if limit > 0 else 0,
            "user_has_pro_access": True,
        }

    def get_item(self, item_id: int, user: TokenData) -> dict:
        """Get a single library item by ID with paywall enforcement."""
        item = self.session.query(LibraryItem).filter(LibraryItem.id == item_id).first()

        if not item:
            raise HTTPException(status_code=404, detail={"error": "Library item not found"})

        is_admin_user = user.role == "admin" or is_super_admin(user, self.config)

        if not item.is_published and not is_admin_user:
            raise HTTPException(status_code=404, detail={"error": "Library item not found"})

        # Determine item's index (for paywall logic)
        item_index = (
            self.session.query(LibraryItem)
            .filter(LibraryItem.is_published == True)
            .filter(LibraryItem.created_at >= item.created_at)
            .count()
            - 1
        )
        if item_index < 0:
            item_index = 0

        can_access = self.can_access_full_content(user, item_index)

        if not can_access:
            return {
                "id": item.id,
                "type": item.type,
                "title": item.title,
                "tags": json.loads(item.tags) if item.tags else [],
                "short_preview": item.short_preview,
                "full_content": None,
                "full_content_locked": True,
                "access_level": "locked",
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "updated_at": item.updated_at.isoformat() if item.updated_at else None,
                "is_published": item.is_published,
                "upgrade_url": self.config.billing.upgrade_url,
            }

        return self.serialize_item(item, item_index, user)

    def create_item(
        self,
        type: str,
        title: str,
        tags: list,
        short_preview: str,
        full_content: str,
        category: Optional[str],
        display_order: int,
        is_published: bool,
        topic_id: Optional[int],
        user: TokenData,
    ) -> dict:
        """Create a new library item."""
        if type not in ["prompt", "skill"]:
            raise HTTPException(
                status_code=400,
                detail={"error": "Type must be 'prompt' or 'skill'"},
            )

        db_user = self.session.query(User).filter(User.email == user.email).first()
        user_id = db_user.id if db_user else None

        item = LibraryItem(
            type=type,
            title=title,
            tags=json.dumps(tags),
            short_preview=short_preview,
            full_content=full_content,
            category=category,
            display_order=display_order,
            is_published=is_published,
            created_by=user_id,
            topic_id=topic_id,
        )
        self.session.add(item)
        self.session.commit()
        self.session.refresh(item)

        return {
            "id": item.id,
            "type": item.type,
            "title": item.title,
            "tags": tags,
            "short_preview": item.short_preview,
            "full_content": item.full_content,
            "full_content_locked": False,
            "category": item.category,
            "display_order": item.display_order or 0,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
            "is_published": item.is_published,
            "topic_id": item.topic_id,
            "topic_name": item.topic.name if item.topic else item.category,
            "message": "Library item created successfully",
        }

    def update_item(self, item_id: int, **fields) -> dict:
        """Update a library item."""
        item = self.session.query(LibraryItem).filter(LibraryItem.id == item_id).first()

        if not item:
            raise HTTPException(status_code=404, detail={"error": "Library item not found"})

        # Validate type if provided
        if fields.get("type") is not None and fields["type"] not in ["prompt", "skill"]:
            raise HTTPException(
                status_code=400,
                detail={"error": "Type must be 'prompt' or 'skill'"},
            )

        # Update fields if provided
        if fields.get("type") is not None:
            item.type = fields["type"]
        if fields.get("title") is not None:
            item.title = fields["title"]
        if fields.get("tags") is not None:
            item.tags = json.dumps(fields["tags"])
        if fields.get("short_preview") is not None:
            item.short_preview = fields["short_preview"]
        if fields.get("full_content") is not None:
            item.full_content = fields["full_content"]
        if fields.get("category") is not None:
            item.category = fields["category"]
        if fields.get("display_order") is not None:
            item.display_order = fields["display_order"]
        if fields.get("is_published") is not None:
            item.is_published = fields["is_published"]
        if fields.get("topic_id") is not None:
            item.topic_id = fields["topic_id"]

        item.updated_at = datetime.now(timezone.utc)

        self.session.commit()
        self.session.refresh(item)

        return {
            "id": item.id,
            "type": item.type,
            "title": item.title,
            "tags": json.loads(item.tags) if item.tags else [],
            "short_preview": item.short_preview,
            "full_content": item.full_content,
            "full_content_locked": False,
            "category": item.category,
            "display_order": item.display_order or 0,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "updated_at": item.updated_at.isoformat() if item.updated_at else None,
            "is_published": item.is_published,
            "topic_id": item.topic_id,
            "topic_name": item.topic.name if item.topic else item.category,
            "message": "Library item updated successfully",
        }

    def delete_item(self, item_id: int) -> dict:
        """Delete a library item."""
        item = self.session.query(LibraryItem).filter(LibraryItem.id == item_id).first()

        if not item:
            raise HTTPException(status_code=404, detail={"error": "Library item not found"})

        self.session.delete(item)
        self.session.commit()

        return {"message": "Library item deleted successfully", "id": item_id}

    # ── Categories ────────────────────────────────────────────

    def list_categories(self) -> dict:
        """Get list of all categories with item counts."""
        results = (
            self.session.query(LibraryItem.category, func.count(LibraryItem.id))
            .filter(LibraryItem.is_published == True, LibraryItem.category != None)
            .group_by(LibraryItem.category)
            .order_by(LibraryItem.category)
            .all()
        )

        return {
            "categories": [
                {"name": cat, "count": count}
                for cat, count in results if cat
            ]
        }

    # ── Topics ────────────────────────────────────────────────

    def list_topics(self) -> dict:
        """Get hierarchical topic tree with item counts."""
        topics = (
            self.session.query(LibraryTopic)
            .order_by(LibraryTopic.display_order, LibraryTopic.name)
            .all()
        )

        counts_query = (
            self.session.query(LibraryItem.topic_id, func.count(LibraryItem.id))
            .filter(LibraryItem.is_published == True, LibraryItem.topic_id != None)
            .group_by(LibraryItem.topic_id)
            .all()
        )
        count_map = {tid: cnt for tid, cnt in counts_query}

        uncategorized_count = (
            self.session.query(func.count(LibraryItem.id))
            .filter(LibraryItem.is_published == True, LibraryItem.topic_id == None)
            .scalar()
        ) or 0

        topic_map = {}
        for t in topics:
            topic_map[t.id] = {
                "id": t.id,
                "name": t.name,
                "slug": t.slug,
                "description": t.description,
                "icon": t.icon,
                "parent_id": t.parent_id,
                "display_order": t.display_order or 0,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "item_count": count_map.get(t.id, 0),
                "children": [],
                "total_count": count_map.get(t.id, 0),
            }

        tree = []
        for t in topics:
            td = topic_map[t.id]
            if t.parent_id and t.parent_id in topic_map:
                topic_map[t.parent_id]["children"].append(td)
                topic_map[t.parent_id]["total_count"] += td["item_count"]
            else:
                tree.append(td)

        return {"topics": tree, "uncategorized_count": uncategorized_count}

    def create_topic(
        self,
        name: str,
        slug: Optional[str],
        description: Optional[str],
        icon: Optional[str],
        parent_id: Optional[int],
        display_order: int,
    ) -> dict:
        """Create a new topic."""
        computed_slug = slug if slug else self.slugify(name)

        existing = self.session.query(LibraryTopic).filter(LibraryTopic.slug == computed_slug).first()
        if existing:
            raise HTTPException(status_code=400, detail={"error": f"Topic with slug '{computed_slug}' already exists"})

        if parent_id is not None:
            parent = self.session.query(LibraryTopic).filter(LibraryTopic.id == parent_id).first()
            if not parent:
                raise HTTPException(status_code=404, detail={"error": "Parent topic not found"})
            if parent.parent_id is not None:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Cannot nest more than 2 levels deep. Parent must be a top-level topic."},
                )

        topic = LibraryTopic(
            name=name,
            slug=computed_slug,
            description=description,
            icon=icon,
            parent_id=parent_id,
            display_order=display_order,
        )
        self.session.add(topic)
        self.session.commit()
        self.session.refresh(topic)

        return {
            "id": topic.id,
            "name": topic.name,
            "slug": topic.slug,
            "description": topic.description,
            "icon": topic.icon,
            "parent_id": topic.parent_id,
            "display_order": topic.display_order or 0,
            "created_at": topic.created_at.isoformat() if topic.created_at else None,
            "message": "Topic created successfully",
        }

    def update_topic(self, topic_id: int, **fields) -> dict:
        """Update a topic."""
        topic = self.session.query(LibraryTopic).filter(LibraryTopic.id == topic_id).first()
        if not topic:
            raise HTTPException(status_code=404, detail={"error": "Topic not found"})

        # Validate slug uniqueness on change
        if fields.get("slug") is not None and fields["slug"] != topic.slug:
            existing = self.session.query(LibraryTopic).filter(
                LibraryTopic.slug == fields["slug"], LibraryTopic.id != topic_id
            ).first()
            if existing:
                raise HTTPException(status_code=400, detail={"error": f"Topic with slug '{fields['slug']}' already exists"})

        # Validate 2-level constraint
        if fields.get("parent_id") is not None:
            if fields["parent_id"] == topic_id:
                raise HTTPException(status_code=400, detail={"error": "A topic cannot be its own parent"})
            parent = self.session.query(LibraryTopic).filter(LibraryTopic.id == fields["parent_id"]).first()
            if not parent:
                raise HTTPException(status_code=404, detail={"error": "Parent topic not found"})
            if parent.parent_id is not None:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Cannot nest more than 2 levels deep. Parent must be a top-level topic."},
                )
            has_children = self.session.query(LibraryTopic).filter(LibraryTopic.parent_id == topic_id).first()
            if has_children:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Cannot move a topic with children under another topic. Remove children first."},
                )

        # Partial update: only set fields that are not None
        if fields.get("name") is not None:
            topic.name = fields["name"]
        if fields.get("slug") is not None:
            topic.slug = fields["slug"]
        if fields.get("description") is not None:
            topic.description = fields["description"]
        if fields.get("icon") is not None:
            topic.icon = fields["icon"]
        if fields.get("parent_id") is not None:
            topic.parent_id = fields["parent_id"]
        if fields.get("display_order") is not None:
            topic.display_order = fields["display_order"]

        self.session.commit()
        self.session.refresh(topic)

        return {
            "id": topic.id,
            "name": topic.name,
            "slug": topic.slug,
            "description": topic.description,
            "icon": topic.icon,
            "parent_id": topic.parent_id,
            "display_order": topic.display_order or 0,
            "created_at": topic.created_at.isoformat() if topic.created_at else None,
            "message": "Topic updated successfully",
        }

    def delete_topic(self, topic_id: int) -> dict:
        """Delete a topic. Fails if topic has items or children."""
        topic = self.session.query(LibraryTopic).filter(LibraryTopic.id == topic_id).first()
        if not topic:
            raise HTTPException(status_code=404, detail={"error": "Topic not found"})

        item_count = self.session.query(LibraryItem).filter(LibraryItem.topic_id == topic_id).count()
        if item_count > 0:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Cannot delete topic with {item_count} assigned item(s). Reassign items first."},
            )

        child_count = self.session.query(LibraryTopic).filter(LibraryTopic.parent_id == topic_id).count()
        if child_count > 0:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Cannot delete topic with {child_count} child topic(s). Remove children first."},
            )

        self.session.delete(topic)
        self.session.commit()

        return {"message": "Topic deleted successfully", "id": topic_id}

    def reorder_topics(self, order: list) -> dict:
        """Reorder topics. Accepts list of {id, display_order}."""
        for entry in order:
            topic_id = entry.get("id") if isinstance(entry, dict) else None
            display_order = entry.get("display_order") if isinstance(entry, dict) else None
            if topic_id is not None and display_order is not None:
                topic = self.session.query(LibraryTopic).filter(LibraryTopic.id == topic_id).first()
                if topic:
                    topic.display_order = display_order

        self.session.commit()
        return {"message": "Topics reordered successfully"}
