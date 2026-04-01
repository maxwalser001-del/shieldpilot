"""Library endpoints: items, topics, categories, CRUD."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_db_session,
    require_admin,
    require_verified_email,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.services.library_service import LibraryService

router = APIRouter()


# ── Request models ────────────────────────────────────────────


class LibraryItemCreate(BaseModel):
    """Request model for creating a library item."""
    type: str  # "prompt" or "skill"
    title: str
    tags: list[str] = []
    short_preview: str
    full_content: str
    category: Optional[str] = None
    display_order: int = 0
    is_published: bool = False
    topic_id: Optional[int] = None


class LibraryItemUpdate(BaseModel):
    """Request model for updating a library item."""
    type: Optional[str] = None
    title: Optional[str] = None
    tags: Optional[list[str]] = None
    short_preview: Optional[str] = None
    full_content: Optional[str] = None
    category: Optional[str] = None
    display_order: Optional[int] = None
    is_published: Optional[bool] = None
    topic_id: Optional[int] = None


class LibraryTopicCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    parent_id: Optional[int] = None
    display_order: int = 0


class LibraryTopicUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    parent_id: Optional[int] = None
    display_order: Optional[int] = None


class LibraryTopicReorder(BaseModel):
    order: list


# ── Library Items ─────────────────────────────────────────────


@router.get(
    "/api/library",
    tags=["Library"],
    summary="List library items",
    description="Return published library items (prompts and skills) with optional filtering. Full content is locked behind the Pro paywall for free-tier users.",
    response_description="Paginated published library items with paywall enforcement",
)
def list_library_items(
    type: Optional[str] = Query(None, description="Filter by type: prompt or skill"),
    category: Optional[str] = Query(None, description="Filter by category"),
    topic_id: Optional[int] = Query(None, description="Filter by topic ID (includes child topics)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """List published library items with paywall enforcement.

    Non-paying users can only access full_content for the first item.
    """
    service = LibraryService(session, config)
    return service.list_items(type, category, topic_id, limit, offset, user)


@router.get(
    "/api/library/admin",
    tags=["Library"],
    summary="List all library items (admin)",
    description="Return all library items including unpublished drafts. Admin only. No paywall restrictions apply.",
    response_description="All library items including unpublished drafts",
)
def list_library_items_admin(
    type: Optional[str] = Query(None, description="Filter by type: prompt or skill"),
    topic_id: Optional[int] = Query(None, description="Filter by topic ID (includes child topics)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """List ALL library items including unpublished (admin only)."""
    service = LibraryService(session, config)
    return service.list_items_admin(type, topic_id, limit, offset, user)


@router.get(
    "/api/library/categories",
    tags=["Library"],
    summary="List library categories",
    description="Return a list of all library categories with the count of published items in each.",
    response_description="Category names with published item counts",
)
def list_library_categories(
    user: TokenData = Depends(require_verified_email),
    session: Session = Depends(get_db_session),
):
    """Get list of all categories with item counts."""
    service = LibraryService(session, None)
    return service.list_categories()


# ── Library Topics (hierarchical) ──────────────────────────────


@router.get(
    "/api/library/topics",
    tags=["Library"],
    summary="List library topics",
    description="Return the hierarchical topic tree with item counts and optional child topics for sidebar navigation.",
    response_description="Hierarchical topic tree with item counts",
)
def list_library_topics(
    user: TokenData = Depends(require_verified_email),
    session: Session = Depends(get_db_session),
):
    """Get hierarchical topic tree with item counts."""
    service = LibraryService(session, None)
    return service.list_topics()


@router.post(
    "/api/library/topics",
    tags=["Library"],
    summary="Create library topic",
    description="Create a new library topic with name, icon, and optional parent for hierarchical organization. Admin only.",
    response_description="The newly created topic with auto-generated slug",
)
def create_library_topic(
    request: LibraryTopicCreate,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Create a new topic (admin only)."""
    service = LibraryService(session, None)
    return service.create_topic(
        name=request.name,
        slug=request.slug,
        description=request.description,
        icon=request.icon,
        parent_id=request.parent_id,
        display_order=request.display_order,
    )


@router.patch(
    "/api/library/topics/reorder",
    tags=["Library"],
    summary="Reorder library topics",
    description="Update the display order of library topics. Accepts a list of topic IDs with new display_order values. Admin only.",
    response_description="Confirmation that topic order was updated",
)
def reorder_library_topics(
    request: LibraryTopicReorder,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Reorder topics (admin only). Accepts list of {id, display_order}."""
    service = LibraryService(session, None)
    return service.reorder_topics(request.order)


@router.put(
    "/api/library/topics/{topic_id}",
    tags=["Library"],
    summary="Update library topic",
    description="Update an existing library topic's name, icon, description, or parent assignment. Admin only.",
    response_description="The updated topic data",
)
def update_library_topic(
    topic_id: int,
    request: LibraryTopicUpdate,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Update a topic (admin only)."""
    service = LibraryService(session, None)
    return service.update_topic(
        topic_id,
        name=request.name,
        slug=request.slug,
        description=request.description,
        icon=request.icon,
        parent_id=request.parent_id,
        display_order=request.display_order,
    )


@router.delete(
    "/api/library/topics/{topic_id}",
    tags=["Library"],
    summary="Delete library topic",
    description="Delete a library topic. Fails if the topic still has items or child topics. Admin only.",
    response_description="Confirmation of topic deletion",
)
def delete_library_topic(
    topic_id: int,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Delete a topic (admin only). Fails if topic has items or children."""
    service = LibraryService(session, None)
    return service.delete_topic(topic_id)


@router.get(
    "/api/library/{item_id}",
    tags=["Library"],
    summary="Get library item",
    description="Return a single library item by ID. Full content access is restricted to Pro-tier users; free-tier users see the preview only.",
    response_description="Single library item with paywall-enforced content access",
)
def get_library_item(
    item_id: int,
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Get a single library item by ID.

    Returns 403 if user doesn't have access to full content.
    """
    service = LibraryService(session, config)
    return service.get_item(item_id, user)


@router.post(
    "/api/library",
    tags=["Library"],
    summary="Create library item",
    description="Create a new library item (prompt or skill) with title, content, tags, and optional topic assignment. Admin only.",
    response_description="The newly created library item",
)
def create_library_item(
    request: LibraryItemCreate,
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Create a new library item (admin only)."""
    service = LibraryService(session, config)
    return service.create_item(
        type=request.type,
        title=request.title,
        tags=request.tags,
        short_preview=request.short_preview,
        full_content=request.full_content,
        category=request.category,
        display_order=request.display_order,
        is_published=request.is_published,
        topic_id=request.topic_id,
        user=user,
    )


@router.put(
    "/api/library/{item_id}",
    tags=["Library"],
    summary="Update library item",
    description="Update an existing library item's title, content, tags, category, or publication status. Admin only.",
    response_description="The updated library item",
)
def update_library_item(
    item_id: int,
    request: LibraryItemUpdate,
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Update a library item (admin only)."""
    service = LibraryService(session, config)
    return service.update_item(
        item_id,
        type=request.type,
        title=request.title,
        tags=request.tags,
        short_preview=request.short_preview,
        full_content=request.full_content,
        category=request.category,
        display_order=request.display_order,
        is_published=request.is_published,
        topic_id=request.topic_id,
    )


@router.delete(
    "/api/library/{item_id}",
    tags=["Library"],
    summary="Delete library item",
    description="Permanently delete a library item by ID. Admin only.",
    response_description="Confirmation of item deletion",
)
def delete_library_item(
    item_id: int,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Delete a library item (admin only)."""
    service = LibraryService(session, None)
    return service.delete_item(item_id)
