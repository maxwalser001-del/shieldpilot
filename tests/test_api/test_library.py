"""Tests for the Library (Prompts & Skills) API endpoints.

Skipped: Library feature removed for initial launch simplification.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(reason="Library feature removed for initial launch")
from fastapi.testclient import TestClient

from sentinelai.api.app import create_app
from sentinelai.api import deps
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger


@pytest.fixture
def app(test_config, db_path):
    """Create a test FastAPI app with test config."""
    # Reset singletons
    deps.reset_singletons()

    # Enable billing so paywall logic applies
    test_config.billing.enabled = True
    test_config.billing.tier = "free"

    # Override the config and logger
    masker = SecretsMasker(test_config.secrets_patterns)
    logger = BlackboxLogger(config=test_config.logging, masker=masker, db_path=db_path)

    deps._config = test_config
    deps._logger = logger

    application = create_app()
    yield application

    # Clean up
    deps.reset_singletons()


@pytest.fixture
def client(app):
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def auth_headers(client, test_config):
    """Get auth headers by logging in as admin."""
    response = client.post("/api/auth/login", json={
        "username": test_config.auth.default_admin_user,
        "password": test_config.auth.default_admin_password,
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def free_user_headers(client):
    """Get auth headers for a free (non-admin) user."""
    # Register a new user (free tier by default)
    email = f"freeuser_{id(__name__)}@example.com"
    reg_response = client.post("/api/auth/register", json={
        "email": email,
        "password": "validpassword123",
        "tos_accepted": True,
    })
    assert reg_response.status_code == 200
    token = reg_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_library_items(client, auth_headers):
    """Create sample library items for testing."""
    items = []

    # Create 3 items
    for i in range(3):
        response = client.post("/api/library", json={
            "type": "prompt" if i % 2 == 0 else "skill",
            "title": f"Test Item {i + 1}",
            "tags": ["test", f"tag{i}"],
            "short_preview": f"Short preview for item {i + 1}",
            "full_content": f"Full content for item {i + 1}. This is secret data!",
            "is_published": True,
        }, headers=auth_headers)
        assert response.status_code == 200
        items.append(response.json())

    return items


class TestLibraryPaywall:
    """Test paywall enforcement for library access."""

    def test_free_user_first_item_has_full_content(
        self, client, free_user_headers, sample_library_items
    ):
        """Free user can see full_content of the first item only."""
        response = client.get("/api/library", headers=free_user_headers)
        assert response.status_code == 200
        data = response.json()

        # First item should have full content
        first_item = data["items"][0]
        assert first_item["full_content"] is not None
        assert first_item["full_content_locked"] is False

    def test_free_user_second_item_no_full_content(
        self, client, free_user_headers, sample_library_items
    ):
        """Free user should NOT see full_content for items beyond the first."""
        response = client.get("/api/library", headers=free_user_headers)
        assert response.status_code == 200
        data = response.json()

        # Should have multiple items
        assert len(data["items"]) >= 2

        # Second item and beyond should have locked content
        for i, item in enumerate(data["items"][1:], start=1):
            assert item["full_content"] is None, f"Item {i + 1} should have null full_content"
            assert item["full_content_locked"] is True, f"Item {i + 1} should be locked"

    def test_free_user_detail_endpoint_locked_item(
        self, client, free_user_headers, sample_library_items
    ):
        """GET /api/library/{id} should return locked state for non-first items."""
        # Get the second item ID
        list_response = client.get("/api/library", headers=free_user_headers)
        items = list_response.json()["items"]
        assert len(items) >= 2

        # Fetch second item directly
        second_item_id = items[1]["id"]
        response = client.get(f"/api/library/{second_item_id}", headers=free_user_headers)
        assert response.status_code == 200
        data = response.json()

        # Should be locked
        assert data["full_content"] is None
        assert data["full_content_locked"] is True

    def test_admin_all_items_have_full_content(
        self, client, auth_headers, sample_library_items
    ):
        """Admin users should see full_content on all items."""
        response = client.get("/api/library", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["full_content"] is not None, f"Item {item['id']} should have content"
            assert item["full_content_locked"] is False

    def test_user_has_pro_access_flag(
        self, client, free_user_headers, auth_headers, sample_library_items
    ):
        """Response should correctly indicate if user has pro access."""
        # Free user
        free_response = client.get("/api/library", headers=free_user_headers)
        assert free_response.json()["user_has_pro_access"] is False

        # Admin user
        admin_response = client.get("/api/library", headers=auth_headers)
        assert admin_response.json()["user_has_pro_access"] is True


class TestLibraryAdminCRUD:
    """Test admin CRUD operations on library items."""

    def test_admin_can_create_item(self, client, auth_headers):
        """Admin can create a new library item."""
        response = client.post("/api/library", json={
            "type": "prompt",
            "title": "New Prompt",
            "tags": ["new", "test"],
            "short_preview": "A short preview",
            "full_content": "Full content here",
            "is_published": False,
        }, headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "New Prompt"
        assert data["type"] == "prompt"
        assert data["is_published"] is False
        assert "id" in data

    def test_non_admin_cannot_create_item(self, client, free_user_headers):
        """Non-admin users should get 403 when trying to create items."""
        response = client.post("/api/library", json={
            "type": "prompt",
            "title": "Unauthorized Item",
            "tags": [],
            "short_preview": "Preview",
            "full_content": "Content",
            "is_published": False,
        }, headers=free_user_headers)

        assert response.status_code == 403

    def test_admin_can_update_item(self, client, auth_headers, sample_library_items):
        """Admin can update an existing library item."""
        item_id = sample_library_items[0]["id"]

        response = client.put(f"/api/library/{item_id}", json={
            "title": "Updated Title",
            "is_published": False,
        }, headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Updated Title"
        assert data["is_published"] is False

    def test_admin_can_delete_item(self, client, auth_headers, sample_library_items):
        """Admin can delete a library item."""
        item_id = sample_library_items[0]["id"]

        response = client.delete(f"/api/library/{item_id}", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["id"] == item_id

        # Verify it's gone
        get_response = client.get(f"/api/library/{item_id}", headers=auth_headers)
        assert get_response.status_code == 404

    def test_unpublished_items_hidden_from_users(
        self, client, free_user_headers, auth_headers
    ):
        """Non-admin users should not see unpublished items."""
        # Create an unpublished item
        client.post("/api/library", json={
            "type": "skill",
            "title": "Unpublished Skill",
            "tags": ["hidden"],
            "short_preview": "Hidden preview",
            "full_content": "Hidden content",
            "is_published": False,
        }, headers=auth_headers)

        # Free user should not see it
        free_response = client.get("/api/library", headers=free_user_headers)
        titles = [item["title"] for item in free_response.json()["items"]]
        assert "Unpublished Skill" not in titles

    def test_admin_sees_unpublished_items(self, client, auth_headers):
        """Admin endpoint should include unpublished items."""
        # Create an unpublished item
        create_response = client.post("/api/library", json={
            "type": "skill",
            "title": "Admin Only Skill",
            "tags": ["admin"],
            "short_preview": "Admin preview",
            "full_content": "Admin content",
            "is_published": False,
        }, headers=auth_headers)
        assert create_response.status_code == 200

        # Admin endpoint should show it
        admin_response = client.get("/api/library/admin", headers=auth_headers)
        assert admin_response.status_code == 200
        titles = [item["title"] for item in admin_response.json()["items"]]
        assert "Admin Only Skill" in titles


class TestLibraryValidation:
    """Test input validation for library endpoints."""

    def test_create_requires_valid_type(self, client, auth_headers):
        """Type must be 'prompt' or 'skill'."""
        response = client.post("/api/library", json={
            "type": "invalid",
            "title": "Test",
            "tags": [],
            "short_preview": "Preview",
            "full_content": "Content",
        }, headers=auth_headers)

        assert response.status_code == 400
        assert "prompt" in response.json()["detail"]["error"].lower() or "skill" in response.json()["detail"]["error"].lower()

    def test_update_validates_type(self, client, auth_headers, sample_library_items):
        """Update should validate type if provided."""
        item_id = sample_library_items[0]["id"]

        response = client.put(f"/api/library/{item_id}", json={
            "type": "invalid_type",
        }, headers=auth_headers)

        assert response.status_code == 400

    def test_get_nonexistent_item_returns_404(self, client, auth_headers):
        """GET /api/library/{id} should return 404 for non-existent items."""
        response = client.get("/api/library/99999", headers=auth_headers)
        assert response.status_code == 404


class TestLibraryFiltering:
    """Test filtering and pagination of library items."""

    def test_filter_by_type(self, client, auth_headers, sample_library_items):
        """Can filter library items by type."""
        # Filter prompts only
        prompt_response = client.get("/api/library?type=prompt", headers=auth_headers)
        assert prompt_response.status_code == 200
        prompts = prompt_response.json()["items"]
        for item in prompts:
            assert item["type"] == "prompt"

        # Filter skills only
        skill_response = client.get("/api/library?type=skill", headers=auth_headers)
        assert skill_response.status_code == 200
        skills = skill_response.json()["items"]
        for item in skills:
            assert item["type"] == "skill"

    def test_pagination(self, client, auth_headers, sample_library_items):
        """Pagination should work correctly."""
        # Get first page with limit 1
        response = client.get("/api/library?limit=1&offset=0", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 1
        assert data["limit"] == 1
        assert data["offset"] == 0
        assert data["total"] >= 3  # We created 3 items
        assert data["pages"] >= 3


class TestLibraryTopics:
    """Test hierarchical topic CRUD and constraints."""

    def test_create_top_level_topic(self, client, auth_headers):
        """POST creates a top-level topic with auto-generated slug."""
        response = client.post("/api/library/topics", json={
            "name": "App Coding",
            "icon": "\U0001f4bb",
        }, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "App Coding"
        assert data["slug"] == "app-coding"
        assert data["parent_id"] is None

    def test_create_sub_topic(self, client, auth_headers):
        """POST with parent_id creates a child topic."""
        parent = client.post("/api/library/topics", json={
            "name": "Security Topics",
        }, headers=auth_headers).json()

        response = client.post("/api/library/topics", json={
            "name": "Network Security",
            "parent_id": parent["id"],
        }, headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["parent_id"] == parent["id"]

    def test_cannot_nest_3_levels(self, client, auth_headers):
        """Cannot create a topic nested 3 levels deep."""
        parent = client.post("/api/library/topics", json={
            "name": "Level One",
        }, headers=auth_headers).json()
        child = client.post("/api/library/topics", json={
            "name": "Level Two",
            "parent_id": parent["id"],
        }, headers=auth_headers).json()

        response = client.post("/api/library/topics", json={
            "name": "Level Three",
            "parent_id": child["id"],
        }, headers=auth_headers)
        assert response.status_code == 400
        assert "2 levels" in response.json()["detail"]["error"]

    def test_list_topics_tree(self, client, auth_headers):
        """GET /api/library/topics returns tree with children nested."""
        parent = client.post("/api/library/topics", json={
            "name": "Coding Skills",
        }, headers=auth_headers).json()
        client.post("/api/library/topics", json={
            "name": "Backend",
            "parent_id": parent["id"],
        }, headers=auth_headers)

        response = client.get("/api/library/topics", headers=auth_headers)
        assert response.status_code == 200
        topics = response.json()["topics"]
        coding = next((t for t in topics if t["name"] == "Coding Skills"), None)
        assert coding is not None
        assert len(coding["children"]) >= 1
        assert any(c["name"] == "Backend" for c in coding["children"])

    def test_delete_empty_topic(self, client, auth_headers):
        """DELETE on empty topic succeeds."""
        topic = client.post("/api/library/topics", json={
            "name": "Temporary",
        }, headers=auth_headers).json()

        response = client.delete(
            f"/api/library/topics/{topic['id']}", headers=auth_headers
        )
        assert response.status_code == 200

    def test_cannot_delete_topic_with_items(self, client, auth_headers):
        """DELETE on topic with items returns 400."""
        topic = client.post("/api/library/topics", json={
            "name": "Has Items",
        }, headers=auth_headers).json()

        client.post("/api/library", json={
            "type": "prompt",
            "title": "Test Prompt In Topic",
            "tags": [],
            "short_preview": "preview",
            "full_content": "full content here",
            "topic_id": topic["id"],
            "is_published": True,
        }, headers=auth_headers)

        response = client.delete(
            f"/api/library/topics/{topic['id']}", headers=auth_headers
        )
        assert response.status_code == 400
        assert "items" in response.json()["detail"]["error"].lower()

    def test_filter_items_by_topic(self, client, auth_headers):
        """GET /api/library?topic_id=N returns only items in that topic."""
        topic = client.post("/api/library/topics", json={
            "name": "Filter Test Topic",
        }, headers=auth_headers).json()

        # Create item in the topic
        client.post("/api/library", json={
            "type": "skill",
            "title": "Skill In Topic",
            "tags": [],
            "short_preview": "preview",
            "full_content": "content",
            "topic_id": topic["id"],
            "is_published": True,
        }, headers=auth_headers)

        # Create item without topic
        client.post("/api/library", json={
            "type": "skill",
            "title": "Skill Without Topic",
            "tags": [],
            "short_preview": "preview",
            "full_content": "content",
            "is_published": True,
        }, headers=auth_headers)

        response = client.get(
            f"/api/library?topic_id={topic['id']}", headers=auth_headers
        )
        assert response.status_code == 200
        items = response.json()["items"]
        assert len(items) >= 1
        assert all(i["topic_id"] == topic["id"] for i in items)

    def test_non_admin_cannot_create_topic(self, client):
        """Non-admin user should get 403 when trying to create a topic."""
        reg = client.post("/api/auth/register", json={
            "email": "topictest@example.com",
            "password": "validpassword123",
            "tos_accepted": True,
        })
        assert reg.status_code == 200
        token = reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        response = client.post("/api/library/topics", json={
            "name": "Forbidden Topic",
        }, headers=headers)
        assert response.status_code == 403
