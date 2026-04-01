"""Tests for path containment edge cases -- Spec 3 (Protected-Path-Spec).

Covers:
- Basic containment checks
- Prefix-matching bug regression (/etc_backup vs /etc)
- Directory traversal resolution
- Tilde (~) expansion
- Nested paths
- Edge cases (root, empty, nonexistent)
- Symlink resolution
"""

from __future__ import annotations

import os

import pytest

from sentinelai.core.path_utils import is_path_under


# ---------------------------------------------------------------------------
# Basic containment
# ---------------------------------------------------------------------------


class TestIsPathUnder:
    """Test canonical is_path_under utility."""

    def test_child_under_parent(self):
        assert is_path_under("/etc/shadow", "/etc") is True

    def test_child_not_under_parent(self):
        assert is_path_under("/tmp/file", "/etc") is False

    def test_exact_match(self):
        assert is_path_under("/etc", "/etc") is True

    # -- Prefix-matching bug regression --

    def test_etc_backup_not_under_etc(self):
        """Regression: /etc_backup must NOT match /etc (prefix bug)."""
        assert is_path_under("/etc_backup", "/etc") is False

    def test_etc_backup_file_not_under_etc(self):
        assert is_path_under("/etc_backup/file.txt", "/etc") is False

    # -- Directory traversal --

    def test_traversal_resolved(self):
        assert is_path_under("/etc/../etc/shadow", "/etc") is True

    def test_traversal_escapes_parent(self):
        assert is_path_under("/etc/../tmp/file", "/etc") is False

    # -- Tilde expansion --

    def test_tilde_ssh(self):
        assert is_path_under("~/.ssh/id_rsa", "~/.ssh") is True

    def test_tilde_not_under_different_dir(self):
        assert is_path_under("~/.ssh/id_rsa", "~/.aws") is False

    def test_tilde_parent_contains_full_home(self):
        """~ expands to home, so ~/anything should be under ~."""
        assert is_path_under("~/.config/file.txt", "~") is True

    # -- Nested paths --

    def test_deeply_nested(self):
        assert is_path_under("/etc/ssl/certs/ca-bundle.crt", "/etc") is True

    # -- Edge cases --

    def test_root_contains_everything(self):
        assert is_path_under("/etc/shadow", "/") is True

    def test_empty_child(self):
        # Empty string resolves to cwd via Path("").resolve()
        result = is_path_under("", "/etc")
        # Result depends on cwd, just verify no crash
        assert isinstance(result, bool)

    def test_nonexistent_paths(self):
        """Non-existent paths should still work (resolve() doesn't require existence)."""
        assert is_path_under("/nonexistent/child", "/nonexistent") is True

    def test_nonexistent_not_matching(self):
        assert is_path_under("/nonexistent/child", "/other") is False

    # -- Sibling directories --

    def test_sibling_not_matching(self):
        """Sibling directories must not match each other."""
        assert is_path_under("/var/log/syslog", "/var/lib") is False

    def test_parent_not_under_child(self):
        """Parent path is NOT under its own child."""
        assert is_path_under("/etc", "/etc/ssl") is False

    # -- Trailing slashes --

    def test_trailing_slash_on_parent(self):
        """Trailing slash on parent should not affect result."""
        assert is_path_under("/etc/shadow", "/etc/") is True

    def test_trailing_slash_on_child(self):
        """Trailing slash on child should not affect result."""
        assert is_path_under("/etc/shadow/", "/etc") is True


# ---------------------------------------------------------------------------
# Symlink resolution
# ---------------------------------------------------------------------------


class TestIsPathUnderSymlinks:
    """Test symlink resolution in is_path_under."""

    def test_symlink_resolves_to_protected(self, tmp_path):
        """A symlink pointing into a protected dir should be detected."""
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        target_file = protected_dir / "secret.txt"
        target_file.write_text("secret")

        symlink = tmp_path / "innocent_link"
        symlink.symlink_to(target_file)

        assert is_path_under(str(symlink), str(protected_dir)) is True

    def test_symlink_outside_not_matching(self, tmp_path):
        """A symlink pointing outside should not match."""
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("outside")

        symlink = protected_dir / "tricky_link"
        symlink.symlink_to(outside_file)

        # The symlink lives inside protected_dir, but resolves to outside
        assert is_path_under(str(symlink), str(protected_dir)) is False

    def test_symlink_chain(self, tmp_path):
        """A chain of symlinks should resolve to the final target."""
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        target = protected_dir / "real_file.txt"
        target.write_text("data")

        link1 = tmp_path / "link1"
        link1.symlink_to(target)

        link2 = tmp_path / "link2"
        link2.symlink_to(link1)

        assert is_path_under(str(link2), str(protected_dir)) is True

    def test_symlink_dir_to_protected(self, tmp_path):
        """A symlink to a protected directory counts as under that directory."""
        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()

        symlink_dir = tmp_path / "alias"
        symlink_dir.symlink_to(protected_dir)

        # The symlink itself resolves to protected_dir
        assert is_path_under(str(symlink_dir), str(protected_dir)) is True

        # A file accessed through the symlink dir also resolves
        actual_file = protected_dir / "secret.txt"
        actual_file.write_text("secret")
        assert is_path_under(str(symlink_dir / "secret.txt"), str(protected_dir)) is True
