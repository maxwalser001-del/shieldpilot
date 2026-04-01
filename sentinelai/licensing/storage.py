"""License key storage in ~/.shieldpilot/license.key."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# License key file location
_SHIELDPILOT_DIR = Path.home() / ".shieldpilot"
_LICENSE_FILE = _SHIELDPILOT_DIR / "license.key"


def save_key(key_str: str) -> Path:
    """Save a license key to ~/.shieldpilot/license.key.

    Creates the ~/.shieldpilot/ directory if it doesn't exist.
    Sets file permissions to owner-only (0o600).

    Args:
        key_str: License key string (SP-XXXXXXXX-...).

    Returns:
        Path to the saved license file.
    """
    _SHIELDPILOT_DIR.mkdir(parents=True, exist_ok=True)
    _LICENSE_FILE.write_text(key_str.strip() + "\n", encoding="utf-8")
    os.chmod(_LICENSE_FILE, 0o600)
    return _LICENSE_FILE


def load_key() -> Optional[str]:
    """Load a license key from ~/.shieldpilot/license.key.

    Returns:
        License key string, or None if no key file exists.
    """
    if not _LICENSE_FILE.is_file():
        return None
    content = _LICENSE_FILE.read_text(encoding="utf-8").strip()
    if not content:
        return None
    return content


def remove_key() -> bool:
    """Remove the license key file.

    Returns:
        True if the file was removed, False if it didn't exist.
    """
    if _LICENSE_FILE.is_file():
        _LICENSE_FILE.unlink()
        return True
    return False


def get_license_path() -> Path:
    """Return the path where the license key is stored."""
    return _LICENSE_FILE
