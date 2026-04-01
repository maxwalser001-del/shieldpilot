"""Chain hashing for tamper-evident logging.

Each log entry's hash depends on its content and the previous entry's hash,
forming a chain. Any modification to a past entry breaks the chain from that
point forward, making tampering detectable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from sentinelai.core.models import ChainVerificationResult

# Seed used for the first entry in every chain
GENESIS_SEED = "SENTINEL_GENESIS_v1"


class ChainHasher:
    """Computes and verifies tamper-evident hash chains."""

    @staticmethod
    def compute_hash(entry_data: str, previous_hash: str) -> str:
        """Compute SHA-256 hash of entry data concatenated with previous hash.

        Args:
            entry_data: Serialized entry content (JSON string).
            previous_hash: Hash of the previous entry, or GENESIS_SEED for first entry.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        payload = f"{entry_data}|{previous_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_genesis_hash(entry_data: str) -> str:
        """Compute hash for the first entry in a chain."""
        return ChainHasher.compute_hash(entry_data, GENESIS_SEED)

    @staticmethod
    def serialize_for_hashing(data: Dict[str, Any]) -> str:
        """Deterministically serialize data for hash computation.

        Uses sorted keys and no whitespace to ensure consistent hashing
        regardless of field insertion order.
        """
        return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def verify_chain(entries: List[Dict[str, Any]]) -> ChainVerificationResult:
        """Verify the integrity of a chain of log entries.

        Each entry dict must contain 'chain_hash', 'previous_hash', and the
        data fields used for hashing.

        Args:
            entries: List of entry dicts ordered by id ascending.

        Returns:
            ChainVerificationResult with verification outcome.
        """
        if not entries:
            return ChainVerificationResult(
                valid=True,
                total_entries=0,
                verified_entries=0,
                message="No entries to verify.",
            )

        verified = 0

        for i, entry in enumerate(entries):
            # Extract stored hashes
            stored_hash = entry.get("chain_hash", "")
            stored_previous = entry.get("previous_hash", "")

            # Rebuild the hashable data (exclude metadata fields)
            hashable = {
                k: v
                for k, v in entry.items()
                if k not in ("id", "chain_hash", "previous_hash")
            }
            entry_data = ChainHasher.serialize_for_hashing(hashable)

            # Determine expected previous hash
            if i == 0:
                expected_previous = GENESIS_SEED
            else:
                expected_previous = entries[i - 1].get("chain_hash", "")

            # Verify previous_hash pointer
            if stored_previous != expected_previous:
                return ChainVerificationResult(
                    valid=False,
                    total_entries=len(entries),
                    verified_entries=verified,
                    first_broken_entry=entry.get("id", i),
                    message=f"Chain broken at entry {entry.get('id', i)}: "
                    f"previous_hash mismatch.",
                )

            # Recompute and verify chain_hash
            expected_hash = ChainHasher.compute_hash(entry_data, stored_previous)
            if stored_hash != expected_hash:
                return ChainVerificationResult(
                    valid=False,
                    total_entries=len(entries),
                    verified_entries=verified,
                    first_broken_entry=entry.get("id", i),
                    message=f"Chain broken at entry {entry.get('id', i)}: "
                    f"content hash mismatch (tampering detected).",
                )

            verified += 1

        return ChainVerificationResult(
            valid=True,
            total_entries=len(entries),
            verified_entries=verified,
            message=f"All {verified} entries verified successfully.",
        )
