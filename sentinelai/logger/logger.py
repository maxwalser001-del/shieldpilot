"""BlackboxLogger — tamper-evident activity recorder.

All data is masked through SecretsMasker before storage.
Every entry is chain-hashed for tamper detection.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine, desc, text
from sqlalchemy.orm import Session, joinedload, sessionmaker

from sentinelai.core.config import LoggingConfig
from sentinelai.core.constants import Action, IncidentSeverity, RiskCategory
from sentinelai.core.models import (
    ChainVerificationResult,
    DashboardStats,
    RiskAssessment,
    ScanResult,
)
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger.chain import GENESIS_SEED, ChainHasher
from sentinelai.logger.database import (
    Base,
    CommandLog,
    FileChangeLog,
    IncidentLog,
    NetworkAccessLog,
    PromptScanLog,
    init_database,
)


# Sentinel value to distinguish "no tenant_id argument" from tenant_id=None.
# None means "filter for rows with tenant_id IS NULL" (global/no-tenant),
# while _UNSET means "don't add a tenant_id filter at all" (backwards compat).
_UNSET = object()

# Required fields that MUST be present in every log entry of each type.
# These are the minimum fields needed for audit compliance.
REQUIRED_LOG_FIELDS = {
    "commands": [
        "timestamp", "command", "raw_command_hash", "risk_score",
        "risk_level", "action_taken", "executed", "signals_json",
        "chain_hash", "previous_hash",
    ],
    "incidents": [
        "timestamp", "severity", "category", "title", "description",
        "chain_hash", "previous_hash",
    ],
    "prompt_scans": [
        "timestamp", "source", "content_hash", "overall_score",
        "threat_count", "chain_hash", "previous_hash",
    ],
    "file_changes": [
        "timestamp", "file_path", "change_type", "hash_before",
        "hash_after", "chain_hash", "previous_hash",
    ],
    "network_access": [
        "timestamp", "destination", "port", "protocol",
        "direction", "blocked", "chain_hash", "previous_hash",
    ],
}

# Fields included in the chain hash for each table type.
# Must match the `hashable` dicts used in log_command, log_prompt_scan, etc.
_HASHABLE_FIELDS = {
    "commands": ["timestamp", "command", "raw_command_hash", "risk_score",
                 "risk_level", "action_taken", "executed", "signals_json"],
    "prompt_scans": ["timestamp", "source", "content_hash", "overall_score",
                     "threat_count"],
    "file_changes": ["timestamp", "file_path", "change_type", "hash_before",
                     "hash_after"],
    "network_access": ["timestamp", "destination", "port", "protocol",
                       "direction", "blocked"],
    "incidents": ["timestamp", "severity", "category", "title"],
}


class BlackboxLogger:
    """Tamper-evident logging system for all ShieldPilot activity.

    Every log entry is:
    1. Passed through SecretsMasker
    2. Serialized to JSON for hashing
    3. Chain-hashed (content + previous_hash)
    4. Stored in SQLite
    """

    def __init__(
        self,
        config: Optional[LoggingConfig] = None,
        masker: Optional[SecretsMasker] = None,
        db_path: Optional[str] = None,
    ):
        self.config = config or LoggingConfig()
        self.masker = masker or SecretsMasker()
        path = db_path or self.config.database
        self._engine, self._Session = init_database(path)

    def _get_session(self) -> Session:
        return self._Session()

    def _get_last_hash(self, session: Session, table_class: type) -> str:
        """Get the chain_hash of the most recent entry in a table."""
        last = (
            session.query(table_class.chain_hash)
            .order_by(desc(table_class.id))
            .first()
        )
        return last[0] if last else GENESIS_SEED

    def _compute_chain_hash(
        self, data: Dict[str, Any], previous_hash: str
    ) -> str:
        """Compute chain hash for an entry."""
        serialized = ChainHasher.serialize_for_hashing(data)
        return ChainHasher.compute_hash(serialized, previous_hash)

    def log_command(
        self,
        assessment: RiskAssessment,
        output: Optional[str] = None,
        executed: bool = False,
        exit_code: Optional[int] = None,
        working_directory: Optional[str] = None,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> int:
        """Log a command evaluation and optional execution result.

        Returns the database ID of the created entry.
        """
        session = self._get_session()
        try:
            # Mask sensitive data
            masked_command = self.masker.mask(assessment.command)
            masked_output = self.masker.mask(output[:1000]) if output else None
            raw_hash = hashlib.sha256(
                assessment.command.encode("utf-8")
            ).hexdigest()

            signals_data = [s.model_dump() for s in assessment.signals]
            signals_json = json.dumps(signals_data, default=str)

            # Build hashable data dict
            now = datetime.utcnow()
            hashable = {
                "timestamp": str(now),
                "command": masked_command,
                "raw_command_hash": raw_hash,
                "risk_score": assessment.final_score,
                "risk_level": assessment.risk_level.value,
                "action_taken": assessment.action.value,
                "executed": executed,
                "signals_json": signals_json,
            }

            previous_hash = self._get_last_hash(session, CommandLog)
            chain_hash = self._compute_chain_hash(hashable, previous_hash)

            entry = CommandLog(
                timestamp=now,
                command=masked_command,
                raw_command_hash=raw_hash,
                working_directory=working_directory,
                risk_score=assessment.final_score,
                risk_level=assessment.risk_level.value,
                action_taken=assessment.action.value,
                executed=executed,
                exit_code=exit_code,
                output_snippet=masked_output,
                signals_json=signals_json,
                llm_used=assessment.llm_used,
                llm_reasoning=assessment.llm_reasoning,
                execution_time_ms=assessment.execution_time_ms,
                tenant_id=tenant_id,
                session_id=session_id,
                chain_hash=chain_hash,
                previous_hash=previous_hash,
            )
            session.add(entry)
            session.commit()
            return entry.id
        finally:
            session.close()

    def log_prompt_scan(
        self,
        scan_result: ScanResult,
        tenant_id: Optional[str] = None,
    ) -> int:
        """Log a prompt injection scan result."""
        session = self._get_session()
        try:
            content_hash = hashlib.sha256(
                scan_result.source.encode("utf-8")
            ).hexdigest()
            threats_data = [t.model_dump() for t in scan_result.threats]
            threats_json = json.dumps(threats_data, default=str)

            now = datetime.utcnow()
            hashable = {
                "timestamp": str(now),
                "source": scan_result.source,
                "content_hash": content_hash,
                "overall_score": scan_result.overall_score,
                "threat_count": len(scan_result.threats),
            }

            previous_hash = self._get_last_hash(session, PromptScanLog)
            chain_hash = self._compute_chain_hash(hashable, previous_hash)

            entry = PromptScanLog(
                timestamp=now,
                source=scan_result.source,
                content_hash=content_hash,
                content_length=len(scan_result.source),
                overall_score=scan_result.overall_score,
                threat_count=len(scan_result.threats),
                threats_json=threats_json,
                recommendation=scan_result.recommendation,
                tenant_id=tenant_id,
                chain_hash=chain_hash,
                previous_hash=previous_hash,
            )
            session.add(entry)
            session.commit()
            return entry.id
        finally:
            session.close()

    def log_file_change(
        self,
        file_path: str,
        change_type: str,
        hash_before: Optional[str] = None,
        hash_after: Optional[str] = None,
        size_before: Optional[int] = None,
        size_after: Optional[int] = None,
        command_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> int:
        """Log a file system change."""
        session = self._get_session()
        try:
            masked_path = self.masker.mask(file_path)
            now = datetime.utcnow()
            hashable = {
                "timestamp": str(now),
                "file_path": masked_path,
                "change_type": change_type,
            }

            previous_hash = self._get_last_hash(session, FileChangeLog)
            chain_hash = self._compute_chain_hash(hashable, previous_hash)

            entry = FileChangeLog(
                timestamp=now,
                file_path=masked_path,
                change_type=change_type,
                hash_before=hash_before,
                hash_after=hash_after,
                size_before=size_before,
                size_after=size_after,
                command_id=command_id,
                tenant_id=tenant_id,
                chain_hash=chain_hash,
                previous_hash=previous_hash,
            )
            session.add(entry)
            session.commit()
            return entry.id
        finally:
            session.close()

    def log_network_access(
        self,
        destination: str,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        direction: str = "outbound",
        blocked: bool = False,
        command_id: Optional[int] = None,
        bytes_sent: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> int:
        """Log a network access event."""
        session = self._get_session()
        try:
            now = datetime.utcnow()
            hashable = {
                "timestamp": str(now),
                "destination": destination,
                "port": port,
                "blocked": blocked,
            }

            previous_hash = self._get_last_hash(session, NetworkAccessLog)
            chain_hash = self._compute_chain_hash(hashable, previous_hash)

            entry = NetworkAccessLog(
                timestamp=now,
                destination=destination,
                port=port,
                protocol=protocol,
                direction=direction,
                blocked=blocked,
                command_id=command_id,
                bytes_sent=bytes_sent,
                tenant_id=tenant_id,
                chain_hash=chain_hash,
                previous_hash=previous_hash,
            )
            session.add(entry)
            session.commit()
            return entry.id
        finally:
            session.close()

    def log_incident(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        evidence: str,
        command_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> int:
        """Log a security incident."""
        session = self._get_session()
        try:
            masked_evidence = self.masker.mask(evidence)
            now = datetime.utcnow()
            hashable = {
                "timestamp": str(now),
                "severity": severity,
                "category": category,
                "title": title,
            }

            previous_hash = self._get_last_hash(session, IncidentLog)
            chain_hash = self._compute_chain_hash(hashable, previous_hash)

            entry = IncidentLog(
                timestamp=now,
                severity=severity,
                category=category,
                title=title,
                description=description,
                evidence=masked_evidence,
                command_id=command_id,
                tenant_id=tenant_id,
                chain_hash=chain_hash,
                previous_hash=previous_hash,
            )
            session.add(entry)
            session.commit()
            return entry.id
        finally:
            session.close()

    def get_command_by_id(self, command_id: int) -> Optional[CommandLog]:
        """Get a single command log by ID. Returns None if not found."""
        session = self._get_session()
        try:
            return session.get(CommandLog, command_id)
        finally:
            session.close()

    def query_commands(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        risk_min: Optional[int] = None,
        risk_max: Optional[int] = None,
        action: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = _UNSET,
    ) -> tuple:
        """Query command logs with filters. Returns (items, total_count).

        Args:
            tenant_id: If provided (non-_UNSET), filter by tenant_id.
                       None means "no tenant" (global). _UNSET means "don't filter".
        """
        session = self._get_session()
        try:
            query = session.query(CommandLog)

            # Multi-tenant isolation: scope to tenant when provided
            if tenant_id is not _UNSET:
                query = query.filter(CommandLog.tenant_id == tenant_id)

            if since:
                query = query.filter(CommandLog.timestamp >= since)
            if until:
                query = query.filter(CommandLog.timestamp <= until)
            if risk_min is not None:
                query = query.filter(CommandLog.risk_score >= risk_min)
            if risk_max is not None:
                query = query.filter(CommandLog.risk_score <= risk_max)
            if action:
                query = query.filter(CommandLog.action_taken == action)
            if search:
                query = query.filter(CommandLog.command.contains(search))

            total = query.count()
            items = (
                query.order_by(desc(CommandLog.timestamp))
                .offset(offset)
                .limit(limit)
                .all()
            )
            return items, total
        finally:
            session.close()

    def query_incidents(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
        since: Optional[datetime] = None,
        tenant_id: Optional[str] = _UNSET,
    ) -> tuple:
        """Query incidents with filters. Returns (items, total_count).

        Args:
            tenant_id: If provided (non-_UNSET), filter by tenant_id.
                       None means "no tenant" (global). _UNSET means "don't filter".
        """
        session = self._get_session()
        try:
            query = session.query(IncidentLog).options(
                joinedload(IncidentLog.command)
            )

            # Multi-tenant isolation: scope to tenant when provided
            if tenant_id is not _UNSET:
                query = query.filter(IncidentLog.tenant_id == tenant_id)

            if severity:
                query = query.filter(IncidentLog.severity == severity)
            if category:
                query = query.filter(IncidentLog.category == category)
            if resolved is not None:
                query = query.filter(IncidentLog.resolved == resolved)
            if since is not None:
                query = query.filter(IncidentLog.timestamp >= since)

            total = query.count()
            items = (
                query.order_by(desc(IncidentLog.timestamp))
                .offset(offset)
                .limit(limit)
                .all()
            )
            return items, total
        finally:
            session.close()

    def query_scans(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple:
        """Query prompt scan logs. Returns (items, total_count)."""
        session = self._get_session()
        try:
            query = session.query(PromptScanLog)
            total = query.count()
            items = (
                query.order_by(desc(PromptScanLog.id))
                .offset(offset)
                .limit(limit)
                .all()
            )
            return items, total
        finally:
            session.close()

    def resolve_incident(
        self, incident_id: int, resolution_notes: str = ""
    ) -> bool:
        """Mark an incident as resolved."""
        session = self._get_session()
        try:
            incident = session.get(IncidentLog, incident_id)
            if not incident:
                return False
            incident.resolved = True
            incident.resolved_at = datetime.utcnow()
            incident.resolution_notes = resolution_notes
            session.commit()
            return True
        finally:
            session.close()

    def verify_chain(self, table_name: str = "commands") -> ChainVerificationResult:
        """Verify chain integrity for a specific table."""
        table_map = {
            "commands": CommandLog,
            "prompt_scans": PromptScanLog,
            "file_changes": FileChangeLog,
            "network_access": NetworkAccessLog,
            "incidents": IncidentLog,
        }
        table_class = table_map.get(table_name)
        if not table_class:
            return ChainVerificationResult(
                valid=False, message=f"Unknown table: {table_name}"
            )

        hashable_fields = _HASHABLE_FIELDS.get(table_name, [])

        session = self._get_session()
        try:
            entries = (
                session.query(table_class)
                .order_by(table_class.id)
                .all()
            )

            # Convert ORM objects to dicts with only hashable fields + chain fields
            entry_dicts = []
            for e in entries:
                d = {
                    "id": getattr(e, "id"),
                    "chain_hash": getattr(e, "chain_hash"),
                    "previous_hash": getattr(e, "previous_hash"),
                }
                for field in hashable_fields:
                    val = getattr(e, field, None)
                    d[field] = str(val) if field == "timestamp" else val
                entry_dicts.append(d)

            return ChainHasher.verify_chain(entry_dicts)
        finally:
            session.close()

    def verify_chain_with_alert(self, table_name: str) -> ChainVerificationResult:
        """Verify chain and auto-log an incident if tampering is detected."""
        result = self.verify_chain(table_name)
        if not result.valid:
            try:
                self.log_incident(
                    severity="critical",
                    category="tampering",
                    title=f"Chain integrity failure: {table_name}",
                    description=result.message,
                    evidence=f"table={table_name}, first_broken={result.first_broken_entry}",
                )
            except Exception:
                pass  # Best-effort, don't let alerting break verification
        return result

    def reseed_chain(self, table_name: str = "commands") -> ChainVerificationResult:
        """Rebuild the hash chain for a table from scratch.

        Recomputes previous_hash and chain_hash for every entry in order,
        starting from GENESIS_SEED.  Use this to repair a broken chain
        (e.g. after concurrent inserts or manual DB edits).

        Returns a ChainVerificationResult from verifying the reseeded chain.
        """
        table_map = {
            "commands": CommandLog,
            "prompt_scans": PromptScanLog,
            "file_changes": FileChangeLog,
            "network_access": NetworkAccessLog,
            "incidents": IncidentLog,
        }
        table_class = table_map.get(table_name)
        if not table_class:
            return ChainVerificationResult(
                valid=False, message=f"Unknown table: {table_name}"
            )

        hashable_fields = _HASHABLE_FIELDS.get(table_name, [])

        session = self._get_session()
        try:
            entries = (
                session.query(table_class)
                .order_by(table_class.id)
                .all()
            )

            prev_hash = GENESIS_SEED
            for entry in entries:
                # Build the hashable dict (same as verify_chain)
                hashable = {}
                for field in hashable_fields:
                    val = getattr(entry, field, None)
                    hashable[field] = str(val) if field == "timestamp" else val

                chain_hash = self._compute_chain_hash(hashable, prev_hash)

                entry.previous_hash = prev_hash
                entry.chain_hash = chain_hash

                prev_hash = chain_hash

            session.commit()

            # Verify the freshly reseeded chain
            return self.verify_chain(table_name)
        finally:
            session.close()

    def get_stats(self, hours: int = 24, session=None) -> DashboardStats:
        """Get aggregated dashboard statistics for the given time period.

        Args:
            hours: Number of hours to look back for time-windowed stats.
            session: Optional pre-existing DB session. If None, creates and
                closes its own. Pass an existing session from SSE endpoints
                to avoid creating a new session on every poll cycle.
        """
        owns_session = session is None
        if owns_session:
            session = self._get_session()
        try:
            from datetime import timedelta
            from sqlalchemy import func

            cutoff = datetime.utcnow() - timedelta(hours=hours)

            # Time-windowed stats
            total = session.query(CommandLog).filter(
                CommandLog.timestamp >= cutoff
            ).count()
            blocked = session.query(CommandLog).filter(
                CommandLog.timestamp >= cutoff,
                CommandLog.action_taken == "block",
            ).count()
            warned = session.query(CommandLog).filter(
                CommandLog.timestamp >= cutoff,
                CommandLog.action_taken == "warn",
            ).count()
            allowed = session.query(CommandLog).filter(
                CommandLog.timestamp >= cutoff,
                CommandLog.action_taken == "allow",
            ).count()

            # Average risk score
            avg_result = session.query(
                func.avg(CommandLog.risk_score)
            ).filter(CommandLog.timestamp >= cutoff).scalar()
            avg_score = round(float(avg_result), 1) if avg_result else 0.0

            # Incidents (time-windowed)
            total_incidents = session.query(IncidentLog).filter(
                IncidentLog.timestamp >= cutoff
            ).count()
            unresolved = session.query(IncidentLog).filter(
                IncidentLog.timestamp >= cutoff,
                IncidentLog.resolved == False,
            ).count()

            # Scans (time-windowed)
            total_scans = session.query(PromptScanLog).filter(
                PromptScanLog.timestamp >= cutoff
            ).count()

            # All-time stats
            all_time_total = session.query(CommandLog).count()
            all_time_blocked = session.query(CommandLog).filter(
                CommandLog.action_taken == "block"
            ).count()
            all_time_warned = session.query(CommandLog).filter(
                CommandLog.action_taken == "warn"
            ).count()
            all_time_allowed = session.query(CommandLog).filter(
                CommandLog.action_taken == "allow"
            ).count()
            all_time_incidents = session.query(IncidentLog).count()
            all_time_scans = session.query(PromptScanLog).count()

            return DashboardStats(
                total_commands=total,
                blocked_commands=blocked,
                warned_commands=warned,
                allowed_commands=allowed,
                average_risk_score=avg_score,
                total_incidents=total_incidents,
                unresolved_incidents=unresolved,
                total_scans=total_scans,
                all_time_total=all_time_total,
                all_time_blocked=all_time_blocked,
                all_time_warned=all_time_warned,
                all_time_allowed=all_time_allowed,
                all_time_incidents=all_time_incidents,
                all_time_scans=all_time_scans,
            )
        finally:
            if owns_session:
                session.close()
