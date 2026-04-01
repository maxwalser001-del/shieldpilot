"""Built-in risk analyzers."""

from sentinelai.engine.analyzers.credential_access import CredentialAccessAnalyzer
from sentinelai.engine.analyzers.destructive_fs import DestructiveFSAnalyzer
from sentinelai.engine.analyzers.injection import InjectionAnalyzer
from sentinelai.engine.analyzers.malware_patterns import MalwarePatternAnalyzer
from sentinelai.engine.analyzers.network_exfil import NetworkExfilAnalyzer
from sentinelai.engine.analyzers.obfuscation import ObfuscationAnalyzer
from sentinelai.engine.analyzers.persistence import PersistenceAnalyzer
from sentinelai.engine.analyzers.privilege_escalation import PrivilegeEscalationAnalyzer
from sentinelai.engine.analyzers.supply_chain import SupplyChainAnalyzer

ALL_ANALYZERS = [
    DestructiveFSAnalyzer,
    PrivilegeEscalationAnalyzer,
    NetworkExfilAnalyzer,
    CredentialAccessAnalyzer,
    PersistenceAnalyzer,
    ObfuscationAnalyzer,
    MalwarePatternAnalyzer,
    SupplyChainAnalyzer,
    InjectionAnalyzer,
]

__all__ = [
    "DestructiveFSAnalyzer",
    "PrivilegeEscalationAnalyzer",
    "NetworkExfilAnalyzer",
    "CredentialAccessAnalyzer",
    "PersistenceAnalyzer",
    "ObfuscationAnalyzer",
    "MalwarePatternAnalyzer",
    "SupplyChainAnalyzer",
    "InjectionAnalyzer",
    "ALL_ANALYZERS",
]
