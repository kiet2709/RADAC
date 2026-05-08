"""Unified data types fed into every access-control model.

A single AccessRequest carries everything any model could need; each model
ignores the fields it does not understand. This keeps the experimental
comparison fair: every model sees the same request payload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_OBLIGATIONS = "ALLOW_WITH_OBLIGATIONS"
    DENY = "DENY"

    @property
    def is_allow_like(self) -> bool:
        return self in (Decision.ALLOW, Decision.ALLOW_WITH_OBLIGATIONS)


@dataclass
class Subject:
    """Active entity requesting access.

    Carries fields used by every model:
      * MAC reads `clearance_level` (integer lattice).
      * DAC reads `user_id`.
      * RBAC reads `role`.
      * ABAC reads `attributes` (and standard fields).
      * RADAC reads `trust_score`, `device_trust`, `operational_need`.
    """
    user_id: str
    role: str = "employee"
    clearance_level: int = 1                 # 0=public, 1=internal, 2=confidential, 3=secret, 4=top-secret
    department: str = "general"
    trust_score: float = 0.7                 # 0..1, auth + history
    device_trust: float = 0.8                # 0..1, device posture / EDR
    operational_need: float = 0.5            # 0..1, justification strength
    purpose: str = "general"
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def composite_trust(self) -> float:
        return 0.6 * self.trust_score + 0.4 * self.device_trust


@dataclass
class Resource:
    """Object the subject wants to act on.

      * MAC reads `classification_level`.
      * DAC reads `owner` and `acl`.
      * RBAC: any role in `allowed_roles` may access (with permission match).
      * ABAC reads `attributes` (and standard fields).
      * RADAC / Improved RADAC read `sensitivity`, `asset_id`, `cia_weights`.
    """
    resource_id: str
    classification_level: int = 1
    sensitivity: float = 0.5                 # 0..1
    owner: str = "system"
    acl: Dict[str, List[str]] = field(default_factory=dict)   # user_id -> [actions]
    allowed_roles: Dict[str, List[str]] = field(default_factory=dict)  # role -> [actions]
    asset_id: str = ""                       # node id in mission graph
    cia_weights: Tuple[float, float, float] = (1.0, 1.0, 1.0)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Context:
    """Per-request situational data."""
    location: str = "internal"               # internal | branch | vpn | public | unknown
    location_risk: float = 0.2               # 0..1
    time_of_day: str = "business_hours"      # business_hours | after_hours | night
    threat_level: float = 0.3                # 0..1, enterprise-wide
    auth_strength: float = 0.8               # 0..1, MFA strong = high
    extra: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def location_to_risk(loc: str) -> float:
        return {
            "internal": 0.10,
            "branch":   0.30,
            "vpn":      0.40,
            "public":   0.80,
            "unknown":  0.90,
        }.get(loc, 0.50)


@dataclass
class ThreatEvent:
    """Live SOC threat targeting one or more assets.

    Used by the Improved RADAC (paper FURZE+SSA). All other models ignore it.
    """
    threat_id: str
    severity: float = 0.5                    # 0..1 (e.g. CVSS / 10)
    targets: List[str] = field(default_factory=list)   # asset_ids
    affects_c: float = 0.5
    affects_i: float = 0.5
    affects_a: float = 0.5
    description: str = ""


@dataclass
class AccessRequest:
    """Single access request fed to a model."""
    request_id: str
    subject: Subject
    resource: Resource
    action: str = "read"                     # read | write | delete | execute
    context: Context = field(default_factory=Context)
    threats: List[ThreatEvent] = field(default_factory=list)
    expected_decision: Optional[Decision] = None     # ground truth (for evaluation)
    label: str = ""                          # human description for logs


@dataclass
class AccessResponse:
    """What every model returns."""
    decision: Decision
    risk_score: float = 0.0                  # 0..100; 0 if model is risk-blind
    reason: str = ""
    obligations: List[str] = field(default_factory=list)
    debug: Dict[str, Any] = field(default_factory=dict)
