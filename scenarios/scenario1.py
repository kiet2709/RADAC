"""Scenario 1 — Dynamic risk-sensitive enterprise environment.

Purpose (per task brief):
    "Highlight the strengths of original RADAC. Design a dynamic,
    risk-sensitive environment where contextual factors (e.g., user
    behaviour, environment changes, threat level) significantly affect
    access decisions."

Design choices that keep the comparison fair:

1. One regular employee `alice` requests one resource `customer_db`
   over and over. Alice always has the static permissions every
   classical model needs:
     * MAC : her clearance >= the resource classification
     * DAC : she is on the ACL
     * RBAC: her role has the action permission
     * ABAC: a generic role-based rule allows her by default
   So MAC, DAC, RBAC and ABAC will trivially say ALLOW whenever they
   only consult identity / role.

2. Across 16 requests we vary CONTEXT only:
     * threat_level     (0.10 .. 0.92)
     * location & loc_risk (internal, vpn, public)
     * operational_need (0.10 .. 0.95)
     * device_trust     (sometimes drops on public Wi-Fi)
   The ground truth tracks the *aggregate* risk picture: when threat
   and location both look bad and operational need is low, the right
   answer is DENY; when operational need is high enough, RAdAC's
   trade-off says ALLOW (or allow-with-obligations).

3. No Mission Dependency Graph nor active threat events with targets
   are populated, so the SSA component of Improved RADAC contributes
   nothing extra. This isolates the "risk-adaptive vs static" axis,
   exactly what the brief requests for Scenario 1.

Result we expect: original RADAC and Improved RADAC both track ground
truth closely; MAC, DAC, RBAC are stuck at ALLOW; ABAC misses the
gradations because its rule conjunctions are too coarse.
"""

from __future__ import annotations

from typing import List

from src.common.entities import (
    AccessRequest,
    Context,
    Decision,
    Resource,
    Subject,
)
from src.models.abac import ABACModel, ABACRule
from src.models.dac import DACModel
from src.models.mac import MACModel
from src.models.rbac import RBACModel
from src.models.radac import RADACModel
from src.models.radac_improved.model import ImprovedRADACModel


# ---------------------------------------------------------------------- #
# Static principals & resource                                           #
# ---------------------------------------------------------------------- #
def _resource() -> Resource:
    return Resource(
        resource_id="customer_db",
        classification_level=2,                  # confidential
        sensitivity=0.6,
        owner="db_admin",
        acl={"alice": ["read", "write"], "bob": ["read"]},
        allowed_roles={"analyst": ["read", "write"], "auditor": ["read"]},
        asset_id="A_customer_db",
        cia_weights=(1.0, 0.7, 0.6),
        attributes={"data_class": "PII"},
    )


def _alice(trust: float = 0.85, device: float = 0.85,
           op_need: float = 0.5) -> Subject:
    return Subject(
        user_id="alice",
        role="analyst",
        clearance_level=2,
        department="risk",
        trust_score=trust,
        device_trust=device,
        operational_need=op_need,
        purpose="reporting",
        attributes={"team": "risk"},
    )


# ---------------------------------------------------------------------- #
# Request set: 16 requests, paired into 8 (allow-target, deny-target).   #
# ---------------------------------------------------------------------- #
def build_requests() -> List[AccessRequest]:
    R = _resource()
    requests: List[AccessRequest] = []

    # i, label, context kwargs, op_need, device_trust, expected
    rows = [
        # ---- Should ALLOW: routine, low threat, trusted location ---------
        ("S1-01", "calm-internal-routine",
         dict(location="internal", location_risk=0.1, threat_level=0.10,
              auth_strength=0.9), 0.50, 0.90, Decision.ALLOW),

        ("S1-02", "calm-vpn-with-need",
         dict(location="vpn", location_risk=0.35, threat_level=0.15,
              auth_strength=0.85), 0.65, 0.85, Decision.ALLOW),

        ("S1-03", "moderate-threat-strong-need",
         dict(location="internal", location_risk=0.1, threat_level=0.45,
              auth_strength=0.9), 0.85, 0.90, Decision.ALLOW),

        ("S1-04", "moderate-threat-internal-routine",
         dict(location="internal", location_risk=0.1, threat_level=0.35,
              auth_strength=0.9), 0.55, 0.88, Decision.ALLOW),

        ("S1-05", "elevated-threat-emergency-need",
         dict(location="vpn", location_risk=0.40, threat_level=0.55,
              auth_strength=0.85), 0.92, 0.85, Decision.ALLOW),

        ("S1-06", "branch-low-threat-routine",
         dict(location="branch", location_risk=0.30, threat_level=0.20,
              auth_strength=0.85), 0.55, 0.82, Decision.ALLOW),

        ("S1-07", "internal-mid-threat-mid-need",
         dict(location="internal", location_risk=0.10, threat_level=0.40,
              auth_strength=0.9), 0.60, 0.88, Decision.ALLOW),

        ("S1-08", "vpn-low-threat-low-need",
         dict(location="vpn", location_risk=0.35, threat_level=0.20,
              auth_strength=0.9), 0.55, 0.85, Decision.ALLOW),

        # ---- Should DENY: dangerous context, no compelling need ---------
        ("S1-09", "high-threat-public-low-need",
         dict(location="public", location_risk=0.85, threat_level=0.85,
              auth_strength=0.7), 0.20, 0.45, Decision.DENY),

        ("S1-10", "active-attack-public-routine",
         dict(location="public", location_risk=0.85, threat_level=0.92,
              auth_strength=0.7), 0.30, 0.55, Decision.DENY),

        ("S1-11", "elevated-threat-public-low-need",
         dict(location="public", location_risk=0.80, threat_level=0.70,
              auth_strength=0.7), 0.25, 0.55, Decision.DENY),

        ("S1-12", "high-threat-unmanaged-device",
         dict(location="vpn", location_risk=0.50, threat_level=0.80,
              auth_strength=0.6), 0.20, 0.40, Decision.DENY),

        ("S1-13", "public-night-low-need",
         dict(location="public", location_risk=0.85, threat_level=0.55,
              auth_strength=0.6, time_of_day="night"), 0.10, 0.50, Decision.DENY),

        ("S1-14", "high-threat-vpn-low-need",
         dict(location="vpn", location_risk=0.45, threat_level=0.85,
              auth_strength=0.7), 0.20, 0.55, Decision.DENY),

        ("S1-15", "weak-auth-public-mid-threat",
         dict(location="public", location_risk=0.85, threat_level=0.65,
              auth_strength=0.5), 0.20, 0.50, Decision.DENY),

        ("S1-16", "high-threat-low-trust",
         dict(location="public", location_risk=0.80, threat_level=0.80,
              auth_strength=0.55), 0.30, 0.50, Decision.DENY),
    ]

    for rid, label, ctx_kwargs, op_need, device_trust, expected in rows:
        # device trust drops on public Wi-Fi to mimic a captive portal etc.
        trust = 0.85
        subj = _alice(trust=trust, device=device_trust, op_need=op_need)
        ctx = Context(**ctx_kwargs)
        requests.append(AccessRequest(
            request_id=rid,
            subject=subj,
            resource=R,
            action="read",
            context=ctx,
            threats=[],
            expected_decision=expected,
            label=label,
        ))
    return requests


# ---------------------------------------------------------------------- #
# Model construction.                                                    #
# Identical "static" privileges given to MAC/DAC/RBAC/ABAC so they can   #
# all trivially say ALLOW; the question is whether they DENY when the    #
# context demands it.                                                    #
# ---------------------------------------------------------------------- #
def build_models():
    mac = MACModel()
    dac = DACModel()
    rbac = RBACModel()

    # ABAC: a small rule-set with role allow + a couple of context guards.
    # We give ABAC genuinely useful rules (threat & location guards) so
    # the comparison is fair. ABAC will still miss gradations because
    # its rules are conjunctive thresholds, not aggregate risk.
    abac = ABACModel(default=Decision.DENY)
    abac.add_rule(ABACRule(
        rule_id="ABAC-R1",
        effect=Decision.ALLOW,
        condition=lambda r: (r.subject.role == "analyst"
                             and r.action in ("read", "write")
                             and r.resource.resource_id == "customer_db"),
        description="analyst may read/write customer_db",
    ))
    abac.add_rule(ABACRule(
        rule_id="ABAC-R2",
        effect=Decision.DENY,
        condition=lambda r: (r.context.location == "public"
                             and r.context.threat_level >= 0.70),
        description="deny if public network during a high threat level",
    ))
    abac.add_rule(ABACRule(
        rule_id="ABAC-R3",
        effect=Decision.DENY,
        condition=lambda r: r.context.auth_strength < 0.55,
        description="deny if auth strength is below acceptable",
    ))

    radac = RADACModel()
    improved = ImprovedRADACModel(mission_graph=None)   # SSA inactive in S1
    return [mac, dac, rbac, abac, radac, improved]
