"""Scenario 2 — Targeted threats hitting mission-critical assets.

Purpose (per task brief):
    "Highlight limitations of original RADAC and improvements from the
    paper. Design a scenario where original RADAC struggles (e.g. lack
    of situational awareness, insufficient context handling, or delayed
    adaptation)."

Design choices:

1. Two resources with **almost identical direct attributes** (same
   classification, same sensitivity, same ACL/role permissions):
     * `payment_gateway` -> mission asset id `A_payment_gateway`
       (ends up at the top of the mission dependency graph; high
       criticality and high mission impact when threatened)
     * `sandbox_kb`      -> asset id `A_sandbox_kb`
       (orphan node with no path to any mission; criticality 0)

   So **subject + object + context** carry no signal that would let
   the original RAdAC (or any classical model) tell them apart.

2. Threat events vary: some target the payment gateway specifically,
   some target the sandbox, some target nothing relevant. The threat
   level number visible to RAdAC is the same in every "live threat"
   request — only the *target* differs.

3. The Improved RADAC consults the Mission Dependency Graph and an
   RB-FCM to compute a per-asset SSA modifier. Because only it knows
   which asset is mission-critical, only it raises the risk enough to
   DENY when a threat actually targets the gateway.

Other models (MAC, DAC, RBAC, ABAC) are given matching static
permissions for both resources so they always ALLOW. They will hit
about 12/16 accuracy because they cannot deny based on threats. The
brief asks us not to highlight their advantages — none should appear.
"""

from __future__ import annotations

import os
from typing import List

from src.common.entities import (
    AccessRequest,
    Context,
    Decision,
    Resource,
    Subject,
    ThreatEvent,
)
from src.models.abac import ABACModel, ABACRule
from src.models.dac import DACModel
from src.models.mac import MACModel
from src.models.rbac import RBACModel
from src.models.radac import RADACModel
from src.models.radac_improved.mission_graph import MissionDependencyGraph
from src.models.radac_improved.model import ImprovedRADACModel


# ---------------------------------------------------------------------- #
# Resources & subject                                                    #
# ---------------------------------------------------------------------- #
def _payment_gateway() -> Resource:
    return Resource(
        resource_id="payment_gateway",
        classification_level=2,
        sensitivity=0.6,
        owner="payments_admin",
        acl={"bob": ["read", "write"]},
        allowed_roles={"analyst": ["read", "write"]},
        asset_id="A_payment_gateway",
        cia_weights=(1.0, 1.0, 1.0),
        attributes={"data_class": "tx-state"},
    )


def _sandbox_kb() -> Resource:
    return Resource(
        resource_id="sandbox_kb",
        classification_level=2,
        sensitivity=0.6,                      # same numeric sensitivity!
        owner="sandbox_admin",
        acl={"bob": ["read", "write"]},
        allowed_roles={"analyst": ["read", "write"]},
        asset_id="A_sandbox_kb",              # this asset has no path to any mission
        cia_weights=(1.0, 1.0, 1.0),
        attributes={"data_class": "test-fixtures"},
    )


def _bob(op_need: float = 0.55) -> Subject:
    return Subject(
        user_id="bob",
        role="analyst",
        clearance_level=2,
        department="finance",
        trust_score=0.85,
        device_trust=0.85,
        operational_need=op_need,
        purpose="reporting",
        attributes={"team": "finops"},
    )


# ---------------------------------------------------------------------- #
# Threat events                                                          #
# ---------------------------------------------------------------------- #
def _threat_payment(severity: float = 0.85) -> ThreatEvent:
    return ThreatEvent(
        threat_id=f"T-pay-{int(severity*100)}",
        severity=severity,
        targets=["A_payment_gateway"],
        affects_c=0.6, affects_i=0.9, affects_a=0.7,
        description="targeted exploit against payment gateway service",
    )


def _threat_sandbox(severity: float = 0.85) -> ThreatEvent:
    return ThreatEvent(
        threat_id=f"T-sbx-{int(severity*100)}",
        severity=severity,
        targets=["A_sandbox_kb"],
        affects_c=0.6, affects_i=0.9, affects_a=0.7,
        description="targeted exploit against the sandbox knowledge base",
    )


def _threat_unrelated(severity: float = 0.55) -> ThreatEvent:
    """Background noise threat that does not target either resource."""
    return ThreatEvent(
        threat_id="T-bg",
        severity=severity,
        targets=["A_other_unrelated"],
        affects_c=0.4, affects_i=0.4, affects_a=0.4,
        description="background noise targeting unrelated assets",
    )


# ---------------------------------------------------------------------- #
# Request set                                                            #
# ---------------------------------------------------------------------- #
def build_requests() -> List[AccessRequest]:
    pg = _payment_gateway()
    sk = _sandbox_kb()
    requests: List[AccessRequest] = []

    # default context: moderate threat indicator visible everywhere, so
    # a non-SSA model cannot tell which asset is actually being targeted.
    base_ctx = lambda: Context(
        location="vpn", location_risk=0.35,
        threat_level=0.40, auth_strength=0.85,
        time_of_day="business_hours",
    )

    rows = [
        # ---- payment_gateway + targeted critical threats -> DENY -------
        ("S2-01", "pay-targeted-severe",
         pg, [_threat_payment(0.90)],   0.55, Decision.DENY),
        ("S2-02", "pay-targeted-severe-need",
         pg, [_threat_payment(0.85)],   0.65, Decision.DENY),
        ("S2-03", "pay-targeted-severe-with-noise",
         pg, [_threat_payment(0.90), _threat_unrelated(0.4)], 0.55, Decision.DENY),
        ("S2-04", "pay-targeted-multi",
         pg, [_threat_payment(0.80), _threat_payment(0.85)], 0.5, Decision.DENY),

        # ---- payment_gateway + no relevant threat -> ALLOW -------------
        ("S2-05", "pay-quiet",
         pg, [],                        0.55, Decision.ALLOW),
        ("S2-06", "pay-quiet-need",
         pg, [],                        0.75, Decision.ALLOW),
        ("S2-07", "pay-noise-only",
         pg, [_threat_unrelated(0.35)], 0.55, Decision.ALLOW),
        ("S2-08", "pay-quiet-routine",
         pg, [],                        0.50, Decision.ALLOW),

        # ---- sandbox + targeted threats (low mission impact) -> ALLOW --
        ("S2-09", "sbx-targeted-severe",
         sk, [_threat_sandbox(0.90)],   0.55, Decision.ALLOW),
        ("S2-10", "sbx-targeted-severe-need",
         sk, [_threat_sandbox(0.85)],   0.65, Decision.ALLOW),
        ("S2-11", "sbx-targeted-noise",
         sk, [_threat_sandbox(0.85), _threat_unrelated(0.3)], 0.55, Decision.ALLOW),
        ("S2-12", "sbx-targeted-multi",
         sk, [_threat_sandbox(0.80), _threat_sandbox(0.85)], 0.5, Decision.ALLOW),

        # ---- sandbox + no relevant threat -> ALLOW ---------------------
        ("S2-13", "sbx-quiet",
         sk, [],                        0.55, Decision.ALLOW),
        ("S2-14", "sbx-quiet-need",
         sk, [],                        0.75, Decision.ALLOW),
        ("S2-15", "sbx-noise-only",
         sk, [_threat_unrelated(0.35)], 0.55, Decision.ALLOW),
        ("S2-16", "sbx-quiet-routine",
         sk, [],                        0.50, Decision.ALLOW),
    ]

    for rid, label, resource, threats, op_need, expected in rows:
        requests.append(AccessRequest(
            request_id=rid,
            subject=_bob(op_need=op_need),
            resource=resource,
            action="read",
            context=base_ctx(),
            threats=threats,
            expected_decision=expected,
            label=label,
        ))
    return requests


# ---------------------------------------------------------------------- #
# Models                                                                 #
# ---------------------------------------------------------------------- #
def build_models(graph_path: str | None = None):
    mac = MACModel()
    dac = DACModel()
    rbac = RBACModel()

    abac = ABACModel(default=Decision.DENY)
    abac.add_rule(ABACRule(
        rule_id="ABAC-R1",
        effect=Decision.ALLOW,
        condition=lambda r: (r.subject.role == "analyst"
                             and r.action in ("read", "write")
                             and r.resource.resource_id in ("payment_gateway",
                                                            "sandbox_kb")),
        description="analyst may read/write either resource",
    ))
    abac.add_rule(ABACRule(
        rule_id="ABAC-R2",
        effect=Decision.DENY,
        condition=lambda r: r.context.threat_level >= 0.80,
        description="deny when overall threat level is critical",
    ))

    radac = RADACModel()

    if graph_path is None:
        graph_path = os.path.join(os.path.dirname(__file__),
                                  "..", "data", "mission_graph.json")
    mdg = MissionDependencyGraph.from_json(graph_path)
    improved = ImprovedRADACModel(mission_graph=mdg)

    return [mac, dac, rbac, abac, radac, improved]
