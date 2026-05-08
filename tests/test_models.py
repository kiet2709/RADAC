"""Smoke tests: every model can decide every request without crashing,
and standard rules behave as expected on hand-picked cases.

Run as: python -m unittest tests.test_models
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

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
from src.models.radac_improved.mission_graph import MissionDependencyGraph
from src.models.radac_improved.model import ImprovedRADACModel


def make_request(action="read", trust=0.85, threat=0.2, sens=0.5,
                 clearance=2, classification=2, role="analyst",
                 user_id="alice", asset_id="A_x"):
    return AccessRequest(
        request_id="T-1",
        subject=Subject(user_id=user_id, role=role, clearance_level=clearance,
                        trust_score=trust, device_trust=0.9,
                        operational_need=0.5),
        resource=Resource(resource_id="r1",
                          classification_level=classification,
                          sensitivity=sens,
                          owner="admin",
                          acl={"alice": ["read", "write"]},
                          allowed_roles={"analyst": ["read", "write"]},
                          asset_id=asset_id),
        action=action,
        context=Context(location="internal", location_risk=0.1,
                        threat_level=threat, auth_strength=0.9),
    )


class TestMAC(unittest.TestCase):
    def test_read_up_denied(self):
        req = make_request(action="read", clearance=1, classification=3)
        self.assertEqual(MACModel().decide(req).decision, Decision.DENY)

    def test_read_down_allowed(self):
        req = make_request(action="read", clearance=3, classification=1)
        self.assertEqual(MACModel().decide(req).decision, Decision.ALLOW)

    def test_write_down_denied(self):
        req = make_request(action="write", clearance=3, classification=1)
        self.assertEqual(MACModel().decide(req).decision, Decision.DENY)


class TestDAC(unittest.TestCase):
    def test_owner_allow(self):
        req = make_request(user_id="admin")
        # admin is owner -> allowed regardless of ACL
        self.assertEqual(DACModel().decide(req).decision, Decision.ALLOW)

    def test_acl_allow(self):
        req = make_request(user_id="alice", action="read")
        self.assertEqual(DACModel().decide(req).decision, Decision.ALLOW)

    def test_acl_deny(self):
        req = make_request(user_id="charlie")
        self.assertEqual(DACModel().decide(req).decision, Decision.DENY)


class TestRBAC(unittest.TestCase):
    def test_role_allow(self):
        req = make_request(role="analyst", action="read")
        self.assertEqual(RBACModel().decide(req).decision, Decision.ALLOW)

    def test_role_deny(self):
        req = make_request(role="visitor", action="read")
        self.assertEqual(RBACModel().decide(req).decision, Decision.DENY)


class TestABAC(unittest.TestCase):
    def test_default_deny(self):
        m = ABACModel()
        req = make_request()
        self.assertEqual(m.decide(req).decision, Decision.DENY)

    def test_rule_allow_then_deny_overrides(self):
        m = ABACModel()
        m.add_rule(ABACRule("R1", Decision.ALLOW,
                            lambda r: r.subject.role == "analyst",
                            "analyst allowed"))
        m.add_rule(ABACRule("R2", Decision.DENY,
                            lambda r: r.context.threat_level > 0.5,
                            "deny if threat high"))
        self.assertEqual(m.decide(make_request(threat=0.2)).decision,
                         Decision.ALLOW)
        self.assertEqual(m.decide(make_request(threat=0.9)).decision,
                         Decision.DENY)


class TestRADAC(unittest.TestCase):
    def test_low_threat_allows(self):
        m = RADACModel()
        out = m.decide(make_request(threat=0.05, sens=0.3))
        self.assertIn(out.decision,
                      (Decision.ALLOW, Decision.ALLOW_WITH_OBLIGATIONS))

    def test_high_threat_denies(self):
        req = make_request(threat=0.95, sens=0.9, trust=0.4)
        # force public-network risk too
        req.context.location = "public"
        req.context.location_risk = 0.85
        req.subject.operational_need = 0.05
        out = RADACModel().decide(req)
        self.assertEqual(out.decision, Decision.DENY)


class TestImprovedRADAC(unittest.TestCase):
    def setUp(self):
        path = os.path.join(ROOT, "data", "mission_graph.json")
        self.mdg = MissionDependencyGraph.from_json(path)

    def test_no_threats_matches_radac_qualitatively(self):
        m = ImprovedRADACModel(mission_graph=self.mdg)
        out = m.decide(make_request(threat=0.05))
        self.assertNotEqual(out.decision, Decision.DENY)

    def test_targeted_critical_threat_denies(self):
        from src.common.entities import ThreatEvent
        m = ImprovedRADACModel(mission_graph=self.mdg)
        req = make_request(asset_id="A_payment_gateway", threat=0.4, sens=0.6,
                           trust=0.85)
        req.threats = [ThreatEvent(threat_id="t", severity=0.95,
                                   targets=["A_payment_gateway"],
                                   affects_c=0.7, affects_i=0.9, affects_a=0.7)]
        out = m.decide(req)
        self.assertEqual(out.decision, Decision.DENY)

    def test_irrelevant_targeted_threat_does_not_block(self):
        from src.common.entities import ThreatEvent
        m = ImprovedRADACModel(mission_graph=self.mdg)
        req = make_request(asset_id="A_sandbox_kb", threat=0.4, sens=0.6,
                           trust=0.85)
        req.threats = [ThreatEvent(threat_id="t", severity=0.95,
                                   targets=["A_sandbox_kb"],
                                   affects_c=0.7, affects_i=0.9, affects_a=0.7)]
        out = m.decide(req)
        self.assertNotEqual(out.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
