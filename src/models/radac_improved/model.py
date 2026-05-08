"""ImprovedRADACModel — the paper's full FURZE + SSA framework.

Pipeline (Figure 2 of the paper):

  Subject + Object + Context  --->  Risk Evaluation Function (Mamdani)
                                          |
                         Threats + MDG --->|---> SSA modifier (RB-FCM + MDG)
                                          v
                              Access Decision Function
                                  (verdict bands)

Key behaviours that distinguish this from the original RAdAC:
  1. Risk is computed by a **fuzzy** Mamdani inference engine instead of
     a linear formula (paper Section 3, "Risk evaluation").
  2. Mission impact and asset criticality, computed via the MDG and
     RB-FCM, are added on top of the fuzzy score: this is the paper's
     situational-awareness contribution.
  3. Decision continuity is supported through `re_evaluate` — the same
     request can be re-decided when the context changes. This is the
     UCON inheritance that the paper highlights.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ...common.entities import (
    AccessRequest,
    AccessResponse,
    Context,
    Decision,
)
from ..base import AccessControlModel
from .fuzzy_engine import FuzzyRiskEngine, RiskInputs
from .mission_graph import MissionDependencyGraph
from .ssa_evaluator import SSAEvaluator


@dataclass
class ImprovedRADACModel(AccessControlModel):
    name: str = "Improved-RADAC"
    mission_graph: Optional[MissionDependencyGraph] = None
    allow_below: float = 32.0
    deny_above: float = 55.0
    ssa_aggregation: str = "conservative"
    ssa_damping: float = 0.6                # damp SSA modifier so it can flip but not dominate
    min_subject_trust: float = 0.10
    engine: FuzzyRiskEngine = field(init=False)
    ssa: Optional[SSAEvaluator] = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.engine = FuzzyRiskEngine()
        self.ssa = (SSAEvaluator(self.mission_graph)
                    if self.mission_graph is not None else None)

    # ------------------------------------------------------------------ #
    def _ssa_extra(self, request: AccessRequest):
        if self.ssa is None or not request.threats:
            return 0.0, {}
        if not request.resource.asset_id:
            return 0.0, {"note": "resource has no asset_id"}
        breakdown = self.ssa.ssa_risk(
            threats=request.threats,
            asset_id=request.resource.asset_id,
            cia_weights=request.resource.cia_weights,
            mode=self.ssa_aggregation,
        )
        return self.ssa_damping * breakdown["ssa_risk"], breakdown

    # ------------------------------------------------------------------ #
    def decide(self, request: AccessRequest) -> AccessResponse:
        s = request.subject
        if s.composite_trust < self.min_subject_trust:
            return AccessResponse(
                decision=Decision.DENY,
                risk_score=100.0,
                reason=(f"subject composite trust {s.composite_trust:.2f} "
                        f"< floor {self.min_subject_trust}"),
                debug={"floor_check": "fail"},
            )

        c = request.context
        loc_risk = c.location_risk if c.location_risk > 0.0 else c.location_to_risk(c.location)
        ri = RiskInputs(
            trust=s.composite_trust,
            sensitivity=request.resource.sensitivity,
            threat=c.threat_level,
            op_need=s.operational_need,
            loc_risk=loc_risk,
        )
        scored = self.engine.evaluate(ri)
        fuzzy_risk = scored["risk"]

        extra, breakdown = self._ssa_extra(request)
        total_risk = max(0.0, min(100.0, fuzzy_risk + extra))

        if total_risk <= self.allow_below:
            verdict = Decision.ALLOW
            reason = (f"fuzzy={fuzzy_risk:.1f} + ssa={extra:.1f} = "
                      f"{total_risk:.1f} <= {self.allow_below}")
            obls: List[str] = []
        elif total_risk >= self.deny_above:
            verdict = Decision.DENY
            reason = (f"fuzzy={fuzzy_risk:.1f} + ssa={extra:.1f} = "
                      f"{total_risk:.1f} >= {self.deny_above}")
            obls = []
        else:
            verdict = Decision.ALLOW_WITH_OBLIGATIONS
            reason = (f"fuzzy={fuzzy_risk:.1f} + ssa={extra:.1f} = "
                      f"{total_risk:.1f} in trade-off band")
            obls = ["require-mfa", "log-session", "step-up-monitor"]

        debug = dict(scored)
        debug["fuzzy_risk"] = fuzzy_risk
        debug["ssa_extra"] = extra
        debug.update({f"ssa_{k}": v for k, v in breakdown.items()})
        return AccessResponse(
            decision=verdict,
            risk_score=total_risk,
            reason=reason,
            obligations=obls,
            debug=debug,
        )

    # decision-continuity entry point (UCON) --------------------------- #
    def re_evaluate(self, request: AccessRequest) -> AccessResponse:
        """Same as decide(); kept as an explicit name for clarity in logs."""
        return self.decide(request)
