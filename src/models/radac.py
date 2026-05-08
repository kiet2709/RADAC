"""Original RAdAC (Risk-Adaptable Access Control) — McGraw, 2009.

Strict, un-enhanced form. From the paper under study (Lee et al. 2017,
quoting McGraw):

    "RAdAC incorporates a real time, probabilistic determination of
    security risk into the access control decision rather than just
    using a hard comparison of the attributes of the subject and
    object."

The original RAdAC is therefore characterised by:

  1. A real-time numeric risk score derived from subject + object +
     context attributes.
  2. The "trade-off" between security risk and operational need
     (high operational need can override moderate risk).
  3. Threshold bands turning the score into a verdict.

It does NOT include:
  * fuzzy inference (that came with Cheng 2007 / Ni 2010)
  * mission impact / situational awareness (the contribution of the
    paper under study)
  * decision continuity / ongoing re-evaluation (UCON extension)

We implement the simplest faithful version: a weighted linear risk
model with operational-need offset and three verdict bands. No
enhancements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..common.entities import AccessRequest, AccessResponse, Decision
from .base import AccessControlModel


@dataclass
class RADACModel(AccessControlModel):
    name: str = "RADAC"
    # Linear risk weights (sum approx 1 before op_need offset).
    w_trust: float = 0.30                 # weight on (1 - trust)
    w_sensitivity: float = 0.25
    w_threat: float = 0.25
    w_location: float = 0.20
    w_op_need: float = 0.30               # subtracted; operational need lowers risk
    # Verdict bands on the 0..100 risk axis.
    allow_below: float = 32.0
    deny_above: float = 55.0
    # Hard floor: if subject completely untrusted, deny outright.
    min_subject_trust: float = 0.10

    def _risk(self, req: AccessRequest) -> float:
        s = req.subject
        r = req.resource
        c = req.context

        loc_risk = c.location_risk
        if loc_risk <= 0.0:
            loc_risk = c.location_to_risk(c.location)

        # Real-time probabilistic risk: weighted sum of standard factors.
        raw = (self.w_trust       * (1.0 - s.composite_trust)
               + self.w_sensitivity * r.sensitivity
               + self.w_threat      * c.threat_level
               + self.w_location    * loc_risk
               - self.w_op_need     * s.operational_need)

        # Map [-w_op_need, w_trust+w_sens+w_threat+w_loc] -> [0, 100]
        lo = -self.w_op_need
        hi = self.w_trust + self.w_sensitivity + self.w_threat + self.w_location
        norm = (raw - lo) / (hi - lo) if hi > lo else 0.0
        return max(0.0, min(100.0, 100.0 * norm))

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

        risk = self._risk(request)
        if risk <= self.allow_below:
            verdict = Decision.ALLOW
            reason = f"risk {risk:.1f} <= allow_below {self.allow_below}"
            obls: List[str] = []
        elif risk >= self.deny_above:
            verdict = Decision.DENY
            reason = f"risk {risk:.1f} >= deny_above {self.deny_above}"
            obls = []
        else:
            verdict = Decision.ALLOW_WITH_OBLIGATIONS
            reason = (f"risk {risk:.1f} in trade-off band "
                      f"[{self.allow_below}, {self.deny_above}]")
            obls = ["require-mfa", "log-session"]

        return AccessResponse(
            decision=verdict,
            risk_score=risk,
            reason=reason,
            obligations=obls,
            debug={
                "trust": round(s.composite_trust, 3),
                "sensitivity": request.resource.sensitivity,
                "threat": request.context.threat_level,
                "location_risk": request.context.location_risk,
                "operational_need": s.operational_need,
            },
        )
