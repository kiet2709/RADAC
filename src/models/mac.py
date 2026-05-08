"""Mandatory Access Control (MAC) — Bell-LaPadula style.

Standard textbook MAC: each subject has a clearance level, each object a
classification level. Decisions follow the lattice:

  * read   : subject.clearance >= object.classification    ("no read up")
  * write  : subject.clearance <= object.classification    ("no write down")

There is no risk evaluation, no context awareness. The administrator
assigns clearances; users cannot delegate. This is the "not optimised,
not enhanced" form requested in the task brief.
"""

from __future__ import annotations

from ..common.entities import AccessRequest, AccessResponse, Decision
from .base import AccessControlModel


class MACModel(AccessControlModel):
    name = "MAC"

    def decide(self, request: AccessRequest) -> AccessResponse:
        s = request.subject
        r = request.resource
        action = request.action.lower()

        if action in ("read", "execute"):
            ok = s.clearance_level >= r.classification_level
            reason = (f"read/execute: clearance {s.clearance_level} "
                      f"vs classification {r.classification_level}")
        elif action in ("write", "append"):
            ok = s.clearance_level <= r.classification_level
            reason = (f"write: no-write-down rule "
                      f"clearance {s.clearance_level} "
                      f"vs classification {r.classification_level}")
        elif action == "delete":
            ok = s.clearance_level >= r.classification_level
            reason = (f"delete (treated as read+write at same level): "
                      f"clearance {s.clearance_level} "
                      f"vs classification {r.classification_level}")
        else:
            ok = False
            reason = f"unknown action '{action}' rejected by MAC"

        return AccessResponse(
            decision=Decision.ALLOW if ok else Decision.DENY,
            risk_score=0.0,
            reason=reason,
            debug={
                "clearance": s.clearance_level,
                "classification": r.classification_level,
                "action": action,
            },
        )
