"""Discretionary Access Control (DAC).

Owner-driven Access Control Lists, in their textbook form. Each
resource carries a per-user ACL mapping `user_id -> [allowed actions]`.
The owner of the resource always has full rights. There is no group
abstraction (that is RBAC), no environment awareness, no risk
calculation.

This is the "standard, no enhancement" version requested.
"""

from __future__ import annotations

from ..common.entities import AccessRequest, AccessResponse, Decision
from .base import AccessControlModel


class DACModel(AccessControlModel):
    name = "DAC"

    def decide(self, request: AccessRequest) -> AccessResponse:
        s = request.subject
        r = request.resource
        action = request.action.lower()

        if s.user_id == r.owner:
            return AccessResponse(
                decision=Decision.ALLOW,
                risk_score=0.0,
                reason=f"{s.user_id} is owner of {r.resource_id}",
                debug={"owner": r.owner, "matched_via": "owner"},
            )

        permitted = r.acl.get(s.user_id, [])
        if action in permitted or "*" in permitted:
            return AccessResponse(
                decision=Decision.ALLOW,
                risk_score=0.0,
                reason=f"{s.user_id} has '{action}' on {r.resource_id} via ACL",
                debug={"owner": r.owner, "matched_via": "acl",
                       "permitted_actions": list(permitted)},
            )

        return AccessResponse(
            decision=Decision.DENY,
            risk_score=0.0,
            reason=f"{s.user_id} has no ACL entry for '{action}' on {r.resource_id}",
            debug={"owner": r.owner, "matched_via": "none",
                   "permitted_actions": list(permitted)},
        )
