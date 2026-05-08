"""Role-Based Access Control (RBAC) — NIST RBAC0 form.

Standard RBAC0:
  * Users are assigned roles.
  * Roles are granted permissions on resources.
  * A request is permitted iff the subject's role has the requested
    action listed in `resource.allowed_roles[role]`.

No role hierarchy, no separation-of-duty, no risk awareness, no context
sensitivity. Pure "is the role on the list?" check, in line with the
no-enhancement constraint of the experiment.
"""

from __future__ import annotations

from ..common.entities import AccessRequest, AccessResponse, Decision
from .base import AccessControlModel


class RBACModel(AccessControlModel):
    name = "RBAC"

    def decide(self, request: AccessRequest) -> AccessResponse:
        role = request.subject.role
        action = request.action.lower()
        permitted = request.resource.allowed_roles.get(role, [])

        if action in permitted or "*" in permitted:
            return AccessResponse(
                decision=Decision.ALLOW,
                risk_score=0.0,
                reason=f"role '{role}' has '{action}' on {request.resource.resource_id}",
                debug={"role": role, "permitted_actions": list(permitted)},
            )
        return AccessResponse(
            decision=Decision.DENY,
            risk_score=0.0,
            reason=f"role '{role}' lacks '{action}' on {request.resource.resource_id}",
            debug={"role": role, "permitted_actions": list(permitted)},
        )
