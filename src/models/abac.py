"""Attribute-Based Access Control (ABAC) — NIST SP 800-162 / XACML style.

Standard ABAC: a list of policy rules. A rule is `(target, condition)`
where `target` filters which (subject, resource, action, environment)
attributes the rule applies to, and `condition` is a boolean predicate
over those same attributes.

Rules can return ALLOW or DENY. Combining algorithm: `deny-overrides`
(default in XACML 3.0). If no rule applies, the result is DENY (default
deny — the standard policy in XACML).

Standard form, no risk computation, no fuzzy logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..common.entities import AccessRequest, AccessResponse, Decision
from .base import AccessControlModel


@dataclass
class ABACRule:
    rule_id: str
    effect: Decision                                              # ALLOW or DENY
    condition: Callable[[AccessRequest], bool]
    description: str = ""


@dataclass
class ABACModel(AccessControlModel):
    name: str = "ABAC"
    rules: List[ABACRule] = field(default_factory=list)
    default: Decision = Decision.DENY

    def add_rule(self, rule: ABACRule) -> None:
        self.rules.append(rule)

    def decide(self, request: AccessRequest) -> AccessResponse:
        matched: List[ABACRule] = []
        for rule in self.rules:
            try:
                if rule.condition(request):
                    matched.append(rule)
            except Exception as exc:
                # Misbehaving rule -> safe default (skip)
                continue

        # XACML deny-overrides combining
        any_deny = any(r.effect == Decision.DENY for r in matched)
        any_allow = any(r.effect == Decision.ALLOW for r in matched)

        if any_deny:
            chosen = next(r for r in matched if r.effect == Decision.DENY)
            return AccessResponse(
                decision=Decision.DENY,
                risk_score=0.0,
                reason=f"deny-overrides via rule {chosen.rule_id}: {chosen.description}",
                debug={"matched_rules": [r.rule_id for r in matched]},
            )
        if any_allow:
            chosen = next(r for r in matched if r.effect == Decision.ALLOW)
            return AccessResponse(
                decision=Decision.ALLOW,
                risk_score=0.0,
                reason=f"allow via rule {chosen.rule_id}: {chosen.description}",
                debug={"matched_rules": [r.rule_id for r in matched]},
            )
        return AccessResponse(
            decision=self.default,
            risk_score=0.0,
            reason="no rule matched; default deny",
            debug={"matched_rules": []},
        )
