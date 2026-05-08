"""Evaluation metrics used to compare access-control models.

All metrics are scenario-agnostic so the same code drives both experiments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence

from .entities import AccessRequest, AccessResponse, Decision


def _is_allow(d: Decision) -> bool:
    return d.is_allow_like


@dataclass
class ModelMetrics:
    model: str
    n: int
    accuracy: float                  # 0..1, vs ground truth
    false_allow_rate: float          # FAR: should-deny but allowed
    false_deny_rate: float           # FDR: should-allow but denied
    n_allow: int
    n_deny: int
    n_oblig: int
    adaptability: float              # rate of decision-flips when context changes (0..1)
    consistency: float               # 1.0 = same input always same output (sanity)
    mean_risk: float                 # avg reported risk (0..100)

    def as_row(self) -> Dict[str, float]:
        return {
            "model": self.model,
            "n": self.n,
            "accuracy": round(self.accuracy, 4),
            "false_allow_rate": round(self.false_allow_rate, 4),
            "false_deny_rate": round(self.false_deny_rate, 4),
            "n_allow": self.n_allow,
            "n_deny": self.n_deny,
            "n_obligations": self.n_oblig,
            "adaptability": round(self.adaptability, 4),
            "consistency": round(self.consistency, 4),
            "mean_risk": round(self.mean_risk, 2),
        }


def confusion(requests: Sequence[AccessRequest],
              responses: Sequence[AccessResponse]) -> Dict[str, int]:
    """Confusion counts vs ground truth (`expected_decision`).

    Requests with no ground truth are skipped.
    """
    tp = tn = fp = fn = 0
    for req, resp in zip(requests, responses):
        if req.expected_decision is None:
            continue
        truth_allow = _is_allow(req.expected_decision)
        pred_allow = _is_allow(resp.decision)
        if truth_allow and pred_allow:
            tp += 1
        elif (not truth_allow) and (not pred_allow):
            tn += 1
        elif (not truth_allow) and pred_allow:
            fp += 1
        else:
            fn += 1
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def adaptability(requests: Sequence[AccessRequest],
                 responses: Sequence[AccessResponse]) -> float:
    """Fraction of consecutive request pairs whose decision *changed*.

    A model that ignores context will produce 0 here. A model that flips
    appropriately when context changes will be > 0. Pure adaptability,
    not correctness — paired with accuracy it shows whether the flips
    are *useful*.
    """
    if len(responses) < 2:
        return 0.0
    flips = 0
    for a, b in zip(responses[:-1], responses[1:]):
        if a.decision != b.decision:
            flips += 1
    return flips / (len(responses) - 1)


def consistency(requests: Sequence[AccessRequest],
                responses: Sequence[AccessResponse]) -> float:
    """For requests that are identical (same subject/resource/context),
    fraction that produced the *same* decision.
    """
    buckets: Dict[str, List[Decision]] = {}
    for req, resp in zip(requests, responses):
        key = (
            f"{req.subject.user_id}|{req.subject.role}|{req.subject.clearance_level}"
            f"|{req.resource.resource_id}|{req.action}"
            f"|{req.context.location}|{round(req.context.threat_level,2)}"
        )
        buckets.setdefault(key, []).append(resp.decision)
    total = same = 0
    for decisions in buckets.values():
        if len(decisions) < 2:
            continue
        total += 1
        if all(d == decisions[0] for d in decisions):
            same += 1
    return 1.0 if total == 0 else same / total


def evaluate_model(model_name: str,
                   requests: Sequence[AccessRequest],
                   responses: Sequence[AccessResponse]) -> ModelMetrics:
    cm = confusion(requests, responses)
    n_with_truth = cm["tp"] + cm["tn"] + cm["fp"] + cm["fn"]
    n_should_deny = cm["tn"] + cm["fp"]
    n_should_allow = cm["tp"] + cm["fn"]
    accuracy = (cm["tp"] + cm["tn"]) / n_with_truth if n_with_truth else 0.0
    far = cm["fp"] / n_should_deny if n_should_deny else 0.0
    fdr = cm["fn"] / n_should_allow if n_should_allow else 0.0

    n_allow = sum(1 for r in responses if r.decision == Decision.ALLOW)
    n_oblig = sum(1 for r in responses if r.decision == Decision.ALLOW_WITH_OBLIGATIONS)
    n_deny = sum(1 for r in responses if r.decision == Decision.DENY)
    mean_risk = sum(r.risk_score for r in responses) / max(1, len(responses))

    return ModelMetrics(
        model=model_name,
        n=len(responses),
        accuracy=accuracy,
        false_allow_rate=far,
        false_deny_rate=fdr,
        n_allow=n_allow,
        n_deny=n_deny,
        n_oblig=n_oblig,
        adaptability=adaptability(requests, responses),
        consistency=consistency(requests, responses),
        mean_risk=mean_risk,
    )
