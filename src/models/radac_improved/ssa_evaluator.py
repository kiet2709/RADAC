"""Security Situational Awareness (SSA) evaluator.

Plugs the Mission Dependency Graph and the threat-CIA RB-FCM together
to produce, for one (asset, current-threats) pair:

  * asset_criticality(asset)  -> mission value of the asset (0..1)
  * base_impact(asset)        -> RB-FCM-computed CIA-weighted impact (0..1)
  * mission_impact(asset)     -> base impact percolated up the MDG (0..1)
  * ssa_risk(asset)           -> final risk modifier in [0,100] that the
                                 paper says we add to the fuzzy risk
                                 score.

This is the contribution the paper makes over plain RAdAC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ...common.entities import ThreatEvent
from .fcm import RuleBasedFCM
from .mission_graph import MissionDependencyGraph


@dataclass
class SSAEvaluator:
    graph: MissionDependencyGraph

    def __post_init__(self) -> None:
        self._criticalities = self.graph.asset_criticalities()

    def asset_criticality(self, asset_id: str) -> float:
        return self._criticalities.get(asset_id, 0.0)

    def _build_threat_fcm(self, threat: ThreatEvent,
                          asset_cia_weights: Tuple[float, float, float]
                          ) -> RuleBasedFCM:
        fcm = RuleBasedFCM()
        for n in ("threat", "C", "I", "A", "base_impact"):
            fcm.add_node(n, 0.0)
        fcm.set_activation("threat", threat.severity)
        fcm.add_edge("threat", "C", threat.affects_c)
        fcm.add_edge("threat", "I", threat.affects_i)
        fcm.add_edge("threat", "A", threat.affects_a)
        wc, wi, wa = asset_cia_weights
        norm = (wc + wi + wa) or 1.0
        fcm.add_edge("C", "base_impact", wc / norm)
        fcm.add_edge("I", "base_impact", wi / norm)
        fcm.add_edge("A", "base_impact", wa / norm)
        return fcm

    def base_impact(self, threat: ThreatEvent, asset_id: str,
                    cia_weights: Tuple[float, float, float] = (1.0, 1.0, 1.0)
                    ) -> float:
        if asset_id not in threat.targets:
            return 0.0
        fcm = self._build_threat_fcm(threat, cia_weights)
        final = fcm.run(steps=15)
        return float(final.get("base_impact", 0.0))

    def mission_impact(self, threat: ThreatEvent, asset_id: str,
                       cia_weights: Tuple[float, float, float] = (1.0, 1.0, 1.0)
                       ) -> float:
        bi = self.base_impact(threat, asset_id, cia_weights)
        return self.graph.mission_impact(asset_id, bi)

    def ssa_risk(self, threats: List[ThreatEvent], asset_id: str,
                 cia_weights: Tuple[float, float, float] = (1.0, 1.0, 1.0),
                 mode: str = "conservative") -> Dict[str, float]:
        crit = self.asset_criticality(asset_id)
        per_threat = [self.mission_impact(t, asset_id, cia_weights)
                      for t in threats]
        if not per_threat:
            mission_impact = 0.0
        elif mode == "conservative":
            mission_impact = max(per_threat)
        elif mode == "additive":
            prod_safe = 1.0
            for p in per_threat:
                prod_safe *= (1.0 - min(1.0, p))
            mission_impact = 1.0 - prod_safe
        else:  # mean
            mission_impact = sum(per_threat) / len(per_threat)

        # Criticality only counts when an actual threat is propagating
        # impact through the graph; without that, asset_criticality alone
        # is just an offline prioritisation, not a live risk.
        if mission_impact <= 0.0:
            ssa_risk = 0.0
        else:
            ssa_risk = 100.0 * (0.4 * crit + 0.6 * mission_impact)
        return {
            "criticality": crit,
            "mission_impact": mission_impact,
            "ssa_risk": max(0.0, min(100.0, ssa_risk)),
        }
