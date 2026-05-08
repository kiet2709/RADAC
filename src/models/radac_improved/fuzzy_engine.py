"""FURZE Risk Evaluation Function — Mamdani fuzzy inference.

The paper (Section 3) advocates the Fuzzy Control Language (IEC
61131-7) approach pioneered by Cheng et al. (2007) and Ni, Bertino,
Lobo (2010). Inputs are normalised to [0,1] linguistic variables with
triangular membership functions {low, med, high}; the output (risk) is
on [0,100].

Inference is Mamdani min-max with centroid defuzzification, the
canonical recipe for fuzzy decision-making under uncertainty.

Inputs:
    trust       - composite subject + device trust
    sensitivity - data classification of the resource
    threat      - global enterprise threat indicator
    op_need     - operational need backing the request
    loc_risk    - location risk
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl


@dataclass
class RiskInputs:
    trust: float
    sensitivity: float
    threat: float
    op_need: float
    loc_risk: float

    def clamp(self) -> "RiskInputs":
        c = lambda x: max(0.0, min(1.0, float(x)))
        return RiskInputs(c(self.trust), c(self.sensitivity), c(self.threat),
                          c(self.op_need), c(self.loc_risk))


class FuzzyRiskEngine:
    """Mamdani fuzzy inference engine with the FURZE rule-base."""

    def __init__(self) -> None:
        self.trust       = ctrl.Antecedent(np.linspace(0, 1, 101), "trust")
        self.sensitivity = ctrl.Antecedent(np.linspace(0, 1, 101), "sensitivity")
        self.threat      = ctrl.Antecedent(np.linspace(0, 1, 101), "threat")
        self.op_need     = ctrl.Antecedent(np.linspace(0, 1, 101), "op_need")
        self.loc_risk    = ctrl.Antecedent(np.linspace(0, 1, 101), "loc_risk")
        self.risk        = ctrl.Consequent(np.linspace(0, 100, 101), "risk")

        for v in (self.trust, self.sensitivity, self.threat,
                  self.op_need, self.loc_risk):
            v["low"]  = fuzz.trimf(v.universe, [0.0, 0.0, 0.5])
            v["med"]  = fuzz.trimf(v.universe, [0.2, 0.5, 0.8])
            v["high"] = fuzz.trimf(v.universe, [0.5, 1.0, 1.0])

        self.risk["low"]  = fuzz.trimf(self.risk.universe, [0,   0,  40])
        self.risk["med"]  = fuzz.trimf(self.risk.universe, [25, 50, 75])
        self.risk["high"] = fuzz.trimf(self.risk.universe, [60, 100, 100])

        self._system    = ctrl.ControlSystem(self._build_rules())
        self._simulator = ctrl.ControlSystemSimulation(self._system)

    def _build_rules(self):
        T, S, Th, On, L, R = (self.trust, self.sensitivity, self.threat,
                              self.op_need, self.loc_risk, self.risk)
        return [
            # Low-risk regions.
            ctrl.Rule(T["high"] & S["low"]                 , R["low"]),
            ctrl.Rule(T["high"] & Th["low"] & L["low"]     , R["low"]),
            ctrl.Rule(On["high"] & T["med"] & Th["low"]    , R["low"]),
            ctrl.Rule(On["high"] & T["high"]               , R["low"]),

            # Mid-range conditions.
            ctrl.Rule(T["med"] & S["med"]                  , R["med"]),
            ctrl.Rule(Th["med"] & L["med"]                 , R["med"]),
            ctrl.Rule(T["high"] & S["high"] & On["med"]    , R["med"]),
            ctrl.Rule(T["med"] & Th["med"] & On["med"]     , R["med"]),
            ctrl.Rule(On["low"] & S["med"]                 , R["med"]),

            # High-risk regions.
            ctrl.Rule(S["high"] & T["low"]                 , R["high"]),
            ctrl.Rule(Th["high"] & L["high"]               , R["high"]),
            ctrl.Rule(T["low"] & On["low"]                 , R["high"]),
            ctrl.Rule(S["high"] & Th["high"]               , R["high"]),
            ctrl.Rule(L["high"] & S["high"]                , R["high"]),
            ctrl.Rule(On["low"] & S["high"]                , R["high"]),
        ]

    def evaluate(self, ri: RiskInputs) -> Dict[str, float]:
        ri = ri.clamp()
        sim = self._simulator
        sim.input["trust"]       = ri.trust
        sim.input["sensitivity"] = ri.sensitivity
        sim.input["threat"]      = ri.threat
        sim.input["op_need"]     = ri.op_need
        sim.input["loc_risk"]    = ri.loc_risk
        try:
            sim.compute()
            risk_score = float(sim.output["risk"])
        except Exception:
            # Fallback: linear heuristic if no rule fires with non-zero strength.
            risk_score = 50.0 * (1.0 - ri.trust) + 50.0 * ri.sensitivity * ri.threat
        return {
            "risk":        float(np.clip(risk_score, 0.0, 100.0)),
            "trust":       ri.trust,
            "sensitivity": ri.sensitivity,
            "threat":      ri.threat,
            "op_need":     ri.op_need,
            "loc_risk":    ri.loc_risk,
        }
