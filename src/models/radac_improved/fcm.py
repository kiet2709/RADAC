"""Rule-Based Fuzzy Cognitive Map (Carvalho & Tome 1999, Kosko 1986).

A signed weighted directed graph whose nodes carry an activation in
[0,1] and propagate via:

    A_i(t+1) = sigmoid( 0.5 * A_i(t) + sum_j w_{j->i} * A_j(t) )

Used by the paper to model the threat -> {C,I,A} -> base-impact chain
that the SSA evaluator feeds into the fuzzy risk function.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


def _sigmoid(x: float, k: float = 5.0) -> float:
    return 1.0 / (1.0 + math.exp(-k * (x - 0.5)))


@dataclass
class FCMEdge:
    src: str
    dst: str
    weight: float = 1.0
    rule: Optional[Callable[[float, Dict[str, float]], float]] = None

    def contribution(self, src_activation: float,
                     ctx: Dict[str, float]) -> float:
        if self.rule is not None:
            return self.rule(src_activation, ctx) * self.weight
        return src_activation * self.weight


@dataclass
class RuleBasedFCM:
    nodes: Dict[str, float] = field(default_factory=dict)
    edges: List[FCMEdge] = field(default_factory=list)

    def add_node(self, name: str, init: float = 0.0) -> None:
        self.nodes[name] = float(init)

    def add_edge(self, src: str, dst: str, weight: float = 1.0,
                 rule: Optional[Callable[[float, Dict[str, float]], float]] = None
                 ) -> None:
        if src not in self.nodes:
            self.add_node(src)
        if dst not in self.nodes:
            self.add_node(dst)
        self.edges.append(FCMEdge(src, dst, weight, rule))

    def set_activation(self, name: str, value: float) -> None:
        self.nodes[name] = max(0.0, min(1.0, float(value)))

    def step(self, ctx: Dict[str, float] | None = None) -> Dict[str, float]:
        ctx = ctx or {}
        new_state: Dict[str, float] = {}
        for n, a in self.nodes.items():
            incoming = sum(e.contribution(self.nodes[e.src], ctx)
                           for e in self.edges if e.dst == n)
            new_state[n] = _sigmoid(0.5 * a + incoming)
        self.nodes = new_state
        return dict(self.nodes)

    def run(self, steps: int = 20, eps: float = 1e-3,
            ctx: Dict[str, float] | None = None) -> Dict[str, float]:
        prev = dict(self.nodes)
        for _ in range(steps):
            self.step(ctx)
            diff = max(abs(self.nodes[n] - prev[n]) for n in self.nodes)
            prev = dict(self.nodes)
            if diff < eps:
                break
        return dict(self.nodes)
