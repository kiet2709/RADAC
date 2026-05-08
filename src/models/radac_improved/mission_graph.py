"""Mission Dependency Graph (Holspopple & Yang 2013, Watters 2009,
Innerhofer-Oberperfler & Breu 2006, Jakobson 2011).

Layered DAG: mission -> business process -> IT capability -> asset.
Edges carry weights in [0,1] expressing how strongly the parent
depends on the child.

Two operations the paper relies on:
  * trickle-down: distribute mission priority to assets to obtain a
    per-asset criticality.
  * percolate-up: take a base-impact at an asset and propagate it up
    the graph to obtain a mission-level impact.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import networkx as nx


@dataclass
class MissionDependencyGraph:
    g: nx.DiGraph = field(default_factory=nx.DiGraph)

    def add_node(self, node_id: str, layer: str, priority: float = 0.0,
                 label: str = "") -> None:
        self.g.add_node(node_id, layer=layer, priority=float(priority),
                        label=label or node_id)

    def add_edge(self, parent: str, child: str, weight: float = 1.0) -> None:
        self.g.add_edge(parent, child, weight=float(weight))

    @classmethod
    def from_json(cls, path: str) -> "MissionDependencyGraph":
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        m = cls()
        for n in data["nodes"]:
            m.add_node(n["id"], n["layer"],
                       float(n.get("priority", 0.0)),
                       n.get("label", ""))
        for e in data["edges"]:
            m.add_edge(e["from"], e["to"], float(e.get("weight", 1.0)))
        return m

    def assets(self) -> List[str]:
        return [n for n, d in self.g.nodes(data=True) if d["layer"] == "asset"]

    def missions(self) -> List[str]:
        return [n for n, d in self.g.nodes(data=True) if d["layer"] == "mission"]

    def asset_criticalities(self) -> Dict[str, float]:
        crit: Dict[str, float] = defaultdict(float)
        for m in self.missions():
            self._propagate_priority(m, self.g.nodes[m]["priority"], crit)
        if not crit:
            return {}
        max_c = max(crit.values()) or 1.0
        return {a: round(crit[a] / max_c, 4) for a in self.assets()}

    def _propagate_priority(self, node: str, value: float,
                            sink: Dict[str, float]) -> None:
        if self.g.nodes[node]["layer"] == "asset":
            sink[node] += value
            return
        for _, child, data in self.g.out_edges(node, data=True):
            self._propagate_priority(child, value * data["weight"], sink)

    def percolate_impact(self, asset_id: str, base_impact: float
                         ) -> Dict[str, float]:
        if asset_id not in self.g:
            return {}
        impact: Dict[str, float] = {asset_id: float(base_impact)}
        frontier = [asset_id]
        while frontier:
            nxt: List[str] = []
            for node in frontier:
                for parent, _, data in self.g.in_edges(node, data=True):
                    new_val = data["weight"] * impact[node]
                    if new_val > impact.get(parent, -1.0):
                        impact[parent] = new_val
                        nxt.append(parent)
            frontier = nxt
        return impact

    def mission_impact(self, asset_id: str, base_impact: float) -> float:
        full = self.percolate_impact(asset_id, base_impact)
        miss_vals: List[Tuple[float, float]] = []
        for m in self.missions():
            if m in full:
                miss_vals.append((full[m], self.g.nodes[m]["priority"]))
        if not miss_vals:
            return 0.0
        num = sum(v * p for v, p in miss_vals)
        den = sum(p for _, p in miss_vals) or 1.0
        return num / den
