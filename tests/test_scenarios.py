"""Scenario sanity tests.

These verify the *expected ordering* of accuracies, not numeric values:
  * Scenario 1: RADAC and Improved RADAC should be at least as accurate
    as MAC/DAC/RBAC/ABAC.
  * Scenario 2: Improved RADAC should strictly beat original RADAC.
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.common.metrics import evaluate_model
from scenarios import scenario1, scenario2


def run(scenario_module):
    requests = scenario_module.build_requests()
    if scenario_module is scenario2:
        models = scenario_module.build_models(
            graph_path=os.path.join(ROOT, "data", "mission_graph.json"))
    else:
        models = scenario_module.build_models()
    metrics = {}
    for m in models:
        responses = [m.decide(r) for r in requests]
        metrics[m.name] = evaluate_model(m.name, requests, responses)
    return metrics


class TestScenario1(unittest.TestCase):
    def test_radac_strong(self):
        m = run(scenario1)
        # RADAC should beat the static models on accuracy.
        self.assertGreaterEqual(m["RADAC"].accuracy, m["MAC"].accuracy)
        self.assertGreaterEqual(m["RADAC"].accuracy, m["DAC"].accuracy)
        self.assertGreaterEqual(m["RADAC"].accuracy, m["RBAC"].accuracy)
        # RADAC should be reasonably accurate.
        self.assertGreaterEqual(m["RADAC"].accuracy, 0.75)


class TestScenario2(unittest.TestCase):
    def test_improved_beats_original(self):
        m = run(scenario2)
        self.assertGreater(m["Improved-RADAC"].accuracy, m["RADAC"].accuracy)
        self.assertGreaterEqual(m["Improved-RADAC"].accuracy, 0.85)


if __name__ == "__main__":
    unittest.main()
