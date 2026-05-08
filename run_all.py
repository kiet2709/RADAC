"""Run both scenarios end-to-end and write all CSV artefacts."""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scenarios import scenario1, scenario2
from src.evaluator import run_scenario


def main() -> None:
    out = os.path.join(ROOT, "results")

    print("\n#" + "=" * 70)
    print("# Scenario 1: dynamic risk-sensitive enterprise environment")
    print("# (RADAC's adaptive risk evaluation should excel)")
    print("#" + "=" * 70)
    run_scenario("scenario1",
                 scenario1.build_requests(),
                 scenario1.build_models(),
                 out)

    print("\n#" + "=" * 70)
    print("# Scenario 2: situational awareness via mission impact")
    print("# (Paper's Improved RADAC should outperform original RADAC)")
    print("#" + "=" * 70)
    run_scenario("scenario2",
                 scenario2.build_requests(),
                 scenario2.build_models(),
                 out)

    print("\nAll results written to:", out)


if __name__ == "__main__":
    main()
