"""Run scenario 2 across all six access-control models."""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scenarios import scenario2
from src.evaluator import run_scenario


def main() -> None:
    requests = scenario2.build_requests()
    models = scenario2.build_models()
    out = os.path.join(ROOT, "results")
    run_scenario("scenario2", requests, models, out)


if __name__ == "__main__":
    main()
