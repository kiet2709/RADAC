"""Run scenario 1 across all six access-control models."""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scenarios import scenario1
from src.evaluator import run_scenario


def main() -> None:
    requests = scenario1.build_requests()
    models = scenario1.build_models()
    out = os.path.join(ROOT, "results")
    run_scenario("scenario1", requests, models, out)


if __name__ == "__main__":
    main()
