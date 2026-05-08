"""Unified evaluator: feed the same request stream to every model.

For each scenario the runner calls `run_scenario(...)` to:
  1. Iterate the request list once per model.
  2. Capture every (model, request, response) tuple to a CSV.
  3. Compute summary metrics per model and print a comparison table.

Reproducibility: all randomness, if any, comes from the scenario builder
seeded via numpy. The evaluator itself is deterministic.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict
from typing import Dict, List, Sequence

from tabulate import tabulate

from .common.entities import AccessRequest, AccessResponse, Decision
from .common.metrics import ModelMetrics, evaluate_model
from .models.base import AccessControlModel


def _safe(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Decision):
        return value.value
    if isinstance(value, dict):
        return json.dumps({k: _safe(v) for k, v in value.items()},
                          ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return json.dumps([_safe(v) for v in value], ensure_ascii=False)
    return str(value)


def _request_summary(req: AccessRequest) -> Dict[str, object]:
    return {
        "request_id": req.request_id,
        "label": req.label,
        "user_id": req.subject.user_id,
        "role": req.subject.role,
        "clearance": req.subject.clearance_level,
        "trust_score": round(req.subject.trust_score, 3),
        "device_trust": round(req.subject.device_trust, 3),
        "operational_need": round(req.subject.operational_need, 3),
        "resource_id": req.resource.resource_id,
        "classification": req.resource.classification_level,
        "sensitivity": round(req.resource.sensitivity, 3),
        "asset_id": req.resource.asset_id,
        "action": req.action,
        "location": req.context.location,
        "location_risk": round(req.context.location_risk, 3),
        "threat_level": round(req.context.threat_level, 3),
        "n_threats": len(req.threats),
        "expected": req.expected_decision.value if req.expected_decision else "",
    }


def _write_log_csv(path: str, model: AccessControlModel,
                   requests: Sequence[AccessRequest],
                   responses: Sequence[AccessResponse]) -> None:
    fields = [
        "model",
        # request fields
        *list(_request_summary(requests[0]).keys()),
        # decision fields
        "decision", "risk_score", "reason", "obligations", "debug",
        "ground_truth_match",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        for req, resp in zip(requests, responses):
            row = {"model": model.name}
            row.update(_request_summary(req))
            row["decision"] = resp.decision.value
            row["risk_score"] = round(resp.risk_score, 2)
            row["reason"] = resp.reason
            row["obligations"] = json.dumps(resp.obligations)
            row["debug"] = _safe(resp.debug)
            if req.expected_decision is None:
                row["ground_truth_match"] = ""
            else:
                exp_allow = req.expected_decision.is_allow_like
                got_allow = resp.decision.is_allow_like
                row["ground_truth_match"] = "match" if exp_allow == got_allow else "miss"
            writer.writerow(row)


def _write_summary_csv(path: str, summaries: List[ModelMetrics]) -> None:
    if not summaries:
        return
    fields = list(summaries[0].as_row().keys())
    with open(path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        for m in summaries:
            writer.writerow(m.as_row())


def _write_requests_csv(path: str, requests: Sequence[AccessRequest]) -> None:
    if not requests:
        return
    fields = list(_request_summary(requests[0]).keys())
    fields.append("threats")
    with open(path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        for req in requests:
            row = _request_summary(req)
            row["threats"] = json.dumps(
                [{"id": t.threat_id,
                  "severity": t.severity,
                  "targets": t.targets,
                  "affects": [t.affects_c, t.affects_i, t.affects_a]}
                 for t in req.threats])
            writer.writerow(row)


def run_scenario(scenario_name: str,
                 requests: Sequence[AccessRequest],
                 models: Sequence[AccessControlModel],
                 results_dir: str) -> Dict[str, ModelMetrics]:
    """Drive one scenario across every model and write all artefacts."""
    os.makedirs(results_dir, exist_ok=True)
    _write_requests_csv(os.path.join(results_dir, f"{scenario_name}_requests.csv"),
                        requests)

    summaries: Dict[str, ModelMetrics] = {}
    for model in models:
        responses: List[AccessResponse] = [model.decide(r) for r in requests]
        log_path = os.path.join(results_dir, f"{scenario_name}_{model.name}.csv")
        _write_log_csv(log_path, model, requests, responses)
        summaries[model.name] = evaluate_model(model.name, requests, responses)

    _write_summary_csv(os.path.join(results_dir, f"{scenario_name}_summary.csv"),
                       list(summaries.values()))

    print(f"\n=== Scenario: {scenario_name} ===")
    print(f"Requests: {len(requests)} | Models: {len(models)}")
    rows = [m.as_row() for m in summaries.values()]
    print(tabulate(rows, headers="keys", tablefmt="github"))
    print(f"\nResults written to: {results_dir}")

    return summaries
