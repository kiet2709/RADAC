# Comparative experimental framework for access-control models

A reproducible Python framework that implements **six** access-control
models and benchmarks them under two carefully designed scenarios.

| #   | Model                | Standard / Source                                                      |
|----:|----------------------|------------------------------------------------------------------------|
|  1  | **MAC**              | Bell-LaPadula lattice (no-read-up, no-write-down)                      |
|  2  | **DAC**              | Owner-driven access-control list                                       |
|  3  | **RBAC**             | NIST RBAC0 (role -> permissions)                                       |
|  4  | **ABAC**             | XACML 3.0 deny-overrides over attribute rules                          |
|  5  | **RADAC** (original) | McGraw 2009 — real-time probabilistic risk + operational-need trade-off |
|  6  | **Improved RADAC**   | Lee, Vanickis, Rogelio, Jacob 2017 — *FURZE + SSA* (paper under study)  |

The original RADAC is implemented in its un-enhanced form (linear risk
formula and threshold bands). The Improved RADAC is the paper's full
FURZE policy framework: Mamdani fuzzy inference for risk evaluation
plus Security Situational Awareness (SSA) via a Mission Dependency
Graph and a Rule-Based Fuzzy Cognitive Map. No mechanism beyond what
the paper describes has been added.

---

## Repository layout

```
combine_RADAC/
├── src/
│   ├── common/                     # shared dataclasses + metrics
│   │   ├── entities.py
│   │   └── metrics.py
│   ├── models/
│   │   ├── base.py                 # AccessControlModel ABC
│   │   ├── mac.py
│   │   ├── dac.py
│   │   ├── rbac.py
│   │   ├── abac.py
│   │   ├── radac.py                # original RADAC
│   │   └── radac_improved/         # paper-faithful implementation
│   │       ├── fuzzy_engine.py     # Mamdani fuzzy risk evaluation
│   │       ├── fcm.py              # Rule-Based Fuzzy Cognitive Map
│   │       ├── mission_graph.py    # MDG (trickle-down + percolate-up)
│   │       ├── ssa_evaluator.py    # SSA = MDG + RB-FCM
│   │       └── model.py            # ImprovedRADACModel facade
│   └── evaluator.py                # unified runner + CSV writers
├── scenarios/
│   ├── scenario1.py                # dynamic risk-sensitive context
│   └── scenario2.py                # mission-impact / SSA scenario
├── data/
│   └── mission_graph.json          # MDG used by Improved RADAC in S2
├── results/                        # CSV outputs (created at runtime)
├── docs/
│   └── paper                       # document related
├── tests/
│   ├── test_models.py
│   └── test_scenarios.py
├── run_scenario1.py
├── run_scenario2.py
├── run_all.py
├── requirements.txt
└── README.md
```

---

## Setup

```powershell
# 1. clone / open the project
cd combine_RADAC

# 2. create a virtual environment (Python 3.10+)
python -m venv .venv

# 3. install dependencies
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The same commands work on Linux / macOS — replace `.\.venv\Scripts\python.exe`
with `./.venv/bin/python`.

---

## Running the experiments

```powershell
# all scenarios in one go
.\.venv\Scripts\python.exe run_all.py

# or run them individually
.\.venv\Scripts\python.exe run_scenario1.py
.\.venv\Scripts\python.exe run_scenario2.py

# unit tests
.\.venv\Scripts\python.exe -m unittest tests.test_models tests.test_scenarios -v
```

For each scenario the runner:

1. Builds **one fixed list of access requests** (16 requests).
2. Sends that *same* list to each of the six models in turn.
3. Writes per-request decision CSVs and one summary CSV to `results/`.
4. Prints the comparison table to stdout.

Reproducibility: all data and parameters are deterministic and
hard-coded in `scenarios/*.py` and `data/mission_graph.json`. Re-runs
yield identical CSV files.

---

## Output files

After running both scenarios you will find under `results/`:

```
scenario1_requests.csv          # the request list (input snapshot)
scenario1_MAC.csv               # one row per request: decision, risk,
scenario1_DAC.csv               #     reason, obligations, debug, ground-truth match
scenario1_RBAC.csv
scenario1_ABAC.csv
scenario1_RADAC.csv
scenario1_Improved-RADAC.csv
scenario1_summary.csv           # one row per model: aggregated metrics
scenario2_*.csv                 # same six files for the second scenario
```

---

## Evaluation metrics (computed in `src/common/metrics.py`)

| Metric             | Meaning                                                                                  |
|--------------------|-------------------------------------------------------------------------------------------|
| `accuracy`         | Fraction of decisions matching the scenario's ground truth                              |
| `false_allow_rate` | of all should-DENY requests, the fraction the model wrongly ALLOW-ed                    |
| `false_deny_rate`  | of all should-ALLOW requests, the fraction the model wrongly DENY-ed                    |
| `adaptability`     | Fraction of consecutive request pairs where the verdict changes (responds to context)   |
| `consistency`      | Identical inputs always yield identical decisions (sanity check)                        |
| `mean_risk`        | Average reported risk score (0 for risk-blind models)                                   |

ALLOW and ALLOW_WITH_OBLIGATIONS are treated as "allow-like" when
comparing to ground-truth (both grant access; obligations only add
controls).

---

## Expected results

### Scenario 1 — dynamic, risk-sensitive context (RADAC's strength)

Same identity, same resource; **only context varies** (threat level,
location, operational need, device posture). Ground truth: 8 should-allow
and 8 should-deny requests.

| Model            | Accuracy | False-allow | False-deny | Notes                                                  |
|------------------|---------:|------------:|-----------:|--------------------------------------------------------|
| MAC              | 0.50     | 1.00        | 0.00       | Identity unchanged -> always ALLOW                     |
| DAC              | 0.50     | 1.00        | 0.00       | ACL static -> always ALLOW                             |
| RBAC             | 0.50     | 1.00        | 0.00       | Role static -> always ALLOW                            |
| ABAC             | 0.81     | 0.38        | 0.00       | Catches the obvious cases; conjunctive rules miss gradations |
| **RADAC**        | **1.00** | 0.00        | 0.00       | Real-time risk score tracks context perfectly          |
| Improved RADAC   | 1.00     | 0.00        | 0.00       | Matches RADAC; SSA component contributes nothing here   |

### Scenario 2 — situational awareness via mission impact (the paper's contribution)

Same identity, **two resources with identical direct attributes**
(classification, sensitivity, ACL). The only difference is which asset
the request targets in the mission dependency graph: the
`payment_gateway` is mission-critical, the `sandbox_kb` is isolated.
Some requests carry threat events targeting one asset or the other.

| Model              | Accuracy | False-allow | False-deny | Notes                                                       |
|--------------------|---------:|------------:|-----------:|-------------------------------------------------------------|
| MAC                | 0.75     | 1.00        | 0.00       | Allows everything (direct attrs identical)                  |
| DAC                | 0.75     | 1.00        | 0.00       | Same                                                        |
| RBAC               | 0.75     | 1.00        | 0.00       | Same                                                        |
| ABAC               | 0.75     | 1.00        | 0.00       | Same                                                        |
| **RADAC**          | 0.75     | 1.00        | 0.00       | Risk score equal for both resources; cannot tell them apart |
| **Improved RADAC** | **1.00** | 0.00        | 0.00       | Mission graph + SSA detect the targeted critical asset      |

---

## Design constraints honoured

* **Original RADAC** uses only the McGraw (2009) recipe: real-time
  probabilistic risk + operational-need trade-off + threshold bands.
  No fuzzy logic, no mission graph, no decision continuity.
* **Improved RADAC** is built strictly from the paper: FURZE risk
  evaluation via Mamdani fuzzy inference, SSA via Mission Dependency
  Graph + Rule-Based Fuzzy Cognitive Map, decision continuity via
  re-evaluation entry point. Nothing beyond what the paper specifies.
* **MAC / DAC / RBAC / ABAC** are textbook implementations with no
  enhancements. Their permissions in both scenarios are configured so
  they could in principle either always allow or always deny — they
  are never disadvantaged through deliberately broken configuration.
* **Same request list** is fed to every model in each scenario, so
  comparisons are like-for-like.

See [`docs/explanation.md`](docs/explanation.md) for a longer,
plain-English walk-through of the models, scenarios and metrics.
