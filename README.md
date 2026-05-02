# IoT Trust & Drift

IoT cybersecurity analytics: **device trust scoring**, **behavioral drift detection**, and **explainable risk assessment** from network-style telemetry (synthetic flows and hourly feature windows).

## What it does

- **Anomaly detection** — per device type (Isolation Forest on engineered features).
- **Drift detection** — compares current windows to learned baselines; surfaces top drifting features.
- **Policy engine** — checks flows and features against device-type rules.
- **Trust scoring** — combines signals into a 0–100 style trust view.
- **Evidence / explainability** — human-readable rationales linked to scores and alerts.

Outputs land in `data/` as CSVs consumed by the API and dashboard.

## Repository layout

| Path | Role |
|------|------|
| `ml_engine/` | Anomaly and drift models |
| `trust_engine/` | Policy evaluation and trust scoring |
| `explainability/` | Evidence report generation |
| `api/` | FastAPI backend — serves pipeline CSVs as JSON |
| `dashboard/` | React UI (charts, live views, security pages) |
| `simulators/` | Synthetic dataset generation, live demo helpers, attack injection |
| `config/` | Device profiles and shared config |
| `visualizations/` | Optional plotting / animation scripts |
| `data/` | Input features (`feature_vectors.csv`, `full_dataset.csv`) and pipeline outputs |

## Requirements

- **Python 3.10+** (3.11 recommended)
- **Node.js 18+** for the dashboard

Python dependencies are listed in `requirements.txt`.

## Quick start

### 1. Python environment

```bash
cd iot-trust-drift
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the analytics pipeline

From the project root:

```bash
python run_pipeline.py
```

This runs five stages in order and writes:

- `data/anomaly_scores.csv`
- `data/drift_results.csv`
- `data/policy_results.csv`
- `data/trust_scores.csv`
- `data/evidence_reports.csv`

The repo includes precomputed `data/feature_vectors.csv` and related inputs so you can run the pipeline immediately.

### 3. API server

```bash
python api/server.py
```

The app listens on **port 8001** (`http://localhost:8001`). It reads real pipeline output from `data/` and exposes REST endpoints for the UI (including optional attack-scenario toggles for demos).

### 4. Dashboard

In another terminal:

```bash
cd dashboard
npm install
npm start
```

The dev server proxies API calls to `http://localhost:8001` (see `dashboard/package.json`). Open the URL shown in the terminal (typically `http://localhost:3000`).

## Optional: regenerate synthetic raw data

To rebuild the flow-level synthetic dataset (normal + attack phases):

```bash
python simulators/generate_dataset.py
```

Feature aggregation for the ML pipeline is expected to align with `data/feature_vectors.csv` as used by `run_pipeline.py`. If you replace raw data, ensure `feature_vectors.csv` (and `full_dataset.csv` where needed) stay consistent with your feature engineering.

## Project origin

Public repository: [github.com/Kasvi-1603/iot-Trust_drift-](https://github.com/Kasvi-1603/iot-Trust_drift-)

---

*Educational / research-style telemetry and models — tune thresholds and policies for your environment before production use.*
