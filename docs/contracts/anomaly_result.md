# Contract Specification: AnomalyResult

> **Contract ID**: `ANOMALY_RESULT_V1`  
> **Producer**: Agent 4 (Anomaly Detection Engine)  
> **Consumer**: Agent 5 (Decision / Fusion Engine)  
> **Status**: Frozen Architecture Contract

---

## 1. Description & Purpose

The `AnomalyResult` payload represents the output of machine learning model evaluation (e.g., Isolation Forest, Autoencoder) performed by Agent 4 on a `FeatureVector`. It provides raw decision scores, calibrated confidence probabilities, and anomaly status flags to Agent 5.

---

## 2. Field Specifications

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `result_id` | `str` (UUIDv4) | Required | Identification | Unique anomaly evaluation result identifier. | Agent 4 Generator | Agent 5 |
| `vector_id` | `str` (UUIDv4) | Required | Reference | Unique ID of evaluated `FeatureVector`. | `FeatureVector` Payload | Agent 5 |
| `event_id` | `str` (UUIDv4) | Required | Reference | Unique ID of originating `SecurityEvent`. | `FeatureVector` Payload | Agent 5 (Join Key) |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | UTC timestamp when anomaly inference was completed. | Agent 4 Runtime | Agent 5 |
| `is_anomaly` | `bool` | Required | Classification | Binary decision flag (`True` if anomaly threshold exceeded). | Model Decision Threshold | Agent 5 |
| `anomaly_score` | `float` | Required | Raw Metric | Uncalibrated decision function output score (e.g., Isolation Forest raw score). | ML Model | Agent 5 Evaluation |
| `calibrated_confidence` | `float` | Required | Calibrated Metric | Calibrated anomaly probability bounded in range $[0.0, 1.0]$. | Sigmoid / Platt Scaler | Agent 5 Fusion Engine |
| `model_id` | `str` | Required | Provenance | Unique model registry identifier (e.g., `IFOREST_CIC2023_V1`). | Model Registry | Agent 5, Auditing |
| `model_version` | `str` | Required | Provenance | Model artifact version hash or release tag. | Model Artifact | Agent 5, Auditing |

---

## 3. Invariants & Calibration Rules

1. **Confidence Bounding**:
   - `calibrated_confidence` MUST strictly satisfy $0.0 \le \text{calibrated\_confidence} \le 1.0$.
2. **Threshold Consistency**:
   - `is_anomaly` MUST equal `True` if `calibrated_confidence` exceeds the documented model threshold (e.g., $\ge 0.50$).
3. **No Signature Logic**:
   - Agent 4 MUST NOT inspect static rule definitions, IP blacklists, or string pattern matches.

---

## 4. Agent 4 Non-Ownership Declarations

Agent 4 explicitly DOES NOT own:
- Extraction of network or endpoint telemetry fields from raw logs (owned by Agent 1).
- Execution of YARA, Snort, or Sigma signature rules (owned by Agent 2).
- Vectorization, missing value imputation, or feature scaling (owned by Agent 3).
- Threat risk level synthesis or final incident triage disposition (owned by Agent 5).
