# Contract Specification: AnomalyResult

> **Contract ID**: `ANOMALY_RESULT_V2`  
> **Producer**: Agent 4 (Anomaly Detection Engine)  
> **Consumer**: Agent 5 (Decision / Fusion Engine)  
> **Status**: Frozen Architecture Contract

---

## 1. Description & Purpose

The `AnomalyResult` payload represents the output of machine learning model evaluation (e.g., Isolation Forest) performed by Agent 4 on a `FeatureVector`. It provides raw decision scores, optional empirical confidence probabilities, and anomaly status flags to Agent 5.

---

## 2. Field Specifications

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `result_id` | `str` (UUIDv4) | Required | Identification | Unique anomaly evaluation result identifier. | Agent 4 Generator | Agent 5 |
| `vector_id` | `str` (UUIDv4) | Required | Reference | Unique ID of evaluated `FeatureVector`. | `FeatureVector` Payload | Agent 5 |
| `event_id` | `str` (UUIDv4) | Required | Reference | Unique ID of originating `SecurityEvent`. | `FeatureVector` Payload | Agent 5 (Join Key) |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | UTC timestamp when anomaly inference was completed. | Agent 4 Runtime | Agent 5 |
| `is_anomaly` | `bool` | **Required** | Classification | Binary decision flag (`True` if anomaly decision threshold exceeded). | Model Decision Threshold | Agent 5 |
| `anomaly_score` | `float` | **Required** | Raw Metric | Uncalibrated decision function output score (e.g. Isolation Forest raw score). | ML Model | Agent 5 Evaluation |
| `calibrated_confidence` | `float` | **Optional** | Calibrated Metric | Empirical probability score $[0.0, 1.0]$. **Optional** until empirical calibration is executed. | Empirical Calibration Model | Agent 5 Fusion Engine |
| `calibration_method` | `str` | Optional | Provenance | Method tag (`PLATT_SCALING`, `ISOTONIC_REGRESSION`, `UNALIGNED_RAW`). Set to `UNALIGNED_RAW` if uncalibrated. | Calibration Artifact | Agent 5 |
| `model_id` | `str` | Required | Provenance | Unique model registry identifier (e.g., `IFOREST_CIC2023_V1`). | Model Registry | Agent 5, Auditing |
| `model_version` | `str` | Required | Provenance | Model artifact version hash or release tag. | Model Artifact | Agent 5, Auditing |

---

## 3. Calibration Audit & Mandatory Requirements

### 3.1 Prohibited Calibration Claims
- **Arbitrary Sigmoid Mapping Prohibition**: Uncalibrated mathematical transformations (such as `1 / (1 + exp(-raw_score))`) **MUST NOT** be claimed as calibrated probabilities.
- `calibrated_confidence` is marked **`OPTIONAL`**. It MUST NOT be populated with arbitrary heuristics until an empirical calibration procedure is executed and validated.

### 3.2 Required Future Calibration Methodology
If empirical calibration is subsequently implemented for Agent 4, it MUST document and enforce:

1. **Calibration Dataset**: A distinct hold-out calibration dataset split strictly separated from training and testing sets.
2. **Data Partitioning**: 3-way group-aware split: `Train Split` (for model fitting) $\rightarrow$ `Calibration Split` (for scaler fitting) $\rightarrow$ `Test Split` (for evaluation).
3. **Calibration Method**: Empirically validated parametric (Platt Scaling / Logistic Regression) or non-parametric (Isotonic Regression) probability mapping.
4. **Evaluation Metrics**: Expected Calibration Error (**ECE**) $< 0.05$ and **Brier Score** optimization.
5. **Recalibration Conditions**: Periodic recalibration triggered upon model retraining, scaler update, or dataset drift detection.

---

## 4. Agent 4 Non-Ownership Declarations

Agent 4 explicitly DOES NOT own:
- Extraction of network or endpoint telemetry fields from raw logs (owned by Agent 1).
- Execution of YARA, Snort, or Sigma signature rules (owned by Agent 2).
- Vectorization, missing value imputation, or feature scaling (owned by Agent 3).
- Threat risk level synthesis or final incident triage disposition (owned by Agent 5).
