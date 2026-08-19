# Contract Specification: FeatureVector

> **Contract ID**: `FEATURE_VECTOR_V2`  
> **Producer**: Agent 3 (Feature Engineering Engine)  
> **Consumer**: Agent 4 (Anomaly Detection Engine)  
> **Status**: Frozen Architecture Contract

---

## 1. Description & Purpose

The `FeatureVector` payload represents an immutable, high-dimensional numerical feature representation generated from a `SecurityEvent` by Agent 3. It guarantees sanitized, non-NaN, non-Inf numerical values suitable for direct input into Agent 4's machine learning anomaly models.

---

## 2. Field Specifications

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `vector_id` | `str` (UUIDv4) | Required | Identification | Unique vector record identifier. | Agent 3 Generator | Agent 4 |
| `event_id` | `str` (UUIDv4) | Required | Reference | Unique ID of source `SecurityEvent`. | `SecurityEvent` Payload | Agent 4, Agent 5 (Join Key) |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | UTC timestamp of feature extraction completion. | Agent 3 Runtime | Agent 4 |
| `features` | `list[float]` | Required | Numerical Data | Dense array of preprocessed, scaled 64-bit float values. Guaranteed non-NaN, non-Inf. | Feature Pipeline | Agent 4 ML Model |
| `feature_names` | `list[str]` | Required | Metadata | Ordered schema list of feature names corresponding to vector index positions. | Scaler Registry | Agent 4 Feature Audit |
| `feature_pipeline_version` | `str` | Required | Versioning | Hash/tag of feature extraction logic, feature selection, and column ordering definitions. | Pipeline Artifact | Agent 4 Model Compatibility |
| `scaling_version` | `str` | Required | Versioning | Unique hash/tag of fitted scaler pipeline artifacts (e.g. RobustScaler params). | Scaler Artifact | Agent 4 Verification |
| `model_compatibility_tag` | `str` | Required | Compatibility | Compatibility identifier declaring target model family (e.g. `IFOREST_27D_V1`). | Agent 3 Registry | Agent 4 Ingest Check |
| `is_normalized` | `bool` | Required | Quality Flag | Flag confirming feature array has undergone standard/robust scaling transformation. | Preprocessing Pipeline | Agent 4 Input Validation |

---

## 3. Pipeline & Scaling Versioning Rationale

`FeatureVector` strictly separates `feature_pipeline_version` from `scaling_version`:

1. **`feature_pipeline_version`**:
   - Captures feature selection logic, formula definitions (e.g. rate calculations), and strict `feature_names` index ordering.
   - Prevents index misalignment where model feature #3 expects `flow_rate` but receives `header_length`.
2. **`scaling_version`**:
   - Captures specific fitted parameter weights (medians, interquartile ranges, min/max bounds) derived from training split fitting.
   - Prevents applying scalers fitted on dataset A to events extracted under pipeline version B.

Agent 4 MUST verify five compatibility elements prior to model inference:
1. `feature_names` identity and order
2. `feature_ordering` exact sequence match
3. `feature_pipeline_version` match
4. `scaling_version` match
5. `model_compatibility_tag` match

---

## 4. Invariants & Data Sanitization Rules

1. **Numeric Integrity Guarantee**:
   - `features` array MUST NOT contain `NaN`, `Null`, `None`, or `Infinity` (`Inf`/`-Inf`). Any missing value MUST be imputed during Agent 3 transformation.
2. **Dimension Consistency**:
   - The length of `features` MUST exactly match the length of `feature_names` and match the expected input dimension of Agent 4's calibrated model.
3. **Exclusion of Provenance & Raw Metadata**:
   - Metadata and ground-truth fields (`dataset_name`, `category`, `attack_label`, `source_file`, `folder_name`, `provenance`, `sensor_id`, `collector_version`, `raw_payload_b64`) **MUST NOT** be converted into ML numerical features.

---

## 5. Agent 3 Non-Ownership Declarations

Agent 3 explicitly DOES NOT own:
- Ingestion of raw network packet streams or OS kernel events (owned by Agent 1).
- Execution of YARA, Snort, or Sigma signature matching rules (owned by Agent 2).
- Computation of Isolation Forest decision scores or anomaly probabilities (owned by Agent 4).
- Threat risk level assignments or automated containment actions (owned by Agent 5).
