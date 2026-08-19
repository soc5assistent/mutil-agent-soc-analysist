# Contract Specification: FeatureVector

> **Contract ID**: `FEATURE_VECTOR_V1`  
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
| `scaling_version` | `str` | Required | Metadata | Unique identifier/hash of fitted scaler pipeline artifacts. | Scaler Artifact | Agent 4 Verification |
| `is_normalized` | `bool` | Required | Quality Flag | Flag confirming feature array has undergone standard/robust scaling transformation. | Preprocessing Pipeline | Agent 4 Input Validation |

---

## 3. Invariants & Data Sanitization Rules

1. **Numeric Integrity Guarantee**:
   - `features` array MUST NOT contain `NaN`, `Null`, `None`, or `Infinity` (`Inf`/`-Inf`). Any missing value MUST be imputed during Agent 3 transformation.
2. **Dimension Consistency**:
   - The length of `features` MUST exactly match the length of `feature_names` and match the expected input dimension of Agent 4's calibrated model.
3. **Exclusion of Provenance & Raw Metadata**:
   - Provenance fields (`source_type`, `sensor_id`, `collector_version`, `raw_payload_b64`) MUST NOT be directly converted into ML numerical features.
   - Text strings and raw IPs must be properly encoded or excluded to prevent data leakage.

---

## 4. Agent 3 Non-Ownership Declarations

Agent 3 explicitly DOES NOT own:
- Ingestion of raw network packet streams or OS kernel events (owned by Agent 1).
- Execution of YARA, Snort, or Sigma signature matching rules (owned by Agent 2).
- Computation of Isolation Forest decision scores or anomaly probabilities (owned by Agent 4).
- Threat risk level assignments or automated containment actions (owned by Agent 5).
