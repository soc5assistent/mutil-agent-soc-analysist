# Agent 4: Anomaly Detection Architecture & Design Specification

> **Component**: Agent 4 (Anomaly Detection Engine)  
> **Ownership**: Primary Component  
> **Status**: Architecture Specification (v1.0)

---

## 1. Role & Interface Boundaries

Agent 4 receives scaled numerical `FeatureVector` instances from Agent 3, evaluates anomaly scores using an independently trained Isolation Forest model, calibrates threshold decisions, and emits `AnomalyResult` payloads to Agent 5.

```text
[Agent 3: Feature Engineering]
           │
           │  (FeatureVector)
           ▼
┌──────────────────────────────────────────────────────────┐
│                   Agent 4 Engine                         │
│  - Inference Preprocessing Consistency Check             │
│  - Isolation Forest Evaluation (score_samples)           │
│  - Calibrated Decision Boundary Threshold Evaluation     │
│  - Confidence Normalization                              │
└──────────────────────────────────────────────────────────┘
           │
           │  (AnomalyResult)
           ▼
[Agent 5: Alert Fusion Engine]
```

---

## 2. Model & Training Methodology

### A. Training & Validation Strategy
- **Unsupervised Anomaly Detection**: Isolation Forest is trained **exclusively on clean benign traffic** (`Benign_Final` directory split for CICIoT2023).
- **Partitioning**: Training split (70%), Validation split (15%), untouched Held-out Test split (15%). Partitioning is executed **at the file/group level** to prevent temporal data leakage.
- **Threshold Calibration**:
  > **CRITICAL RULE**: The previous project threshold ($0.52$) **MUST NOT** be automatically reused. The anomaly threshold must be calibrated independently on the new validation split by optimizing decision metrics (F1-score / Precision-Recall curve trade-off) prior to test evaluation.

### B. Isolation Forest Configuration
- **Estimators (`n_estimators`)**: Default 100 (configurable via environment/config).
- **Sub-sampling (`max_samples`)**: `'auto'` (or 256 for stable memory footprint).
- **Contamination Parameter (`contamination`)**: Configured based on empirical benign validation noise rate (e.g., `'auto'` or calibrated thresholding).
- **Reproducibility (`random_state`)**: Fixed seed (e.g., `42`) enforced for all training runs.

---

## 3. Score Semantics & Decision Pipeline

1. **Raw Decision Function**:
   Uses `model.score_samples(vector)` from `scikit-learn` (returns negative anomaly score where lower values indicate higher anomaly likelihood).
2. **Threshold Decision**:
   $$\text{is\_anomaly} = \begin{cases} \text{True} & \text{if } \text{raw\_score} < \tau_{\text{calibrated}} \\ \text{False} & \text{otherwise} \end{cases}$$
3. **Calibrated Confidence Score**:
   Normalized anomaly severity score scaled into $[0.0, 1.0]$ for downstream consumption by Agent 5.

---

## 4. Model Persistence & Versioning

Models and preprocessing metadata are saved together as immutable bundles:
- `models/agent4_isolation_forest_v1.0.joblib`: Serialized model weights.
- `models/agent4_isolation_forest_v1.0_metadata.json`: Preprocessing scaler state, feature indices, calibrated threshold $\tau$, training timestamp, git commit hash, and dataset version.

---

## 5. Output Contract: `AnomalyResult`

The output emitted to Agent 5 contains:
- `result_id`: Unique UUIDv4 identifier.
- `vector_id`: Reference to originating `FeatureVector.vector_id`.
- `event_id`: Reference to originating `SecurityEvent.event_id`.
- `is_anomaly`: Boolean decision flag.
- `raw_score`: Uncalibrated Isolation Forest score sample.
- `calibrated_confidence`: Normalized confidence score in $[0.0, 1.0]$.
- `model_version`: Version string matching trained model artifact.
- `timestamp`: ISO-8601 UTC timestamp string.

---

## 6. Unresolved Interface Questions for Team Members (Agent 5)

1. **Agent 5 (Fusion)**: Does Agent 5 require continuous float anomaly scores for fusion weighting or a binary boolean alert trigger? (Agent 4 provides both in `AnomalyResult`).
2. **Agent 5 (Fusion)**: What is the expected alert latency SLA for high-throughput traffic evaluation?
