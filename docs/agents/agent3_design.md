# Agent 3: Feature Engineering Architecture & Design Specification

> **Component**: Agent 3 (Feature Engineering Agent)  
> **Ownership**: Primary Component  
> **Status**: Architecture Specification (v1.0)

---

## 1. Role & Interface Boundaries

Agent 3 consumes canonical `SecurityEvent` instances from Agent 2, extracts network traffic features, applies preprocessing/scaling transformations, and emits an immutable `FeatureVector` to Agent 4.

```text
[Agent 2: Context Enricher]
           │
           │  (SecurityEvent)
           ▼
┌──────────────────────────────────────────────────────────┐
│                   Agent 3 Engine                         │
│  - Field Extraction & Validation                         │
│  - Protocol & Categorical Indicator Encoding            │
│  - NaN / Inf Safeguard Handling                          │
│  - Fitted Feature Scaling (RobustScaler / MinMaxScaler)  │
└──────────────────────────────────────────────────────────┘
           │
           │  (FeatureVector)
           ▼
[Agent 4: Anomaly Detection Engine]
```

---

## 2. Input & Output Contract Design

### A. Input Contract: `SecurityEvent`
The input payload received from Agent 2 must adhere to a standardized interface containing:
- `event_id`: Unique string identifier (UUIDv4).
- `timestamp`: ISO-8601 UTC timestamp string.
- `transport_metrics`: Packet header metrics (`header_length`, `ttl`, `protocol_type`).
- `rate_metrics`: Flow rates (`rate`, `srate`, `drate`, `iat`).
- `flag_counts`: TCP flag counters (`ack_count`, `syn_count`, `fin_count`, `rst_count`, etc.).
- `protocol_indicators`: Binary or numeric protocol indicators (`HTTP`, `HTTPS`, `DNS`, `SSH`, `TCP`, `UDP`, `ICMP`, etc.).

### B. Output Contract: `FeatureVector`
The output emitted to Agent 4 is an immutable numerical vector container:
- `vector_id`: Unique UUIDv4 identifier.
- `event_id`: Reference to originating `SecurityEvent.event_id`.
- `timestamp`: ISO-8601 UTC timestamp string.
- `feature_count`: Total features in vector.
- `vector_data`: Tuple of 64-bit float values.
- `metadata`: Preprocessing execution metadata (scaler versions, transformation flags).

---

## 3. Preprocessing & Feature Engineering Specifications

### A. Feature Scaling & Transformations
1. **Unbounded / Heavy-Tailed Metrics** (`Rate`, `Tot sum`, `Tot size`, `IAT`):
   - **Transformation**: $\log(1 + x)$ log1p transformation to reduce skew.
   - **Scaling**: `RobustScaler` (centering by median, scaling by IQR) to prevent outlier distortion.
2. **Bounded Transport & Flag Metrics** (`Header_Length`, `Time_To_Live`, flag counts):
   - **Scaling**: `MinMaxScaler` or `RobustScaler` depending on empirical distribution on the training set.
3. **Protocol Indicators** (`HTTP`, `HTTPS`, `DNS`, `SSH`, `TCP`, `UDP`, `ICMP`, `LLC`, `DHCP`):
   - **Encoding**: Binary / numeric indicator values normalized to $[0.0, 1.0]$.

### B. Missing Value & Safeguard Policies
- **NaN / Null Values**: Imputed with column median (derived strictly from training split) or $0.0$ for binary indicators.
- **$\pm\infty$ Values**: Clipped to empirical percentile caps ($99.9$-th percentile derived from training split).
- **Determinism**: Identical inputs run through the fitted Agent 3 transformer produce bit-exact identical `FeatureVector` outputs.

---

## 4. Dataset Limitations & Unavailable Features (CICIoT2023)

Based on the empirical audit of the CICIoT2023 raw dataset:

| Feature Concept | Status in Raw CICIoT2023 | Handling in Agent 3 Canonical Contract |
| :--- | :---: | :--- |
| **Source IP (`src_ip`)** | **ABSENT** | Excluded from feature vector; L3 headers stripped in dataset creation. |
| **Destination IP (`dst_ip`)** | **ABSENT** | Excluded from feature vector; L3 headers stripped in dataset creation. |
| **Source Port (`src_port`)** | **ABSENT** | Excluded from feature vector; transport ports omitted from CSV schema. |
| **Destination Port (`dst_port`)** | **ABSENT** | Excluded from feature vector; transport ports omitted from CSV schema. |
| **Raw Timestamps (`timestamp`)** | **ABSENT** | Time dynamics represented via relative `IAT` and `Rate` features. |
| **Flow ID (`flow_id`)** | **ABSENT** | Omitted from CSV schema; unique event ID assigned upon ingestion. |

---

## 5. Unresolved Interface Questions for Team Members (Agents 1 & 2)

Prior to freezing the final 27-dimensional feature contract, input is required from Agent 1 and Agent 2 maintainers:
1. **Agent 1 (Parser)**: Will live PCAP parsing emit protocol indicators as binary flags $\{0, 1\}$ or normalized floating-point rates?
2. **Agent 2 (Enricher)**: Does Agent 2 plan to attach external threat intelligence context (e.g., IP reputation score) that Agent 3 should reserve slots for in future vector versions?
