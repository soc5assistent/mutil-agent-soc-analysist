# Dataset Training & Evaluation Methodology Specification

> **Document Status**: Canonical Training & Evaluation Methodology (v1.0 - Frozen)

---

## 1. Benchmark Dataset Provenance & Empirical Metrics

The primary network security benchmark dataset for model training and evaluation is **CICIoT2023**. All figures documented below were empirically verified via a 100% read-only forensic schema audit across the local raw dataset repository (`datasets/cic_iot_2023/raw/`).

### Empirical Dataset Characteristics

| Characteristic | Empirically Verified Metric | Notes |
| :--- | :--- | :--- |
| **Provenance Source** | `CICIoT2023` | Benchmark dataset of IoT network flow records. |
| **Total CSV Files** | `309` | Distributed across 34 top-level traffic category directories. |
| **Total Ingested Rows** | `46,776,700` | Verified row count across all 309 files. |
| **Data Size on Disk** | `8.33 GB` (8,943,771,319 bytes) | Uncompressed raw CSV file size. |
| **Header Schema Columns** | `39` | 100% uniform column names and ordering across all 309 files. |
| **Exact Duplicate Rows** | `13,711,895` | Within-file exact duplicate rows. |
| **Duplicate Row Percentage** | `29.3135%` | Overall duplicate rate across total dataset rows. |
| **Explicit Target Column** | `ABSENT` | No `label`, `class`, or `attack` column exists in CSV headers. |
| **Ground-Truth Source** | Directory structure | Class categories are encoded in top-level directory names. |

---

## 2. Duplicate Row Handling & Data Sanitization

1. **Empirical Finding**: 13,711,895 rows (29.3135%) are identical within-file duplicates resulting from high-frequency flood attacks (e.g. DDoS-ICMP, DDoS-SYN).
2. **Deduplication Invariant**:
   - Exact duplicate rows **MUST** be removed within each dataset partition *prior* to fitting scalers in Agent 3 or training models in Agent 4.
   - Leaving duplicate rows in training/testing splits artificially inflates model performance metrics and biases feature scaling toward repetitive packet patterns.

---

## 3. Group-Aware File-Level Partitioning

1. **Prohibition of Row-Level Random Splitting**:
   - Row-level random sampling (e.g., `train_test_split(df, test_size=0.2)`) is **STRICTLY PROHIBITED**.
   - Consecutive rows in flow datasets share temporal session states and packet sequences. Row-level splitting causes catastrophic data leakage across train and test sets.
2. **File-Level & Group-Aware Partitioning**:
   - Train, validation, and test splits **MUST** be constructed at the **file level or directory group level**.
   - Entire CSV files are assigned atomically to either `train`, `val`, or `test`. No individual file's rows may span across split boundaries.

---

## 4. Class Imbalance & Category-Stratified Evaluation

1. **Empirical Imbalance Findings**:
   - File counts per category range from 1 file (e.g., `Backdoor_Malware`, `BrowserHijacking`, `SqlInjection`) up to 29 files (`Mirai-greeth_flood`) and 27 files (`DDoS-ICMP_Flood`).
   - Category row counts range from ~3,218 rows (`Backdoor_Malware`) to >7,200,000 rows (`DDoS-ICMP_Flood`).
2. **Stratification & Sampling Invariants**:
   - Evaluation MUST report category-stratified metrics (Precision, Recall, F1-Score per traffic class) rather than single aggregated accuracy.
   - Class imbalance during model fitting MUST be managed via group-aware sampling or cost-sensitive loss weighting without altering test set distributions.

---

## 5. Prevention of Metadata & Label Leakage

1. **Ground-Truth Isolation**:
   - Class labels derived from directory names (e.g., `Benign_Final`, `DDoS-ACK_Fragmentation`) serve strictly as evaluation targets for Agent 4 test suites.
2. **Explicit Feature Exclusion Invariant**:
   - `source_file`, `category`, `attack_label`, `folder_name`, `dataset_name`, and `provenance` metadata **MUST NOT** be encoded or passed as numerical features in `FeatureVector`.
   - Agent 3 feature pipelines accept only sanitized numerical telemetry fields.

---

## 6. Training Pipeline Execution Order

```text
1. File-Level Partitioning  --> Assign 309 CSV files to Train / Val / Test sets by file group.
2. Data Deduplication       --> Remove within-file exact duplicates (29.31% rate) per set.
3. SecurityEvent Mapping    --> Dataset Adapter parses CSVs to canonical SecurityEvent.
4. Agent 3 Preprocessing   --> Compute & fit scalers STRICTLY on training split SecurityEvents.
5. FeatureVector Export     --> Transform Train/Val/Test events to non-NaN FeatureVectors.
6. Agent 4 Calibration      --> Fit Isolation Forest on training FeatureVectors; calibrate scores.
```
