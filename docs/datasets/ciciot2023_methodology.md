# CICIoT2023 Dataset Research Methodology & Pipeline Specification

> **Status**: Dataset Methodology Specification (v1.0)  
> **Primary Dataset**: CICIoT2023 Raw CSV Release

---

## 1. Verified Dataset Inventory

An independent forensic audit of the raw dataset (`datasets/cic_iot_2023/raw/`) verified the following empirical properties:

| Metric | Verified Value | Verification Method |
| :--- | :--- | :--- |
| **Total CSV Files** | `309` | File discovery across 34 parent directories |
| **Total Data Rows** | `46,776,700` | 100% agreement between `csv.reader` and `pandas.read_csv` |
| **Header Columns** | `39` | Exact column name & ordering match across all 309 files |
| **Exact Within-File Duplicates** | `18,231,178` (`38.9749%`) | Deterministic SHA-256 row-tuple hashing |
| **Header Label Column** | `ABSENT` | Structural directory parent path encoding |

---

## 2. Data Ingestion & Ground-Truth Mapping Pipeline

```text
Raw CICIoT2023 (309 CSV files in 34 directories)
                  │
                  ▼
1. Discover CSV Files & Assign Parent Directory Category as Ground Truth
                  │
                  ▼
2. File-Level Deduplication & Pre-Partitioning Clean-up
                  │
                  ▼
3. Group-Aware File-Level Partitioning (Train: 70%, Val: 15%, Test: 15%)
                  │
                  ▼
4. Canonical Event Transformation (SecurityEvent -> Agent 3 FeatureVector)
                  │
                  ▼
5. Preprocessing & Scaling (Fit on Train Split Only)
                  │
                  ▼
6. Agent 4 Isolation Forest Training & Validation Threshold Calibration
```

---

## 3. Ground-Truth Assignment & Category Structure

In raw CICIoT2023 CSV files, no internal column indicates the class label. Class labels are assigned structurally based on the top-level parent folder:

- **Benign Traffic**: Files located in `datasets/cic_iot_2023/raw/Benign_Final/` (`BenignTraffic.pcap.csv`, `BenignTraffic1.pcap.csv`, etc.).
- **Attack Traffic**: Files located in attack-specific folders (e.g., `DDoS-ACK_Fragmentation`, `DoS-TCP_Flood`, `Mirai-greeth_flood`, `Recon-PortScan`).

---

## 4. Anti-Leakage Rules & Splitting Directives

1. **File-Level Group Splitting**:
   Row-level random splitting is **strictly prohibited**. Entire CSV files are assigned to either Train, Validation, or Test splits to prevent session and temporal correlation leakage.
2. **Deduplication Order**:
   Within-file duplicate rows are processed prior to model training to prevent over-representation of repeated scanning/flooding patterns.
3. **No Scaler Fitting on Test Data**:
   Scalers (`RobustScaler`, `MinMaxScaler`) are fitted **only on the training split**. The validation and test splits are transformed using training parameters.
4. **Untouched Test Set**:
   The held-out test split is evaluated **once** at the end of experimentation. Hyperparameters and anomaly decision thresholds are never tuned against the test set.
