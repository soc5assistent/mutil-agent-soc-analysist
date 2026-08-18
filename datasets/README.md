# Datasets Directory & Storage Guidelines

> **IMPORTANT**: Raw dataset files (`*.csv`, `*.pcap`, `*.pcapng`) are **STRICTLY EXCLUDED** from Version Control (Git) via `.gitignore`. Do **NOT** upload dataset files to the GitHub repository.

---

## 📊 Dataset Inventory & Audit Findings

### 1. Primary Dataset: CICIoT2023 (Raw)
- **Local Path**: `datasets/cic_iot_2023/raw/`
- **Total CSV Files**: `309`
- **Total Verified Data Rows**: `46,776,700`
- **Header Column Count**: `39` (100% identical column names and ordering across all 309 files)
- **Header Label Column**: `ABSENT` (Ground-truth classes are encoded structurally via directory parent names)
- **Exact Within-File Duplicates**: `18,231,178` rows (`38.9749%` overall duplicate rate)
- **Category Count**: `34` parent folders (`Benign_Final`, `DDoS-*`, `DoS-*`, `Mirai-*`, `Recon-*`, etc.)

### 2. Secondary Datasets (Validation & Independent Benchmarking)
- **BoT-IoT**: `datasets/bot_iot/` (Secondary validation for IoT traffic dynamics)
- **UNSW-NB15**: `datasets/unsw_nb15/` (Independent benchmark for multi-class anomaly detection)

---

## 🔒 Dataset Handling Rules

1. **No Commit Policy**: Check `git status` before committing to ensure `datasets/` files remain untracked.
2. **File-Level Splitting**: When training or evaluating, split data by entire CSV files or category directories to avoid temporal and session data leakage across train/validation/test sets.
3. **Pre-Split Deduplication**: Deduplicate rows within files/splits prior to feature transformation.
4. **Canonical Mapping**: Raw CSV feature columns are ingested and mapped into standard `SecurityEvent` / `FeatureVector` schemas without hardcoding dataset-specific assumptions into model logic.
