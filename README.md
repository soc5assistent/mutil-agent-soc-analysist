# Multi-Agent SOC Detection & Anomaly Analysis System

A modular, multi-agent research architecture for network intrusion and anomaly detection in Security Operations Centers (SOC).

---

## 📌 Repository Information
- **Repository URL**: `https://github.com/soc5assistent/mutil-agent-soc-analysist.git`
- **Visibility**: Private Research Repository
- **Primary Focus**: Clean, reproducible implementation of Agent 3 (Feature Engineering) and Agent 4 (Anomaly Detection).

---

## 👥 Multi-Agent Team Ownership

| Agent | Responsibility Domain | Component Ownership | Implementation Status |
| :--- | :--- | :---: | :---: |
| **Agent 0** | Ingestion & Traffic Collection | Teammate | External / Interface Contract |
| **Agent 1** | Packet & Event Parsing | Teammate | External / Interface Contract |
| **Agent 2** | Context & Enrichment | Teammate | External / Interface Contract |
| **Agent 3** | **Feature Engineering & Vectorization** | **Primary (This Component)** | Architecture & Design Stage |
| **Agent 4** | **Anomaly Detection (Isolation Forest)** | **Primary (This Component)** | Architecture & Design Stage |
| **Agent 5** | Alert Fusion & Decision Engine | Teammate | External / Interface Contract |

---

## 🎯 Research Quality & Anti-Leakage Constraints

To maintain strict scientific validity and prevent data leakage:
1. **No Data Leakage**: Scalers and feature transformers are fitted exclusively on training splits.
2. **Group-Aware Splitting**: Row-level random train/test splitting is strictly prohibited for file-structured datasets like CICIoT2023. Splitting is executed strictly at the file/group level to prevent temporal/session leakage.
3. **Pre-Split Deduplication**: Duplicate rows within files are handled explicitly before train/test partition boundaries are drawn.
4. **Independent Threshold Calibration**: Thresholds (e.g., Isolation Forest decision boundary) are calibrated independently on validation splits and never tuned on held-out test data.
5. **Canonical Representation**: Raw dataset quirks (such as missing IP/port columns in CICIoT2023) are explicitly documented and mapped into canonical contracts without fabricating unavailable data.

---

## 📁 Project Directory Structure

```text
mutil-agent-soc-analysist/
├── agents/
│   ├── agent3_feature_engineering/   # Agent 3 implementation module
│   └── agent4_anomaly_detection/     # Agent 4 implementation module
├── datasets/                         # Dataset placement instructions (Git-ignored)
│   └── README.md
├── evaluation/                       # Evaluation scripts & verification artifacts
│   ├── datasets/
│   └── scripts/
├── tests/                            # Contract & unit verification tests
│   └── test_architecture_contracts.py
├── docs/                             # Architecture & specification documentation
│   ├── architecture/
│   │   └── system_architecture.md
│   ├── datasets/
│   │   └── ciciot2023_methodology.md
│   └── agents/
│       ├── agent3_design.md
│       └── agent4_design.md
├── README.md
├── .gitignore
└── requirements.txt
```

---

## 🚀 Setup & Installation

1. **Clone Repository**:
   ```bash
   git clone https://github.com/soc5assistent/mutil-agent-soc-analysist.git
   cd mutil-agent-soc-analysist
   ```

2. **Virtual Environment Setup**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run Architecture Contract Tests**:
   ```bash
   pytest tests/
   ```
