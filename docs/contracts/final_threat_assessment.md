# Contract Specification: FinalThreatAssessment

> **Contract ID**: `FINAL_THREAT_ASSESSMENT_V1`  
> **Producer**: Agent 5 (Decision / Fusion Engine)  
> **Consumer**: Downstream SOC Incident Response / SIEM / Alerting Dashboard  
> **Status**: Frozen Architecture Contract

---

## 1. Description & Purpose

The `FinalThreatAssessment` payload represents the ultimate synthesized output of the multi-agent detection system. Agent 5 ingests deterministic evidence from Agent 2 (`SignatureEvidence`) and statistical/ML evidence from Agent 4 (`AnomalyResult`) to produce a unified threat assessment, overall threat level, and recommended response action.

---

## 2. Field Specifications

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `assessment_id` | `str` (UUIDv4) | Required | Identification | Unique threat assessment record identifier. | Agent 5 Generator | SIEM / Dashboard |
| `event_id` | `str` (UUIDv4) | Required | Reference | Unique ID of originating `SecurityEvent`. | `SecurityEvent` Payload | SIEM / Incident Audit |
| `evidence_id` | `str` (UUIDv4) | Required | Reference | Unique ID of associated `SignatureEvidence`. | `SignatureEvidence` Payload | Incident Audit |
| `result_id` | `str` (UUIDv4) | Required | Reference | Unique ID of associated `AnomalyResult`. | `AnomalyResult` Payload | Incident Audit |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | UTC timestamp of threat assessment generation. | Agent 5 Runtime | SIEM / Dashboard |
| `overall_threat_level` | `str` (Enum) | Required | Assessment | Threat classification (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | Fusion Matrix | SOC Analysts / SOAR |
| `action_recommended` | `str` (Enum) | Required | Recommendation | Automated action recommendation (`ALLOW`, `LOG`, `INVESTIGATE`, `ISOLATE`, `BLOCK`). | Action Engine | SOAR Automation |
| `fusion_rationale` | `str` | Required | Explanation | Human-readable synthesis explaining how signature match and anomaly score were weighted. | Decision Logic | SOC Analysts |
| `confidence_score` | `float` | Required | Metric | Combined composite confidence score bounded in range $[0.0, 1.0]$. | Fusion Calculation | Dashboard |
| `evaluator_version` | `str` | Required | Provenance | Version of Agent 5 fusion engine and rule matrix. | Agent 5 Runtime | Auditing |

---

## 3. Threat Assessment Matrix Invariants

1. **Threat Level Enum Values**:
   - `NONE`
   - `LOW`
   - `MEDIUM`
   - `HIGH`
   - `CRITICAL`
2. **Action Recommendation Enum Values**:
   - `ALLOW`
   - `LOG`
   - `INVESTIGATE`
   - `ISOLATE`
   - `BLOCK`
3. **Multi-Source Evidence Requirement**:
   - Agent 5 MUST correlate inputs using `event_id`. An assessment cannot be completed without verifying corresponding source references.

---

## 4. Agent 5 Non-Ownership Declarations

Agent 5 explicitly DOES NOT own:
- Direct parsing or ingestion of raw PCAPs, network logs, or endpoint telemetry (owned by Agent 1).
- Execution of YARA, Snort, or Sigma signature rules (owned by Agent 2).
- Vectorization, scaling, or numeric transformation of security events (owned by Agent 3).
- Model training or direct ML score evaluation (owned by Agent 4).
