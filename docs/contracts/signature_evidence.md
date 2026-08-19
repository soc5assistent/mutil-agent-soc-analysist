# Contract Specification: SignatureEvidence

> **Contract ID**: `SIGNATURE_EVIDENCE_V1`  
> **Producer**: Agent 2 (Signature Engine)  
> **Consumer**: Agent 5 (Decision / Fusion Engine)  
> **Status**: Frozen Architecture Contract

---

## 1. Description & Purpose

The `SignatureEvidence` payload represents the output of deterministic signature rule evaluation (e.g., YARA, Snort/Suricata, Sigma, IOC matchers) executed against an incoming `SecurityEvent`. It conveys structured match findings, rule IDs, and static severity indicators to the fusion engine.

---

## 2. Field Specifications

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `evidence_id` | `str` (UUIDv4) | Required | Identification | Unique evidence record identifier. | Agent 2 Engine | Agent 5 |
| `event_id` | `str` (UUIDv4) | Required | Reference | Unique ID of triggering `SecurityEvent`. | `SecurityEvent` Payload | Agent 5 (Fusion Join Key) |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | UTC time when signature evaluation occurred. | Agent 2 Clock | Agent 5 |
| `signature_matched` | `bool` | Required | Match Result | Boolean flag indicating if one or more signature rules triggered. | Rule Matcher | Agent 5 |
| `rule_id` | `str` | Optional | Match Detail | Identifier of matched signature rule (e.g., `SIG-NET-2024-0042`). | Signature Ruleset | Agent 5 |
| `rule_name` | `str` | Optional | Match Detail | Human-readable name of matched rule (e.g., `Malicious Powershell Encoded Command`). | Signature Ruleset | Agent 5 |
| `severity` | `str` (Enum) | Required | Assessment | Rule severity level (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | Rule Definition | Agent 5 |
| `matched_indicators` | `list[str]` | Required | Evidence | List of specific IOC string patterns or regex substrings matched. | Payload Inspection | Agent 5 |
| `engine_version` | `str` | Required | Provenance | Version of Agent 2 rule engine and active ruleset hash. | Agent 2 Runtime | Auditing, Agent 5 |

---

## 3. Invariants & Constraints

1. **Deterministic Execution**:
   - Signature evaluation must be purely deterministic based on the active ruleset. Given the same `SecurityEvent` and ruleset version, `SignatureEvidence` must be identical.
2. **Strict Rule Matching**:
   - `signature_matched` MUST be `True` if `matched_indicators` is non-empty, and `False` if `matched_indicators` is empty.
3. **No Anomaly Detection**:
   - Agent 2 MUST NOT compute distance metrics, statistical probability distributions, or ML anomaly scores.

---

## 4. Agent 2 Non-Ownership Declarations

Agent 2 explicitly DOES NOT own:
- Machine learning model evaluation or unsupervised anomaly scoring (owned by Agent 4).
- Numerical feature engineering, vector scaling, or tabular matrix creation (owned by Agent 3).
- Direct raw packet/log ingestion from endpoint sensors (owned by Agent 1).
- Final alert triage, SIEM notification dispatch, or threat response mitigation (owned by Agent 5).
