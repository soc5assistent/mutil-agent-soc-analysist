# Contract Specification: SecurityEvent

> **Contract ID**: `SECURITY_EVENT_V1`  
> **Producer**: Agent 1 (Collector / Ingest Parser)  
> **Consumers**: Agent 2 (Signature Engine), Agent 3 (Feature Engineering)  
> **Status**: Frozen Architecture Contract

---

## 1. Description & Purpose

The `SecurityEvent` payload represents a normalized, structured telemetry record produced by Agent 1 from raw endpoint or network telemetry. It serves as the single source of truth for downstream signature matching (Agent 2) and numerical feature extraction (Agent 3).

---

## 2. Field Specifications

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `str` (UUIDv4) | Required | Provenance | Unique event identifier for tracing. | Agent 1 Generator | Agent 2, Agent 3, Agent 5 |
| `source_type` | `str` (Enum) | Required | Provenance | Origin telemetry environment (`LIVE_ENDPOINT`, `LIVE_NETWORK`, `PCAP`, `CICIoT2023`, `SIMULATOR`, `TEST`). | Telemetry Sensor | Agent 2, Agent 3 (Routing/Auditing) |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | Primary UTC event observation timestamp (`YYYY-MM-DDTHH:MM:SS.fffZ`). | Sensor / Packet Header | Agent 2, Agent 3 |
| `ingest_timestamp_utc` | `str` (ISO8601) | Required | Timestamp | Ingestion timestamp recorded by Agent 1 collector. | Agent 1 Ingest Engine | Auditing, Pipeline SLA Monitoring |
| `sensor_id` | `str` | Required | Provenance | Identifier of collecting sensor/host/tap agent. | Collector Config | Auditing, Threat Origin Tracking |
| `collector_version` | `str` | Required | Provenance | Version string of Agent 1 ingestion engine. | Agent 1 Runtime | Pipeline Auditing |
| `event_duration_ms` | `float` | Optional | Timestamp | Total duration of the event or network flow in milliseconds. | Flow Analyzer / Sysmon | Agent 3 Feature Engineering |
| `src_ip` | `str` (IPv4/IPv6) | Optional | Network | Source IP address. | Network Flow / Socket | Agent 2, Agent 3 |
| `dst_ip` | `str` (IPv4/IPv6) | Optional | Network | Destination IP address. | Network Flow / Socket | Agent 2, Agent 3 |
| `src_port` | `int` (0-65535) | Optional | Network | Source transport port number. | Network Flow Header | Agent 2, Agent 3 |
| `dst_port` | `int` (0-65535) | Optional | Network | Destination transport port number. | Network Flow Header | Agent 2, Agent 3 |
| `protocol` | `str` (Enum) | Optional | Network | Transport/Application protocol (e.g., `TCP`, `UDP`, `ICMP`, `HTTP`, `DNS`). | Packet Header | Agent 2, Agent 3 |
| `packet_count` | `int` ( $\ge 0$) | Optional | Network | Total packets transferred in flow. | Flow Exporter / PCAP | Agent 3 Feature Engineering |
| `byte_count` | `int` ( $\ge 0$) | Optional | Network | Total bytes transferred in flow. | Flow Exporter / PCAP | Agent 3 Feature Engineering |
| `tcp_flags` | `int` (Bitmap) | Optional | Network | Bitmask of TCP flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR). | TCP Header | Agent 2, Agent 3 |
| `header_length` | `int` ( $\ge 0$) | Optional | Network | Length of protocol header in bytes. | Packet Header | Agent 3 Feature Engineering |
| `host_name` | `str` | Optional | Endpoint | Hostname of executing endpoint. | Sysmon / EDR Agent | Agent 2, Agent 3 |
| `process_id` | `int` | Optional | Endpoint | Process ID (PID) associated with event. | OS Kernel / EDR | Agent 2, Agent 3 |
| `process_name` | `str` | Optional | Endpoint | Binary executable name (e.g., `powershell.exe`). | OS Kernel / EDR | Agent 2, Agent 3 |
| `parent_process_id` | `int` | Optional | Endpoint | Parent Process ID (PPID). | OS Kernel / EDR | Agent 2, Agent 3 |
| `parent_process_name` | `str` | Optional | Endpoint | Parent process executable name. | OS Kernel / EDR | Agent 2, Agent 3 |
| `user_id` | `str` | Optional | Endpoint | User account context executing process. | OS Security Context | Agent 2, Agent 3 |
| `command_line` | `str` | Optional | Endpoint | Process launch arguments and command line string. | OS Process Audit | Agent 2, Agent 3 |
| `file_path` | `str` | Optional | Endpoint | Path of accessed or modified file. | File System Filter | Agent 2, Agent 3 |
| `raw_payload_b64` | `str` (Base64) | Optional | Raw Metadata | Base64 encoded raw packet or log payload for deep inspection. | Raw Packet Tap | Agent 2 Deep Inspection |
| `custom_attributes` | `dict` | Optional | Raw Metadata | Key-value dictionary for source-specific unmapped metadata. | Collector Parser | Agent 2, Agent 3 |

---

## 3. Strict Provenance Invariants

1. **Supported Provenance Enum Values**:
   - `LIVE_ENDPOINT`
   - `LIVE_NETWORK`
   - `PCAP`
   - `CICIoT2023`
   - `SIMULATOR`
   - `TEST`
2. **Feature Isolation Rule**:
   - Provenance and source metadata fields (`event_id`, `source_type`, `ingest_timestamp_utc`, `sensor_id`, `collector_version`, `raw_payload_b64`) **MUST NOT automatically become ML numerical features** in Agent 3.
   - Any inclusion of provenance metadata in downstream ML models constitutes data leakage and invalidates architecture contracts.

---

## 4. Agent 1 Non-Ownership Declarations

Agent 1 explicitly DOES NOT own:
- Creation of numerical ML `FeatureVector` payloads or fitting of feature scalers.
- Evaluation of YARA, Snort, Sigma, or static indicator signature rules.
- Running machine learning anomaly detection models or Isolation Forest inference.
- Determination of final threat risk levels or alert disposition.
