# Contract Specification: SecurityEvent

> **Contract ID**: `SECURITY_EVENT_V2`  
> **Producers**: Agent 1 (Collector / Ingest Parser), Dataset Adapter Boundary (CICIoT2023 / PCAP Loader)  
> **Consumers**: Agent 2 (Signature Engine), Agent 3 (Feature Engineering)  
> **Status**: Frozen Architecture & Dataset Compatible Contract

---

## 1. Description & Purpose

The `SecurityEvent` payload represents a normalized, structured telemetry record produced by Agent 1 from raw live telemetry or by a Dataset Adapter from offline benchmark datasets (such as CICIoT2023). It serves as the canonical source of truth for downstream signature matching (Agent 2) and numerical feature extraction (Agent 3).

---

## 2. Field Specifications

### 2.1 Core Provenance, Identification & Timestamps

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `str` (UUIDv4) | Required | Provenance | Unique event identifier for tracing. | Agent 1 / Adapter | Agent 2, Agent 3, Agent 5 |
| `source_type` | `str` (Enum) | Required | Provenance | Origin environment (`LIVE_ENDPOINT`, `LIVE_NETWORK`, `PCAP`, `CICIoT2023`, `SIMULATOR`, `TEST`). | Sensor / Adapter | Agent 2, Agent 3 (Routing/Auditing) |
| `timestamp_utc` | `str` (ISO8601) | Required | Timestamp | Event UTC observation timestamp (`YYYY-MM-DDTHH:MM:SS.fffZ`). | Sensor / Synthetic | Agent 2, Agent 3 |
| `is_synthetic_timestamp` | `bool` | Required | Timestamp | `True` if timestamp was synthetically assigned (e.g. for CICIoT2023 offline flows). | Ingest Engine | Agent 3 (Temporal Feature Masking) |
| `ingest_timestamp_utc` | `str` (ISO8601) | Required | Timestamp | Timestamp recorded when payload entered the pipeline. | Agent 1 / Adapter | Auditing, SLA Tracking |
| `sensor_id` | `str` | Required | Provenance | Identifier of collecting sensor/host/tap or dataset loader. | Config / Loader | Auditing, Lineage |
| `collector_version` | `str` | Required | Provenance | Version string of ingestion engine / dataset adapter. | Agent Runtime | Pipeline Auditing |

### 2.2 Network Header Fields

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `src_ip` | `str` (IPv4/IPv6) | Optional | Network | Source IP address. (*ABSENT in CICIoT2023*) | Socket / Header | Agent 2, Agent 3 |
| `dst_ip` | `str` (IPv4/IPv6) | Optional | Network | Destination IP address. (*ABSENT in CICIoT2023*) | Socket / Header | Agent 2, Agent 3 |
| `src_port` | `int` (0-65535) | Optional | Network | Source transport port number. (*ABSENT in CICIoT2023*) | Transport Header | Agent 2, Agent 3 |
| `dst_port` | `int` (0-65535) | Optional | Network | Destination transport port number. (*ABSENT in CICIoT2023*) | Transport Header | Agent 2, Agent 3 |
| `protocol` | `str` (Enum) | Optional | Network | Upper-layer protocol name (`TCP`, `UDP`, `ICMP`, `HTTP`, `DNS`). | Packet Header | Agent 2, Agent 3 |
| `protocol_type_code` | `int` | Optional | Network | Numeric protocol identifier (e.g., IANA protocol 6=TCP, 17=UDP, 1=ICMP, 0=HOPOPT). | Header / CICIoT2023 | Agent 3 Feature Engineering |
| `time_to_live` | `float` | Optional | Network | IP Time-To-Live (TTL) value. | IP Header | Agent 3 Feature Engineering |
| `header_length` | `float` | Optional | Network | Total header length in bytes. | Packet Header | Agent 3 Feature Engineering |

### 2.3 Typed Flow Statistics (Option A Architecture Extension)

To natively support dataset flow summaries (CICIoT2023, NetFlow, IPFIX) without relying on unstructured `custom_attributes`, `SecurityEvent` includes explicit typed flow statistics:

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `flow_rate` | `float` | Optional | Flow Stats | Transmission rate (packets/sec or bytes/sec). | Flow Exporter / `Rate` | Agent 3 Feature Engineering |
| `srate` | `float` | Optional | Flow Stats | Source-to-destination transmission rate. | Flow Exporter / `Srate` | Agent 3 Feature Engineering |
| `drate` | `float` | Optional | Flow Stats | Destination-to-source transmission rate. | Flow Exporter / `Drate` | Agent 3 Feature Engineering |
| `mean_iat_ms` | `float` | Optional | Flow Stats | Mean inter-arrival time in milliseconds. | Flow Exporter / `IAT` | Agent 3 Feature Engineering |
| `tot_size` | `float` | Optional | Flow Stats | Total payload size across flow packets. | Flow Exporter / `Tot size` | Agent 3 Feature Engineering |
| `tot_sum` | `float` | Optional | Flow Stats | Total byte sum across flow packets. | Flow Exporter / `Tot sum` | Agent 3 Feature Engineering |
| `min_packet_size` | `float` | Optional | Flow Stats | Minimum packet size in flow bytes. | Flow Exporter / `Min` | Agent 3 Feature Engineering |
| `max_packet_size` | `float` | Optional | Flow Stats | Maximum packet size in flow bytes. | Flow Exporter / `Max` | Agent 3 Feature Engineering |
| `avg_packet_size` | `float` | Optional | Flow Stats | Average packet size in flow bytes. | Flow Exporter / `AVG` | Agent 3 Feature Engineering |
| `std_packet_size` | `float` | Optional | Flow Stats | Standard deviation of packet sizes. | Flow Exporter / `Std` | Agent 3 Feature Engineering |
| `variance_packet_size` | `float` | Optional | Flow Stats | Variance of packet sizes in flow. | Flow Exporter / `Variance` | Agent 3 Feature Engineering |
| `packet_count` | `float` | Optional | Flow Stats | Total packet count in flow. | Flow Exporter / `Number` | Agent 3 Feature Engineering |
| `tcp_fin_count` | `float` | Optional | TCP Flags | Total FIN flag occurrences in flow. | TCP Header / `fin_count` | Agent 2, Agent 3 |
| `tcp_syn_count` | `float` | Optional | TCP Flags | Total SYN flag occurrences in flow. | TCP Header / `syn_count` | Agent 2, Agent 3 |
| `tcp_rst_count` | `float` | Optional | TCP Flags | Total RST flag occurrences in flow. | TCP Header / `rst_count` | Agent 2, Agent 3 |
| `tcp_psh_count` | `float` | Optional | TCP Flags | Total PSH flag occurrences in flow. | TCP Header / `psh_count` | Agent 2, Agent 3 |
| `tcp_ack_count` | `float` | Optional | TCP Flags | Total ACK flag occurrences in flow. | TCP Header / `ack_count` | Agent 2, Agent 3 |
| `tcp_ece_count` | `float` | Optional | TCP Flags | Total ECE flag occurrences in flow. | TCP Header / `ece_count` | Agent 2, Agent 3 |
| `tcp_cwr_count` | `float` | Optional | TCP Flags | Total CWR flag occurrences in flow. | TCP Header / `cwr_count` | Agent 2, Agent 3 |
| `proto_http_flag` | `float` | Optional | Protocol Flag | Binary/numeric indicator for HTTP protocol. | Application Filter / `HTTP` | Agent 2, Agent 3 |
| `proto_https_flag` | `float` | Optional | Protocol Flag | Binary/numeric indicator for HTTPS protocol. | Application Filter / `HTTPS` | Agent 2, Agent 3 |
| `proto_dns_flag` | `float` | Optional | Protocol Flag | Binary/numeric indicator for DNS protocol. | Application Filter / `DNS` | Agent 2, Agent 3 |
| `proto_ssh_flag` | `float` | Optional | Protocol Flag | Binary/numeric indicator for SSH protocol. | Application Filter / `SSH` | Agent 2, Agent 3 |
| `proto_dhcp_flag` | `float` | Optional | Protocol Flag | Binary/numeric indicator for DHCP protocol. | Application Filter / `DHCP` | Agent 2, Agent 3 |

### 2.4 Endpoint Fields & Metadata

| Field Name | Type | Req/Opt | Category | Meaning | Source | Downstream Consumer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `host_name` | `str` | Optional | Endpoint | Hostname of executing endpoint. | EDR Agent | Agent 2, Agent 3 |
| `process_name` | `str` | Optional | Endpoint | Binary executable name. | OS Kernel / EDR | Agent 2, Agent 3 |
| `command_line` | `str` | Optional | Endpoint | Command line launch arguments. | OS Process Audit | Agent 2, Agent 3 |
| `raw_payload_b64` | `str` | Optional | Raw Metadata | Base64 raw packet/log payload. | Raw Tap | Agent 2 |
| `custom_attributes` | `dict` | Optional | Raw Metadata | Audited, unmapped operational key-values. | Sensor Parser | Pipeline Routing |

---

## 3. Mandatory Invariants & Non-Leakage Rules

1. **`custom_attributes` Audit Rule & Feature Non-Leakage**:
   - Provenance and metadata fields (`event_id`, `source_type`, `ingest_timestamp_utc`, `sensor_id`, `collector_version`, `raw_payload_b64`, `dataset_name`, `category`, `attack_label`, `source_file`, `folder_name`) **MUST NOT automatically become ML numerical features** in Agent 3.
   - `custom_attributes` MUST NOT be used as an undocumented workaround to transport flow statistics or ground-truth metadata.
   - `custom_attributes` MUST NOT contain: `dataset_name`, `category`, `attack_label`, `source_file`, `folder_name`, `provenance`, `collector_version`, `test_metadata`, `simulator_scenario`, or evaluation-only timestamps.
2. **Synthetic Timestamp Handling**:
   - When ingesting offline datasets lacking wall-clock timestamps (e.g., CICIoT2023), `is_synthetic_timestamp` MUST be set to `True`.
   - Agent 3, Agent 4, and Agent 5 **MUST NOT** derive ML temporal features (such as hour-of-day or day-of-week) from synthetic timestamps.
3. **Protocol Type Mapping Status**:
   - Status: **`NOT ESTABLISHED`** for text string enum conversion.
   - CICIoT2023 numeric values (e.g. 6, 17, 1, 0) are preserved in `protocol_type_code` without unverified string guessing.

---

## 4. Agent 1 Non-Ownership Declarations & Dataset Adapter Boundaries

Agent 1 and Dataset Adapters explicitly DO NOT own:
- Creation of numerical ML `FeatureVector` payloads or fitting of feature scalers.
- Evaluation of YARA, Snort, Sigma, or static indicator signature rules.
- Running machine learning anomaly detection models or Isolation Forest inference.
- Determination of final threat risk levels or alert disposition.
