# Live Telemetry vs Benchmark Dataset Compatibility Audit

> **Document Status**: Canonical Live Telemetry Compatibility Specification (v1.0 - Frozen)

---

## 1. Executive Overview

This audit evaluates every flow-statistic field defined in the `SecurityEvent` schema against Agent 1 live ingestion capabilities and benchmark dataset loaders (CICIoT2023).

To avoid unverified runtime assumptions, each field is classified according to its production status in live streaming environments vs offline benchmark replay.

---

## 2. Classification Definitions

1. **1. Already Produced by Agent 1**: Native field produced directly by Agent 1 collector parsers from standard live log/packet sources.
2. **2. Derived from Agent 1 Raw Telemetry**: Field can be computed statelessly from raw packet payloads or single-log attributes produced by Agent 1.
3. **3. Requires Additional Aggregation / State**: Field requires a stateful flow exporter tap or stream aggregation engine (e.g. NetFlow/IPFIX exporter, Zeek flow logger, or windowed Flink aggregator).
4. **4. Dataset-Only**: Pre-computed statistical feature available in offline benchmark CSV files but absent from standard live raw packet taps unless an explicit flow aggregation engine is installed.

---

## 3. Comprehensive Flow-Statistic Field Compatibility Matrix

| SecurityEvent Field | Live Stream Production Status | CICIoT2023 Status | Classification | Engineering Requirement / Status |
| :--- | :--- | :--- | :--- | :--- |
| `src_ip` | Produced directly | **ABSENT** | **1. Already Produced by Agent 1** | Standard L3 IP header field. |
| `dst_ip` | Produced directly | **ABSENT** | **1. Already Produced by Agent 1** | Standard L3 IP header field. |
| `src_port` | Produced directly | **ABSENT** | **1. Already Produced by Agent 1** | Standard L4 transport port field. |
| `dst_port` | Produced directly | **ABSENT** | **1. Already Produced by Agent 1** | Standard L4 transport port field. |
| `protocol` | Derived from L4 header | Available | **2. Derived from Raw Telemetry** | Statelessly mapped from IP protocol header. |
| `protocol_type_code` | Produced directly | Available | **1. Already Produced by Agent 1** | IANA protocol integer code (6=TCP, 17=UDP, 1=ICMP). |
| `time_to_live` | Produced directly | Available (`Time_To_Live`)| **1. Already Produced by Agent 1** | IP header TTL value. |
| `header_length` | Produced directly | Available (`Header_Length`)| **1. Already Produced by Agent 1** | IP/TCP header length bytes. |
| `flow_rate` | Requires flow aggregator | Available (`Rate`) | **3. Requires State / Aggregation** | **NOT ESTABLISHED** for raw packet taps without NetFlow exporter. |
| `srate` | Requires flow aggregator | Available (`Srate`) | **3. Requires State / Aggregation** | **NOT ESTABLISHED** without directional flow engine. |
| `drate` | Requires flow aggregator | Available (`Drate`) | **3. Requires State / Aggregation** | **NOT ESTABLISHED** without directional flow engine. |
| `mean_iat_ms` | Requires flow aggregator | Available (`IAT`) | **3. Requires State / Aggregation** | Requires windowed inter-packet arrival state. |
| `tot_size` | Requires flow aggregator | Available (`Tot size`)| **3. Requires State / Aggregation** | Accumulator across multi-packet flow window. |
| `tot_sum` | Requires flow aggregator | Available (`Tot sum`) | **3. Requires State / Aggregation** | Byte sum accumulator. |
| `min_packet_size` | Requires flow aggregator | Available (`Min`) | **3. Requires State / Aggregation** | Min packet size in flow window. |
| `max_packet_size` | Requires flow aggregator | Available (`Max`) | **3. Requires State / Aggregation** | Max packet size in flow window. |
| `avg_packet_size` | Requires flow aggregator | Available (`AVG`) | **3. Requires State / Aggregation** | Mean packet size across flow window. |
| `std_packet_size` | Requires flow aggregator | Available (`Std`) | **3. Requires State / Aggregation** | Standard deviation across flow window. |
| `variance_packet_size` | Requires flow aggregator | Available (`Variance`)| **3. Requires State / Aggregation** | Variance across flow window. |
| `packet_count` | Requires flow aggregator | Available (`Number`) | **3. Requires State / Aggregation** | Packet counter across flow window. |
| `tcp_*_count` | Requires flow aggregator | Available | **3. Requires State / Aggregation** | TCP flag counters across flow window. |
| `proto_*_flag` | Derived from payload / port | Available | **2. Derived from Raw Telemetry** | Application protocol filter flags. |

---

## 4. Key Compatibility Audit Findings

1. **Stateful Flow Exporter Dependency**:
   - 14 statistical flow fields (`flow_rate`, `mean_iat_ms`, `tot_size`, `min_packet_size`, `max_packet_size`, `avg_packet_size`, `std_packet_size`, `variance_packet_size`, etc.) cannot be derived statelessly from a single raw packet event emitted by Agent 1.
   - For live network deployment, Agent 1 MUST interface with a stateful flow exporter (e.g. Zeek, Suricata, or NetFlow v9/IPFIX flow engine).
   - In benchmark dataset mode (CICIoT2023), these 14 fields are populated directly by the Dataset Adapter from pre-aggregated CSV headers.
2. **5-Tuple Missing Metric Invariant**:
   - Live telemetry provides complete 5-tuples (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) for signature matching (Agent 2) and incident response (Agent 5).
   - CICIoT2023 benchmark CSV files omit `src_ip`, `dst_ip`, `src_port`, and `dst_port`. Agent 3 feature pipelines MUST NOT mandate 5-tuple fields for ML vectorization.
