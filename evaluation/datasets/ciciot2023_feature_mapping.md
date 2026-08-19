# CICIoT2023 to Agent 3 Feature Mapping Audit

> **Contract Version**: Agent 3 Preprocessing Specification v1.0 (27-Dimensional Vector)


## 1. Feature Mapping Table

| Feature | CICIoT2023 Source Column(s) | Mapping Type | Formula | Available? | Notes |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `Header_Length` | `Header_Length` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Protocol Type` | `Protocol Type` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Time_To_Live` | `Time_To_Live` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Rate` | `Rate` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `psh_flag_number` | `psh_flag_number` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `ack_flag_number` | `ack_flag_number` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `ack_count` | `ack_count` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `syn_count` | `syn_count` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `fin_count` | `fin_count` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `rst_count` | `rst_count` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `HTTP` | `HTTP` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `HTTPS` | `HTTPS` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `DNS` | `DNS` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `SSH` | `SSH` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `TCP` | `TCP` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `UDP` | `UDP` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `ICMP` | `ICMP` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `LLC` | `LLC` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Tot sum` | `Tot sum` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Min` | `Min` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Max` | `Max` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Std` | `Std` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Tot size` | `Tot size` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `IAT` | `IAT` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `Number` | `Number` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `DHCP` | `DHCP` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |
| `ece_flag_number` | `ece_flag_number` | Direct Mapping | `Direct identity mapping` | `YES (All Files)` | Matches exact column name in CICIoT2023 39-column header. |


## 2. Fundamental Network Concepts Availability

| Concept | Status | Source Column in CICIoT2023 | Notes |
| :--- | :---: | :--- | :--- |
| **src_ip** | `ABSENT` | *ABSENT* | No source IP column in CSV headers (L3 headers stripped in dataset creation) |
| **dst_ip** | `ABSENT` | *ABSENT* | No destination IP column in CSV headers (L3 headers stripped in dataset creation) |
| **src_port** | `ABSENT` | *ABSENT* | No source port column in CSV headers (Transport ports omitted) |
| **dst_port** | `ABSENT` | *ABSENT* | No destination port column in CSV headers (Transport ports omitted) |
| **protocol** | `AVAILABLE` | `Protocol Type` | Numeric protocol identifier column present |
| **byte_count** | `AVAILABLE` | `Tot size / Tot sum` | Flow total size and byte sum columns present |
| **packet_count** | `AVAILABLE` | `Number` | Number column represents total flow packet count |
| **duration_ms** | `ABSENT` | `Derived estimate only` | No explicit Duration column. Can be estimated as (Tot size / Rate) or (Number * IAT) |
| **rate_bps** | `AVAILABLE` | `Rate` | Rate column represents flow byte/packet rate |
| **packets_per_sec** | `AVAILABLE` | `Rate` | Rate column represents transmission rate |
| **mean_iat_ms** | `AVAILABLE` | `IAT` | IAT column represents mean inter-arrival time |
| **TCP flag counts** | `AVAILABLE` | `fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number, ece_flag_number, cwr_flag_number, ack_count, syn_count, fin_count, rst_count` | Full set of 11 TCP flag count and flag indicator columns present |
| **protocol indicators** | `AVAILABLE` | `HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP, IGMP, IPv, LLC` | 15 application & layer protocol binary/numeric indicator columns present |


## 3. Unavailable & Impossible Features Analysis

- **IP Addresses (`src_ip`, `dst_ip`)**: **ABSENT**. The raw CSV files contain pre-aggregated statistical features; L3 IP addresses were stripped for privacy.

- **Transport Ports (`src_port`, `dst_port`)**: **ABSENT**. Raw port numbers were omitted from the summary CSV feature schema.

- **Raw Timestamps (`timestamp`, `start_time`)**: **ABSENT**. Time dynamics are captured exclusively via relative `IAT` (Inter-Arrival Time) and `Rate` features.

- **Flow Identifiers (`flow_id`)**: **ABSENT**. Flow tuple identifiers are not present in the CSV header.
