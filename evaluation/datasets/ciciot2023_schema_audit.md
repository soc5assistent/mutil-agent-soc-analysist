# CICIoT2023 Forensic Schema Audit Report

> **Audit Mode**: READ-ONLY Forensic Inspection

## Executive Summary

- **Total CSV Files**: `309`
- **Total Rows Inspected**: `46,776,700`
- **Total Data Size**: `8.33 GB` (8,943,771,319 bytes)
- **Distinct Schemas**: `1`
- **Columns per File**: `39`
- **Schema Consistency**: `100% Identical Column Names & Order Across All Files`

## Phase 1: Exact Ordered Schema Columns (39 Columns)

| Index | Column Name | Sample Dtype | Constant Value? | Has NaN? | Has Inf? |
| :---: | :--- | :---: | :---: | :---: | :---: |
| `[00]` | `Header_Length` | `float64` | `NO` | `NO` | `NO` |
| `[01]` | `Protocol Type` | `int64` | `NO` | `NO` | `NO` |
| `[02]` | `Time_To_Live` | `float64` | `NO` | `NO` | `NO` |
| `[03]` | `Rate` | `float64` | `NO` | `NO` | `NO` |
| `[04]` | `fin_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[05]` | `syn_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[06]` | `rst_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[07]` | `psh_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[08]` | `ack_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[09]` | `ece_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[10]` | `cwr_flag_number` | `float64` | `NO` | `YES` | `NO` |
| `[11]` | `ack_count` | `int64` | `NO` | `YES` | `NO` |
| `[12]` | `syn_count` | `int64` | `NO` | `YES` | `NO` |
| `[13]` | `fin_count` | `int64` | `NO` | `YES` | `NO` |
| `[14]` | `rst_count` | `int64` | `NO` | `YES` | `NO` |
| `[15]` | `HTTP` | `float64` | `NO` | `YES` | `NO` |
| `[16]` | `HTTPS` | `float64` | `NO` | `YES` | `NO` |
| `[17]` | `DNS` | `float64` | `NO` | `YES` | `NO` |
| `[18]` | `Telnet` | `float64` | `NO` | `YES` | `NO` |
| `[19]` | `SMTP` | `float64` | `NO` | `YES` | `NO` |
| `[20]` | `SSH` | `float64` | `NO` | `YES` | `NO` |
| `[21]` | `IRC` | `float64` | `NO` | `YES` | `NO` |
| `[22]` | `TCP` | `float64` | `NO` | `YES` | `NO` |
| `[23]` | `UDP` | `float64` | `NO` | `YES` | `NO` |
| `[24]` | `DHCP` | `float64` | `NO` | `YES` | `NO` |
| `[25]` | `ARP` | `float64` | `NO` | `YES` | `NO` |
| `[26]` | `ICMP` | `float64` | `NO` | `YES` | `NO` |
| `[27]` | `IGMP` | `float64` | `NO` | `YES` | `NO` |
| `[28]` | `IPv` | `float64` | `NO` | `YES` | `NO` |
| `[29]` | `LLC` | `float64` | `NO` | `YES` | `NO` |
| `[30]` | `Tot sum` | `int64` | `NO` | `YES` | `NO` |
| `[31]` | `Min` | `int64` | `NO` | `YES` | `NO` |
| `[32]` | `Max` | `int64` | `NO` | `YES` | `NO` |
| `[33]` | `AVG` | `float64` | `NO` | `YES` | `NO` |
| `[34]` | `Std` | `float64` | `NO` | `YES` | `NO` |
| `[35]` | `Tot size` | `float64` | `NO` | `YES` | `NO` |
| `[36]` | `IAT` | `float64` | `NO` | `YES` | `NO` |
| `[37]` | `Number` | `int64` | `NO` | `YES` | `NO` |
| `[38]` | `Variance` | `float64` | `NO` | `YES` | `NO` |


## Phase 2: Category Breakdown & Row Counts

| Category / Directory Name | File Count | Total Row Count | Size (MB) | Category Duplicate Rate |
| :--- | :---: | :---: | :---: | :---: |
| `Backdoor_Malware` | 1 | 3,218 | 0.63 | 0.09% |
| `Benign_Final` | 4 | 1,098,191 | 216.88 | 0.16% |
| `BrowserHijacking` | 1 | 5,859 | 1.15 | 1.21% |
| `CommandInjection` | 1 | 5,409 | 1.06 | 0.39% |
| `DDoS-ACK_Fragmentation` | 13 | 285,075 | 59.87 | 0.05% |
| `DDoS-HTTP_Flood` | 1 | 28,790 | 6.15 | 0.00% |
| `DDoS-ICMP_Flood` | 27 | 7,200,501 | 1264.83 | 37.88% |
| `DDoS-ICMP_Fragmentation` | 20 | 452,490 | 95.1 | 0.03% |
| `DDoS-PSHACK_FLOOD` | 16 | 4,094,772 | 733.91 | 30.32% |
| `DDoS-RSTFINFLOOD` | 16 | 4,045,279 | 731.47 | 37.61% |
| `DDoS-SYN_Flood` | 16 | 4,059,179 | 738.44 | 29.64% |
| `DDoS-SlowLoris` | 1 | 23,426 | 4.98 | 0.00% |
| `DDoS-SynonymousIP_Flood` | 14 | 3,598,133 | 643.38 | 36.04% |
| `DDoS-TCP_Flood` | 18 | 4,497,649 | 804.74 | 37.55% |
| `DDoS-UDP_Flood` | 21 | 5,412,231 | 977.51 | 33.84% |
| `DDoS-UDP_Fragmentation` | 13 | 286,925 | 60.07 | 0.06% |
| `DNS_Spoofing` | 1 | 178,898 | 35.13 | 2.33% |
| `DictionaryBruteForce` | 1 | 13,064 | 2.58 | 0.02% |
| `DoS-HTTP_Flood` | 2 | 71,861 | 15.19 | 0.46% |
| `DoS-SYN_Flood` | 8 | 2,028,836 | 372.51 | 23.71% |
| `DoS-TCP_Flood` | 11 | 2,671,430 | 481.94 | 35.04% |
| `DoS-UDP_Flood` | 17 | 3,072,993 | 577.35 | 23.81% |
| `MITM-ArpSpoofing` | 2 | 307,560 | 59.99 | 7.80% |
| `Mirai-greeth_flood` | 29 | 991,834 | 191.36 | 0.41% |
| `Mirai-greip_flood` | 22 | 751,646 | 146.54 | 0.31% |
| `Mirai-udpplain` | 25 | 890,574 | 170.8 | 1.01% |
| `Recon-HostDiscovery` | 1 | 134,378 | 25.14 | 0.60% |
| `Recon-OSScan` | 1 | 98,259 | 18.96 | 1.79% |
| `Recon-PingSweep` | 1 | 2,262 | 0.45 | 0.00% |
| `Recon-PortScan` | 1 | 82,284 | 15.65 | 2.48% |
| `SqlInjection` | 1 | 5,245 | 1.04 | 0.00% |
| `Uploading_Attack` | 1 | 1,252 | 0.25 | 0.00% |
| `VulnerabilityScan` | 1 | 373,351 | 73.66 | 0.25% |
| `XSS` | 1 | 3,846 | 0.76 | 0.00% |


## Phase 5: Label Investigation

- **Label Column Status**: `Explicit label column not established.`
- **Findings**: In the raw CSV headers, no explicit target column (`label`, `class`, `attack`) is present. Ground-truth classes are encoded in directory parent paths.

## Phase 7: Duplicate Row Analysis

- **Total Rows Inspected**: `46,776,700`
- **Within-File Duplicate Rows**: `13,711,895` (29.3135% duplicate rate)
- **Note**: No duplicate rows have been deleted or modified (READ-ONLY policy enforced).

## Phase 8: Potential Leakage & Structural Risks

### Class & Row Imbalance
- **Evidence**: File count ranges from 1 file (e.g., Backdoor_Malware, BrowserHijacking) to 29 files (Mirai-greeth_flood). Row counts range from ~3,218 rows to >2,000,000 rows across categories.
- **Assessment**: `POTENTIAL RISK (Requires sampling stratification to prevent model bias).`

### Directory / Filename Label Encoding
- **Evidence**: Target class names are encoded exclusively in folder and file paths (e.g. Benign_Final, DDoS-HTTP_Flood).
- **Assessment**: `ESTABLISHED (Loader must extract labels from parent directories, not feature vectors).`

### Constant / Low-Variance Feature Columns
- **Evidence**: 0 column(s) identified with potential low variance or constant values in samples: []
- **Assessment**: `POTENTIAL RISK (May cause zero-variance issues during scaling).`
