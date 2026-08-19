"""SecurityEvent executable data contract."""

from typing import Dict, Optional, Any
from pydantic import BaseModel, Field, field_validator

PROHIBITED_METADATA_KEYS = {
    "dataset_name",
    "category",
    "attack_label",
    "source_file",
    "folder_name",
    "provenance",
    "collector_version",
    "test_metadata",
    "simulator_scenario",
}


class SecurityEvent(BaseModel):
    """Canonical SecurityEvent contract payload produced by Agent 1 or Dataset Adapters."""

    # Core Provenance & Timestamps
    event_id: str = Field(..., description="Unique event identifier (UUIDv4)")
    source_type: str = Field(
        ...,
        description="Origin environment (LIVE_ENDPOINT, LIVE_NETWORK, PCAP, CICIoT2023, SIMULATOR, TEST)",
    )
    timestamp_utc: str = Field(..., description="Event UTC observation timestamp")
    is_synthetic_timestamp: bool = Field(
        False, description="True if timestamp was synthetically assigned for offline benchmark flows"
    )
    ingest_timestamp_utc: str = Field(..., description="Pipeline ingestion UTC timestamp")
    sensor_id: str = Field(..., description="Identifier of collecting sensor or dataset loader")
    collector_version: str = Field(..., description="Ingestion engine software version tag")

    # Network Header Fields (Optional)
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source transport port number")
    dst_port: Optional[int] = Field(None, description="Destination transport port number")
    protocol: Optional[str] = Field(None, description="Upper-layer protocol name (TCP, UDP, ICMP)")
    protocol_type_code: Optional[int] = Field(None, description="Numeric IANA protocol identifier")
    time_to_live: Optional[float] = Field(None, description="IP Time-To-Live value")
    header_length: Optional[float] = Field(None, description="Total header length in bytes")

    # Typed Flow Statistics (Option A Architecture Extension)
    flow_rate: Optional[float] = Field(None, description="Flow transmission rate")
    srate: Optional[float] = Field(None, description="Source-to-destination transmission rate")
    drate: Optional[float] = Field(None, description="Destination-to-source transmission rate")
    mean_iat_ms: Optional[float] = Field(None, description="Mean inter-arrival time in milliseconds")
    tot_size: Optional[float] = Field(None, description="Total payload size in flow bytes")
    tot_sum: Optional[float] = Field(None, description="Total byte sum across flow packets")
    min_packet_size: Optional[float] = Field(None, description="Minimum packet size in flow bytes")
    max_packet_size: Optional[float] = Field(None, description="Maximum packet size in flow bytes")
    avg_packet_size: Optional[float] = Field(None, description="Average packet size in flow bytes")
    std_packet_size: Optional[float] = Field(None, description="Standard deviation of packet size")
    variance_packet_size: Optional[float] = Field(None, description="Variance of packet size in flow")
    packet_count: Optional[float] = Field(None, description="Total packet count in flow")

    # TCP Flag Counts (7 Fields)
    tcp_fin_count: Optional[float] = Field(None, description="TCP FIN flag count")
    tcp_syn_count: Optional[float] = Field(None, description="TCP SYN flag count")
    tcp_rst_count: Optional[float] = Field(None, description="TCP RST flag count")
    tcp_psh_count: Optional[float] = Field(None, description="TCP PSH flag count")
    tcp_ack_count: Optional[float] = Field(None, description="TCP ACK flag count")
    tcp_ece_count: Optional[float] = Field(None, description="TCP ECE flag count")
    tcp_cwr_count: Optional[float] = Field(None, description="TCP CWR flag count")

    # 15 Protocol Indicator Flags
    proto_http_flag: Optional[float] = Field(None, description="HTTP protocol flag")
    proto_https_flag: Optional[float] = Field(None, description="HTTPS protocol flag")
    proto_dns_flag: Optional[float] = Field(None, description="DNS protocol flag")
    proto_telnet_flag: Optional[float] = Field(None, description="Telnet protocol flag")
    proto_smtp_flag: Optional[float] = Field(None, description="SMTP protocol flag")
    proto_ssh_flag: Optional[float] = Field(None, description="SSH protocol flag")
    proto_irc_flag: Optional[float] = Field(None, description="IRC protocol flag")
    proto_tcp_flag: Optional[float] = Field(None, description="TCP protocol flag")
    proto_udp_flag: Optional[float] = Field(None, description="UDP protocol flag")
    proto_dhcp_flag: Optional[float] = Field(None, description="DHCP protocol flag")
    proto_arp_flag: Optional[float] = Field(None, description="ARP protocol flag")
    proto_icmp_flag: Optional[float] = Field(None, description="ICMP protocol flag")
    proto_igmp_flag: Optional[float] = Field(None, description="IGMP protocol flag")
    proto_ipv_flag: Optional[float] = Field(None, description="IPv protocol flag")
    proto_llc_flag: Optional[float] = Field(None, description="LLC protocol flag")

    # Endpoint Fields & Metadata
    host_name: Optional[str] = Field(None, description="Hostname of executing endpoint")
    process_name: Optional[str] = Field(None, description="Executing binary process name")
    command_line: Optional[str] = Field(None, description="Process command line arguments")
    raw_payload_b64: Optional[str] = Field(None, description="Base64 encoded raw payload")
    custom_attributes: Dict[str, Any] = Field(
        default_factory=dict, description="Unmapped operational key-value metadata"
    )

    @field_validator("custom_attributes")
    @classmethod
    def validate_custom_attributes_non_leakage(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Enforces that target labels, dataset metadata, or file paths cannot leak into custom_attributes."""
        for key in v.keys():
            if key.lower() in PROHIBITED_METADATA_KEYS:
                raise ValueError(
                    f"Prohibited metadata attribute '{key}' cannot be transported in custom_attributes"
                )
        return v
