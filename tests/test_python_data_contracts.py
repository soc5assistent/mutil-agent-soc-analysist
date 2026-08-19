import math
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pydantic import ValidationError
from contracts import SecurityEvent, FeatureVector, AnomalyResult


def test_security_event_valid_instantiation_and_serialization():
    """Verifies SecurityEvent instantiates correctly and serializes all fields including flow stats."""
    event = SecurityEvent(
        event_id="123e4567-e89b-12d3-a456-426614174000",
        source_type="CICIoT2023",
        timestamp_utc="2026-08-19T22:00:00.000Z",
        is_synthetic_timestamp=True,
        ingest_timestamp_utc="2026-08-19T22:00:01.000Z",
        sensor_id="cic_loader_01",
        collector_version="v2.0.0",
        flow_rate=125.5,
        mean_iat_ms=45.2,
        proto_http_flag=1.0,
        proto_https_flag=0.0,
        proto_dns_flag=0.0,
        proto_telnet_flag=0.0,
        proto_smtp_flag=0.0,
        proto_ssh_flag=0.0,
        proto_irc_flag=0.0,
        proto_tcp_flag=1.0,
        proto_udp_flag=0.0,
        proto_dhcp_flag=0.0,
        proto_arp_flag=0.0,
        proto_icmp_flag=0.0,
        proto_igmp_flag=0.0,
        proto_ipv_flag=1.0,
        proto_llc_flag=0.0,
    )

    assert event.event_id == "123e4567-e89b-12d3-a456-426614174000"
    assert event.source_type == "CICIoT2023"
    assert event.is_synthetic_timestamp is True
    assert event.flow_rate == 125.5
    assert event.proto_http_flag == 1.0

    # Serialization test
    data_json = event.model_dump_json()
    assert "123e4567-e89b-12d3-a456-426614174000" in data_json
    assert "proto_http_flag" in data_json


def test_security_event_prohibited_custom_attributes_rejection():
    """Verifies that prohibited target/file metadata cannot be injected into custom_attributes."""
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(
            event_id="123e4567-e89b-12d3-a456-426614174000",
            source_type="TEST",
            timestamp_utc="2026-08-19T22:00:00.000Z",
            ingest_timestamp_utc="2026-08-19T22:00:01.000Z",
            sensor_id="test_sensor",
            collector_version="v2.0.0",
            custom_attributes={"attack_label": "DDoS-ICMP_Flood"},
        )
    assert "Prohibited metadata attribute 'attack_label'" in str(exc_info.value)


def test_feature_vector_nan_inf_rejection():
    """Verifies FeatureVector rejects NaN and Inf values in features array."""
    # Test NaN rejection
    with pytest.raises(ValidationError) as exc_nan:
        FeatureVector(
            vector_id="v-001",
            event_id="e-001",
            timestamp_utc="2026-08-19T22:00:00.000Z",
            features=[1.0, float("nan"), 3.0],
            feature_names=["f1", "f2", "f3"],
            feature_pipeline_version="v1.0",
            scaling_version="s1.0",
            model_compatibility_tag="IFOREST_27D_V1",
        )
    assert "non-finite numerical value" in str(exc_nan.value)

    # Test Inf rejection
    with pytest.raises(ValidationError) as exc_inf:
        FeatureVector(
            vector_id="v-002",
            event_id="e-002",
            timestamp_utc="2026-08-19T22:00:00.000Z",
            features=[1.0, float("inf"), 3.0],
            feature_names=["f1", "f2", "f3"],
            feature_pipeline_version="v1.0",
            scaling_version="s1.0",
            model_compatibility_tag="IFOREST_27D_V1",
        )
    assert "non-finite numerical value" in str(exc_inf.value)


def test_feature_vector_dimension_mismatch_rejection():
    """Verifies FeatureVector rejects dimension mismatch between feature_names and features."""
    with pytest.raises(ValidationError) as exc_dim:
        FeatureVector(
            vector_id="v-003",
            event_id="e-003",
            timestamp_utc="2026-08-19T22:00:00.000Z",
            features=[1.0, 2.0],
            feature_names=["f1", "f2", "f3"],
            feature_pipeline_version="v1.0",
            scaling_version="s1.0",
            model_compatibility_tag="IFOREST_27D_V1",
        )
    assert "does not match features length" in str(exc_dim.value)


def test_anomaly_result_optional_confidence():
    """Verifies AnomalyResult requires anomaly_score & is_anomaly and accepts calibrated_confidence=None."""
    res = AnomalyResult(
        result_id="res-001",
        vector_id="v-001",
        event_id="e-001",
        timestamp_utc="2026-08-19T22:00:00.000Z",
        is_anomaly=True,
        anomaly_score=-0.68,
        calibrated_confidence=None,
        model_id="IFOREST_CIC2023_V1",
        model_version="v1.0.0",
    )

    assert res.is_anomaly is True
    assert res.anomaly_score == -0.68
    assert res.calibrated_confidence is None
    assert res.calibration_method == "UNALIGNED_RAW"
