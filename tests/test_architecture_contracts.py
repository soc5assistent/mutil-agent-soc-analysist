"""Architecture contract & documentation validation tests.

Enforces strict separation of concerns, agent input/output schema definitions,
provenance non-leakage constraints, dataset boundary mappings, versioning separation,
and non-ownership declarations across all system documents.
"""

from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent


def test_required_architecture_documents_exist():
    """Verifies that all mandatory architecture contracts and design files exist in the repository."""
    required_files = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / ".gitignore",
        PROJECT_ROOT / "requirements.txt",
        PROJECT_ROOT / "docs" / "architecture" / "system_architecture.md",
        PROJECT_ROOT / "docs" / "contracts" / "security_event.md",
        PROJECT_ROOT / "docs" / "contracts" / "signature_evidence.md",
        PROJECT_ROOT / "docs" / "contracts" / "feature_vector.md",
        PROJECT_ROOT / "docs" / "contracts" / "anomaly_result.md",
        PROJECT_ROOT / "docs" / "contracts" / "final_threat_assessment.md",
        PROJECT_ROOT / "docs" / "datasets" / "ciciot2023_feature_mapping.md",
        PROJECT_ROOT / "docs" / "datasets" / "training_methodology.md",
        PROJECT_ROOT / "docs" / "agents" / "agent3_design.md",
        PROJECT_ROOT / "docs" / "agents" / "agent4_design.md",
        PROJECT_ROOT / "docs" / "datasets" / "ciciot2023_methodology.md",
    ]
    for path in required_files:
        assert path.exists(), f"Required architecture/contract file missing: {path}"


def test_system_architecture_defines_all_agent_inputs_outputs_and_boundaries():
    """Verifies system_architecture.md strictly documents all 5 agent contracts and critical architectural boundaries."""
    doc_path = PROJECT_ROOT / "docs" / "architecture" / "system_architecture.md"
    assert doc_path.exists(), "system_architecture.md missing"
    content = doc_path.read_text(encoding="utf-8")

    # Agent input/output contracts
    assert "Agent 1" in content and "SecurityEvent" in content, "Agent 1 output SecurityEvent not defined"
    assert "Agent 2" in content and "SignatureEvidence" in content, "Agent 2 output SignatureEvidence not defined"
    assert "Agent 3" in content and "FeatureVector" in content, "Agent 3 output FeatureVector not defined"
    assert "Agent 4" in content and "AnomalyResult" in content, "Agent 4 output AnomalyResult not defined"
    assert "Agent 5" in content and "FinalThreatAssessment" in content, "Agent 5 output FinalThreatAssessment not defined"

    # Critical architectural boundary rules
    assert "Agent 1 MUST NOT create the final ML" in content or "Agent 1 MUST NOT create" in content, (
        "Critical rule: Agent 1 must not create FeatureVector missing from system_architecture.md"
    )
    assert "Agent 2 MUST NOT perform anomaly detection" in content, (
        "Critical rule: Agent 2 must not perform anomaly detection missing from system_architecture.md"
    )
    assert "Agent 3" in content and "feature engineering" in content.lower(), "Agent 3 feature engineering ownership missing"
    assert "Agent 4" in content and "anomaly detection" in content.lower(), "Agent 4 anomaly detection ownership missing"

    # Non-ownership matrix check
    assert "Explicit Domain Non-Ownership Matrix" in content or "DOES NOT Own" in content, (
        "Non-ownership declarations missing from system_architecture.md"
    )


def test_security_event_contract_specifies_categories_and_provenance():
    """Verifies security_event.md explicitly details required field categories, field tables, and provenance types."""
    doc_path = PROJECT_ROOT / "docs" / "contracts" / "security_event.md"
    assert doc_path.exists(), "security_event.md missing"
    content = doc_path.read_text(encoding="utf-8")

    # Required field categories
    categories = ["Required", "Optional", "Endpoint", "Network", "Timestamp", "Provenance", "Raw Metadata"]
    for cat in categories:
        assert cat in content, f"SecurityEvent contract missing category: {cat}"

    # Required provenance types
    provenance_types = ["LIVE_ENDPOINT", "LIVE_NETWORK", "PCAP", "CICIoT2023", "SIMULATOR", "TEST"]
    for prov in provenance_types:
        assert prov in content, f"SecurityEvent contract missing provenance type: {prov}"

    # Non-leakage rule check
    assert "MUST NOT automatically become ML" in content or "MUST NOT automatically become ML numerical features" in content, (
        "SecurityEvent contract must state provenance fields MUST NOT automatically become ML features"
    )

    # Table column header check
    for col in ["Field Name", "Type", "Req/Opt", "Meaning", "Source", "Downstream Consumer"]:
        assert col in content, f"SecurityEvent contract table missing column: {col}"

    # Non-ownership section check
    assert "Agent 1 Non-Ownership Declarations" in content or "DOES NOT own" in content, (
        "SecurityEvent contract missing Agent 1 non-ownership section"
    )


def test_security_event_represents_flow_statistics_and_synthetic_timestamp_rules():
    """Verifies SecurityEvent represents flow statistics natively and documents synthetic timestamp rules."""
    doc_path = PROJECT_ROOT / "docs" / "contracts" / "security_event.md"
    assert doc_path.exists(), "security_event.md missing"
    content = doc_path.read_text(encoding="utf-8")

    # Flow stats fields
    flow_fields = ["flow_rate", "mean_iat_ms", "tot_size", "tot_sum", "min_packet_size", "max_packet_size", "avg_packet_size"]
    for field in flow_fields:
        assert field in content, f"SecurityEvent contract missing typed flow field: {field}"

    # Synthetic timestamp field and rule
    assert "is_synthetic_timestamp" in content, "SecurityEvent contract missing is_synthetic_timestamp field"
    assert "MUST NOT" in content and "synthetic" in content.lower(), "Synthetic timestamp feature restriction missing"

    # Custom attributes workaround prohibition
    assert "undocumented workaround" in content.lower() or "custom_attributes MUST NOT" in content, (
        "SecurityEvent contract must prohibit custom_attributes workaround"
    )


def test_feature_vector_contract_versioning_and_metadata_isolation():
    """Verifies feature_vector.md enforces separate feature_pipeline_version, scaling_version, and metadata exclusion."""
    doc_path = PROJECT_ROOT / "docs" / "contracts" / "feature_vector.md"
    assert doc_path.exists(), "feature_vector.md missing"
    content = doc_path.read_text(encoding="utf-8")

    assert "feature_pipeline_version" in content, "feature_pipeline_version missing from FeatureVector contract"
    assert "scaling_version" in content, "scaling_version missing from FeatureVector contract"
    assert "feature_names" in content, "feature_names missing from FeatureVector contract"

    # Prohibited metadata leak check
    prohibited = ["source_file", "category", "attack_label", "dataset_name", "folder_name"]
    for item in prohibited:
        assert item in content, f"FeatureVector contract must explicitly list prohibited metadata item: {item}"

    assert "MUST NOT" in content and "ML numerical features" in content or "converted into ML" in content, (
        "FeatureVector contract must state metadata MUST NOT become ML features"
    )


def test_anomaly_result_contract_optional_confidence():
    """Verifies anomaly_result.md requires anomaly_score and marks calibrated_confidence as optional until empirically calibrated."""
    doc_path = PROJECT_ROOT / "docs" / "contracts" / "anomaly_result.md"
    assert doc_path.exists(), "anomaly_result.md missing"
    content = doc_path.read_text(encoding="utf-8")

    assert "anomaly_score" in content and "Required" in content, "anomaly_score must be Required"
    assert "is_anomaly" in content and "Required" in content, "is_anomaly must be Required"
    assert "calibrated_confidence" in content and "Optional" in content, "calibrated_confidence must be Optional"
    assert "Sigmoid" in content or "sigmoid" in content, "Contract must reference arbitrary sigmoid prohibition"


def test_ciciot2023_feature_mapping_completeness():
    """Verifies ciciot2023_feature_mapping.md maps all 39 columns and specifies Dataset Adapter dataflow."""
    doc_path = PROJECT_ROOT / "docs" / "datasets" / "ciciot2023_feature_mapping.md"
    assert doc_path.exists(), "ciciot2023_feature_mapping.md missing"
    content = doc_path.read_text(encoding="utf-8")

    assert "Dataset Adapter" in content, "Feature mapping missing Dataset Adapter dataflow"
    assert "39" in content, "Feature mapping must reference 39 columns"
    assert "Header_Length" in content and "Protocol Type" in content and "Variance" in content, "Missing raw columns in mapping table"


def test_training_methodology_specifies_duplicate_and_split_rules():
    """Verifies training_methodology.md documents verified empirical stats and file-level splitting rules."""
    doc_path = PROJECT_ROOT / "docs" / "datasets" / "training_methodology.md"
    assert doc_path.exists(), "training_methodology.md missing"
    content = doc_path.read_text(encoding="utf-8")

    assert "46,776,700" in content, "Empirical row count missing"
    assert "13,711,895" in content, "Empirical duplicate count missing"
    assert "29.3135%" in content, "Empirical duplicate rate missing"
    assert "file level" in content.lower() or "file-level" in content.lower(), "File-level splitting requirement missing"
    assert "STRICTLY PROHIBITED" in content, "Row-level random splitting prohibition missing"


def test_gitignore_contains_dataset_and_cache_protections():
    """Verifies that .gitignore includes strict anti-leakage and dataset exclusion rules."""
    gitignore_path = PROJECT_ROOT / ".gitignore"
    assert gitignore_path.exists(), ".gitignore does not exist"

    content = gitignore_path.read_text(encoding="utf-8")
    assert "*.csv" in content, ".gitignore must exclude *.csv files"
    assert "*.pcap" in content, ".gitignore must exclude *.pcap files"
    assert "datasets/*" in content, ".gitignore must exclude datasets/* directory"
    assert "__pycache__/" in content, ".gitignore must exclude __pycache__"


def test_no_premature_agent_implementation():
    """Verifies that production Agent 3/4 logic has not been implemented prematurely before design review."""
    agent3_dir = PROJECT_ROOT / "agents" / "agent3_feature_engineering"
    agent4_dir = PROJECT_ROOT / "agents" / "agent4_anomaly_detection"

    py_files_agent3 = list(agent3_dir.glob("*.py"))
    py_files_agent4 = list(agent4_dir.glob("*.py"))

    assert len(py_files_agent3) == 0, f"Agent 3 implementation created prematurely: {py_files_agent3}"
    assert len(py_files_agent4) == 0, f"Agent 4 implementation created prematurely: {py_files_agent4}"
