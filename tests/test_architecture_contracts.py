"""Architecture contract & documentation validation tests."""

from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent


def test_required_architecture_documents_exist():
    """Verifies that all mandatory architecture and design specification files exist."""
    required_files = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / ".gitignore",
        PROJECT_ROOT / "requirements.txt",
        PROJECT_ROOT / "datasets" / "README.md",
        PROJECT_ROOT / "agents" / "agent3_feature_engineering" / "README.md",
        PROJECT_ROOT / "agents" / "agent4_anomaly_detection" / "README.md",
        PROJECT_ROOT / "docs" / "architecture" / "system_architecture.md",
        PROJECT_ROOT / "docs" / "agents" / "agent3_design.md",
        PROJECT_ROOT / "docs" / "agents" / "agent4_design.md",
        PROJECT_ROOT / "docs" / "datasets" / "ciciot2023_methodology.md",
    ]
    for path in required_files:
        assert path.exists(), f"Required architecture file missing: {path}"


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
    
    # Python source files inside agent dirs (excluding README.md)
    py_files_agent3 = list(agent3_dir.glob("*.py"))
    py_files_agent4 = list(agent4_dir.glob("*.py"))
    
    assert len(py_files_agent3) == 0, f"Agent 3 implementation created prematurely: {py_files_agent3}"
    assert len(py_files_agent4) == 0, f"Agent 4 implementation created prematurely: {py_files_agent4}"
