"""Unit tests for CICIoT2023 frozen dataset split manifest."""

import json
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
MANIFEST_PATH = PROJECT_ROOT / "evaluation" / "datasets" / "ciciot2023_split_manifest.json"
DATA_DIR = PROJECT_ROOT / "datasets" / "cic_iot_2023" / "raw"


def test_split_manifest_exists_and_valid():
    """Verifies that the frozen split manifest file exists and contains metadata."""
    assert MANIFEST_PATH.exists(), f"Split manifest missing: {MANIFEST_PATH}"
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert "metadata" in data
    assert "splits" in data
    assert data["metadata"]["total_csv_files"] == 309
    assert data["metadata"]["random_seed"] == 42


def test_split_manifest_mutually_exclusive_and_complete():
    """Verifies train, validation, and test sets are mutually exclusive and cover all 309 files."""
    assert MANIFEST_PATH.exists(), "Manifest missing"
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    train = set(data["splits"]["train"])
    val = set(data["splits"]["validation"])
    test = set(data["splits"]["test"])

    # Disjointness checks
    assert train.isdisjoint(val), f"Train and Validation overlap: {train & val}"
    assert train.isdisjoint(test), f"Train and Test overlap: {train & test}"
    assert val.isdisjoint(test), f"Validation and Test overlap: {val & test}"

    total_manifest_count = len(data["splits"]["train"]) + len(data["splits"]["validation"]) + len(data["splits"]["test"])
    assert total_manifest_count == 309, f"Expected 309 total files, found {total_manifest_count}"

    # Verify every file on disk appears exactly once
    if DATA_DIR.exists():
        disk_files = {str(p.relative_to(DATA_DIR)).replace("\\", "/") for p in DATA_DIR.rglob("*.csv")}
        all_manifest_files = train | val | test

        assert disk_files == all_manifest_files, f"Mismatch between disk files and manifest files: {disk_files ^ all_manifest_files}"
