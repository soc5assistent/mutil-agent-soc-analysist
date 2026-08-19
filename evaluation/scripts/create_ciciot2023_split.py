"""Deterministic CICIoT2023 file-level category-stratified dataset partitioning script."""

import json
import random
import hashlib
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(r"d:\b tech\feature_eng+\datasets\cic_iot_2023\raw")
OUTPUT_PATH = Path(r"d:\b tech\feature_eng+\evaluation\datasets\ciciot2023_split_manifest.json")
RANDOM_SEED = 42
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15


def generate_ciciot2023_split_manifest():
    """Discovers all 309 raw CSV files, performs category-stratified file-level splitting, and exports JSON manifest."""
    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Raw dataset directory not found: {DATA_DIR}")

    csv_files = sorted(list(DATA_DIR.rglob("*.csv")))
    total_files = len(csv_files)
    print(f"[SPLIT] Discovered {total_files} CSV files in {DATA_DIR}")

    # Group relative file paths by top-level category folder
    category_map = defaultdict(list)
    for path in csv_files:
        rel_path = str(path.relative_to(DATA_DIR)).replace("\\", "/")
        category = path.parent.name
        category_map[category].append(rel_path)

    # Sort categories and filenames deterministically
    sorted_categories = sorted(category_map.keys())

    train_files = []
    val_files = []
    test_files = []

    single_file_categories = []

    # Deterministic RNG initialization
    rng = random.Random(RANDOM_SEED)

    for cat in sorted_categories:
        cat_files = sorted(category_map[cat])
        cat_file_count = len(cat_files)

        # Shuffle deterministically per category
        shuffled = list(cat_files)
        rng.shuffle(shuffled)

        if cat_file_count == 1:
            # Single-file category strategy: assign to train set for base representation
            single_file_categories.append(cat)
            train_files.append(shuffled[0])
        elif cat_file_count == 2:
            train_files.append(shuffled[0])
            test_files.append(shuffled[1])
        elif cat_file_count == 3:
            train_files.append(shuffled[0])
            val_files.append(shuffled[1])
            test_files.append(shuffled[2])
        else:
            # Multi-file categories (>= 4 files)
            n_val = max(1, int(round(cat_file_count * VAL_RATIO)))
            n_test = max(1, int(round(cat_file_count * TEST_RATIO)))
            n_train = cat_file_count - n_val - n_test

            train_files.extend(shuffled[:n_train])
            val_files.extend(shuffled[n_train : n_train + n_val])
            test_files.extend(shuffled[n_train + n_val :])

    # Sort output lists for deterministic JSON output
    train_files = sorted(train_files)
    val_files = sorted(val_files)
    test_files = sorted(test_files)

    manifest_data = {
        "metadata": {
            "dataset": "CICIoT2023",
            "raw_directory": str(DATA_DIR),
            "random_seed": RANDOM_SEED,
            "total_csv_files": total_files,
            "train_file_count": len(train_files),
            "validation_file_count": len(val_files),
            "test_file_count": len(test_files),
            "total_categories": len(sorted_categories),
            "single_file_categories": sorted(single_file_categories),
            "split_ratios": {
                "target_train_ratio": TRAIN_RATIO,
                "target_val_ratio": VAL_RATIO,
                "target_test_ratio": TEST_RATIO,
                "actual_train_pct": round(len(train_files) / total_files * 100.0, 2),
                "actual_val_pct": round(len(val_files) / total_files * 100.0, 2),
                "actual_test_pct": round(len(test_files) / total_files * 100.0, 2),
            },
            "strategy_rationale": (
                "File-level category-stratified partition. Single-file categories assigned to train set "
                "to ensure all 34 traffic classes are represented during scaler fitting. Multi-file categories "
                "split ~70/15/15 across train/val/test partitions without splitting individual CSV rows."
            ),
        },
        "splits": {
            "train": train_files,
            "validation": val_files,
            "test": test_files,
        },
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    json_bytes = json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8")

    with open(OUTPUT_PATH, "wb") as f:
        f.write(json_bytes)

    sha256_hash = hashlib.sha256(json_bytes).hexdigest()
    print(f"[SPLIT] Manifest written: {OUTPUT_PATH}")
    print(f"[SPLIT] SHA256 Checksum : {sha256_hash}")
    print(f"[SPLIT] Counts          : Train={len(train_files)}, Val={len(val_files)}, Test={len(test_files)}")

    return sha256_hash


if __name__ == "__main__":
    generate_ciciot2023_split_manifest()
