"""
Extended CICIoT2023 duplicate audit - all 309 files. Final memory correction.

Change from the prior revision:
  - Buckets A, B, D, E only ever needed distinct-hash COUNT, occurrence
    count, and files/categories involved for reporting - never the actual
    hash strings. They now track an integer distinct_count instead of a
    growing Python list of hash values.
  - Bucket C is different: resolve_benign_attack_detail() genuinely needs
    the hash values to find matching rows in the targeted second scan. Those
    hashes are now written to a small disk file as they're discovered during
    the merge (already naturally sorted, since groups are visited in sorted
    order), not accumulated in an in-memory list. The targeted scan then
    chooses its strategy based on how many hashes are actually there:
      - if the count is small enough to comfortably fit in memory as a
        Python set (C_HASH_SET_THRESHOLD, default 1,000,000 - about 74MB
        of hash strings), load it and do the simple set-membership scan.
      - otherwise, do a genuine streaming merge-join: for each file being
        re-scanned, sort that file's own (hash, row_idx) pairs (bounded by
        that one file's size, same as the general per-file memory model
        documented below), then walk it in lockstep against the sorted
        C-hash file read from disk, without ever loading the whole C-hash
        file into memory.

HONEST MEMORY CHARACTERIZATION (corrected wording - read this instead of
assuming a single blanket bound):
  - The EXTERNAL SORT of row-hash-location records (per-file chunking +
    merge, and the global merge across all 309 per-file chunk files) is
    bounded by HASH_CHUNK_SIZE and the number of open files during merging
    - this part does NOT scale with dataset size.
  - The PANDAS PER-FILE PROCESSING (loading a CSV into a DataFrame,
    computing pandas duplicated() stats, computing row-content strings for
    hashing) is proportional to the size of whichever single source CSV is
    currently being processed, not to the whole dataset. Based on observed
    category sizes this is expected to stay in the low single-digit-GB
    range at most, but it is NOT bounded by HASH_CHUNK_SIZE - that constant
    only governs the external-sort chunking, not the pandas read itself.
  - Bucket A/B/D/E memory is O(1) per bucket (a handful of integers plus
    small sets bounded by <=309 files / <=34 categories / <=3 partitions).
  - Bucket C memory is bounded by C_HASH_SET_THRESHOLD in the common case,
    or by one file's row count at a time in the streaming fallback.

Run directly:
    python audit_ciciot2023_full.py
"""

from __future__ import annotations

import csv
import hashlib
import heapq
import itertools
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_DIR = Path("datasets/cic_iot_2023/raw")
MANIFEST_PATH = Path("evaluation/datasets/ciciot2023_split_manifest.json")

EXPECTED_FILE_COUNT = 309
EXPECTED_COLUMN_COUNT = 39
EXPECTED_TOTAL_ROWS = 46_776_700

BACKDOOR_RELPATH = "Backdoor_Malware/Backdoor_Malware.pcap.csv"
BACKDOOR_EXPECTED = {
    "total_rows": 3218,
    "unique_rows": 3215,
    "dup_first": 3,
    "dup_all": 6,
}

VALID_PARTITIONS = {"train", "validation", "test"}

HASH_CHUNK_SIZE = 250_000   # bound on any single in-memory sort during per-file chunking
MAX_GROUP_DETAIL = 500_000  # informational threshold only - no data is ever dropped
C_HASH_SET_THRESHOLD = 1_000_000  # above this, use streaming merge-join instead of a Python set


def fail(message: str) -> None:
    print(f"\nFAIL: {message}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Discovery + hard-fail schema checks
# ---------------------------------------------------------------------------
def discover_files() -> list[Path]:
    files = sorted(DATA_DIR.rglob("*.csv"))
    print(f"Discovered {len(files)} CSV files under {DATA_DIR}")
    if len(files) != EXPECTED_FILE_COUNT:
        fail(f"expected {EXPECTED_FILE_COUNT} files, found {len(files)}")
    return files


def category_of(path: Path) -> str:
    return path.relative_to(DATA_DIR).parts[0]


def check_column_counts(files: list[Path]) -> None:
    print("\n=== Column count check (header only) ===")
    bad = []
    for path in files:
        with open(path, "r", newline="") as fh:
            header = next(csv.reader(fh))
        if len(header) != EXPECTED_COLUMN_COUNT:
            bad.append((path, len(header)))
    if bad:
        for path, n in bad:
            print(f"  {path}: {n} columns")
        fail(f"{len(bad)} file(s) do not have {EXPECTED_COLUMN_COUNT} columns")
    print(f"All {len(files)} files have exactly {EXPECTED_COLUMN_COUNT} columns.")


# ---------------------------------------------------------------------------
# Manifest loading + hard-fail validation (unchanged)
# ---------------------------------------------------------------------------
def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        fail(f"manifest not found at {MANIFEST_PATH}")
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def validate_manifest(files: list[Path], manifest: dict) -> dict[str, str]:
    print(f"\n=== Manifest validation: {MANIFEST_PATH} ===")

    splits = manifest.get("splits", {})
    unexpected_keys = set(splits.keys()) - VALID_PARTITIONS
    if unexpected_keys:
        fail(f"manifest has unexpected partition key(s): {unexpected_keys}")

    discovered_relpaths = {str(p.relative_to(DATA_DIR)).replace("\\", "/") for p in files}

    file_to_partition: dict[str, str] = {}
    seen_in_multiple: dict[str, list[str]] = defaultdict(list)
    nonexistent: list[tuple[str, str]] = []

    for partition in VALID_PARTITIONS:
        entries = splits.get(partition, [])
        print(f"  {partition}: {len(entries)} entries")
        for rel_path in entries:
            rel_path = rel_path.replace("\\", "/")
            if rel_path not in discovered_relpaths:
                nonexistent.append((partition, rel_path))
            if rel_path in file_to_partition:
                seen_in_multiple[rel_path].append(file_to_partition[rel_path])
                seen_in_multiple[rel_path].append(partition)
            else:
                file_to_partition[rel_path] = partition

    if nonexistent:
        for partition, rel_path in nonexistent:
            print(f"  manifest entry not found on disk: [{partition}] {rel_path}")
        fail(f"{len(nonexistent)} manifest entr(y/ies) point to nonexistent files")

    if seen_in_multiple:
        for rel_path, partitions in seen_in_multiple.items():
            print(f"  {rel_path} appears in multiple partitions: {sorted(set(partitions))}")
        fail(f"{len(seen_in_multiple)} file(s) appear in more than one partition")

    missing_from_manifest = discovered_relpaths - set(file_to_partition.keys())
    if missing_from_manifest:
        for rel_path in sorted(missing_from_manifest):
            print(f"  file on disk but missing from manifest: {rel_path}")
        fail(f"{len(missing_from_manifest)} discovered file(s) are missing from the manifest")

    print("Manifest validation passed: partitions are valid, disjoint, and complete.")
    return file_to_partition


# ---------------------------------------------------------------------------
# Phase 1: dtype inspection (unchanged)
# ---------------------------------------------------------------------------
def inspect_dtypes(files: list[Path]) -> dict[str, Counter]:
    print("\n=== PHASE 1: dtype inspection (reading all files once) ===")
    column_dtypes: dict[str, Counter] = defaultdict(Counter)
    for i, path in enumerate(files, 1):
        df = pd.read_csv(path)
        for col in df.columns:
            column_dtypes[col][str(df[col].dtype)] += 1
        if i % 25 == 0 or i == len(files):
            print(f"  dtype-scanned {i}/{len(files)} files")
        del df
    print("\nPer-column dtype report:")
    inconsistent = []
    for col, counter in column_dtypes.items():
        seen = dict(counter)
        flag = ""
        if len(seen) > 1:
            flag = "  <-- INCONSISTENT ACROSS FILES"
            inconsistent.append(col)
        print(f"  {col:25s} {seen}{flag}")
    print(f"\n{len(inconsistent)} inconsistent column(s): {inconsistent}" if inconsistent
          else "\nAll columns consistent across all files.")
    return column_dtypes


def determine_canonical_dtypes(column_dtypes: dict[str, Counter]) -> dict[str, str]:
    print("\n=== Canonical dtype decisions ===")
    canonical: dict[str, str] = {}
    for col, counter in column_dtypes.items():
        seen = set(counter.keys())
        if len(seen) == 1:
            chosen, reason = next(iter(seen)), "consistent across all files"
        else:
            chosen, reason = "float64", f"inconsistent ({seen}) -> upcast to float64"
        canonical[col] = chosen
        print(f"  {col:25s} -> {chosen:10s} ({reason})")
    return canonical


# ---------------------------------------------------------------------------
# Row hashing helpers (unchanged definition)
# ---------------------------------------------------------------------------
def row_content_strings(df: pd.DataFrame) -> pd.Series:
    as_str = df.astype(str)
    combined = as_str[as_str.columns[0]]
    for col in as_str.columns[1:]:
        combined = combined.str.cat(as_str[col], sep="|")
    return combined


def sha256_of_series(strings: pd.Series) -> list[str]:
    return [hashlib.sha256(s.encode("utf-8")).hexdigest() for s in strings]


def hash_key(line: str) -> str:
    return line.split("\t", 1)[0]


def parse_line(line: str) -> tuple[str, str, str, str, int]:
    h, rel_path, category, partition, row_idx = line.rstrip("\n").split("\t")
    return h, rel_path, category, partition, int(row_idx)


# ---------------------------------------------------------------------------
# Phase 2a: per-file processing -> bounded chunked sort -> per-file merge
# (unchanged from the prior revision)
# ---------------------------------------------------------------------------
def write_run(run_path: Path, records: list[tuple]) -> None:
    records.sort()
    with open(run_path, "w") as f:
        for h, rp, cat, part, row_idx in records:
            f.write(f"{h}\t{rp}\t{cat}\t{part}\t{row_idx}\n")


def merge_runs_to_file(run_paths: list[Path], output_path: Path) -> None:
    handles = [open(p, "r") for p in run_paths]
    try:
        with open(output_path, "w") as out:
            for line in heapq.merge(*handles, key=hash_key):
                out.write(line)
    finally:
        for h in handles:
            h.close()
    for p in run_paths:
        p.unlink()


def process_files_to_chunks(
    files: list[Path],
    canonical_dtypes: dict[str, str],
    file_to_partition: dict[str, str],
    chunk_dir: Path,
) -> tuple[list[Path], int]:
    print("\n=== PHASE 2a: per-file duplicate stats + bounded chunked sort ===")
    print("(NOTE: this step's pandas memory use is proportional to the largest")
    print(" single source CSV, not bounded by HASH_CHUNK_SIZE - see module docstring)")
    chunk_paths: list[Path] = []
    total_rows_processed = 0
    backdoor_checked = False

    for i, path in enumerate(files, 1):
        rel_path = str(path.relative_to(DATA_DIR)).replace("\\", "/")
        category = category_of(path)
        partition = file_to_partition[rel_path]

        df = pd.read_csv(path)
        for col in df.columns:
            target = canonical_dtypes.get(col)
            if target and str(df[col].dtype) != target:
                df[col] = df[col].astype(target)

        total_rows = len(df)
        dup_first_count = int(df.duplicated(keep="first").sum())
        dup_all_count = int(df.duplicated(keep=False).sum())
        unique_count = total_rows - dup_first_count

        content_strings = row_content_strings(df)
        hashes = sha256_of_series(content_strings)
        hash_series = pd.Series(hashes, index=df.index)
        hash_dup_all_count = int(hash_series.duplicated(keep=False).sum())

        if hash_dup_all_count != dup_all_count:
            fail(
                f"pandas/SHA-256 mismatch in {rel_path}: "
                f"pandas={dup_all_count} sha256={hash_dup_all_count}"
            )

        if rel_path == BACKDOOR_RELPATH:
            actual = {
                "total_rows": total_rows,
                "unique_rows": unique_count,
                "dup_first": dup_first_count,
                "dup_all": dup_all_count,
            }
            if actual != BACKDOOR_EXPECTED:
                fail(f"Backdoor_Malware mismatch. Expected {BACKDOOR_EXPECTED}, got {actual}")
            backdoor_checked = True
            print(f"  [{i}/{len(files)}] {rel_path}: Backdoor sanity check PASSED ({actual})")

        dup_rate = 100 * dup_first_count / total_rows if total_rows else 0.0
        print(
            f"  [{i}/{len(files)}] {rel_path}: rows={total_rows} unique={unique_count} "
            f"dup_first={dup_first_count} dup_all={dup_all_count} rate={dup_rate:.4f}% "
            f"category={category} partition={partition}"
        )

        run_paths: list[Path] = []
        n_chunks = (total_rows + HASH_CHUNK_SIZE - 1) // HASH_CHUNK_SIZE if total_rows else 0
        for chunk_idx, start in enumerate(range(0, total_rows, HASH_CHUNK_SIZE)):
            end = min(start + HASH_CHUNK_SIZE, total_rows)
            records = [(hashes[j], rel_path, category, partition, j) for j in range(start, end)]
            run_path = chunk_dir / f"file{i:04d}_run{chunk_idx:03d}.tsv"
            write_run(run_path, records)
            run_paths.append(run_path)
            del records
        if n_chunks > 1:
            print(f"      ({n_chunks} chunks of <={HASH_CHUNK_SIZE} rows written for this file)")

        final_chunk_path = chunk_dir / f"chunk_{i:04d}.tsv"
        merge_runs_to_file(run_paths, final_chunk_path)
        chunk_paths.append(final_chunk_path)

        total_rows_processed += total_rows
        del df, content_strings, hashes, hash_series

    if not backdoor_checked:
        fail("Backdoor_Malware.pcap.csv was never processed - cannot confirm ground truth")

    return chunk_paths, total_rows_processed


# ---------------------------------------------------------------------------
# Phase 2b: external merge, streaming aggregation.
# A/B/D/E: integer counters only. C: hashes written to disk, not retained.
# ---------------------------------------------------------------------------
def merge_and_classify(chunk_paths: list[Path], chunk_dir: Path) -> tuple[dict, Path]:
    print("\n=== PHASE 2b: external merge + streaming overlap classification ===")

    def new_counter_bucket() -> dict:
        return {"distinct_count": 0, "occurrences": 0, "files": set(), "categories": set()}

    buckets = {
        "A_benign_train_val": new_counter_bucket(),
        "B_benign_train_test": new_counter_bucket(),
        "D_attack_val_test": new_counter_bucket(),
        "E_attack_cross_category": new_counter_bucket(),
    }
    # C is special: needs actual hash values later, written to disk instead of a list
    c_bucket = {"distinct_count": 0, "occurrences": 0, "files": set(), "categories": set()}
    c_hash_path = chunk_dir / "c_benign_attack_hashes.txt"

    open_files = [open(p, "r") for p in chunk_paths]
    c_hash_file = open(c_hash_path, "w")
    try:
        merged = heapq.merge(*open_files, key=hash_key)
        groups_processed = 0
        large_groups = 0

        for h, group_lines in itertools.groupby(merged, key=hash_key):
            count = 0
            categories: set[str] = set()
            partitions: set[str] = set()
            files_involved: set[str] = set()
            for line in group_lines:
                count += 1
                _, rel_path, category, partition, _row_idx = parse_line(line)
                categories.add(category)
                partitions.add(partition)
                files_involved.add(rel_path)

            groups_processed += 1
            if count > MAX_GROUP_DETAIL:
                large_groups += 1  # informational only - nothing above was dropped

            is_benign_only = categories == {"Benign_Final"}
            has_benign = "Benign_Final" in categories
            has_attack = any(c != "Benign_Final" for c in categories)
            attack_cats = categories - {"Benign_Final"}

            if is_benign_only and "train" in partitions and "validation" in partitions:
                b = buckets["A_benign_train_val"]
                b["distinct_count"] += 1; b["occurrences"] += count
                b["files"] |= files_involved; b["categories"] |= categories
            if is_benign_only and "train" in partitions and "test" in partitions:
                b = buckets["B_benign_train_test"]
                b["distinct_count"] += 1; b["occurrences"] += count
                b["files"] |= files_involved; b["categories"] |= categories
            if has_benign and has_attack:
                c_bucket["distinct_count"] += 1; c_bucket["occurrences"] += count
                c_bucket["files"] |= files_involved; c_bucket["categories"] |= categories
                c_hash_file.write(h + "\n")  # written, not retained in memory
            if not has_benign and "validation" in partitions and "test" in partitions:
                b = buckets["D_attack_val_test"]
                b["distinct_count"] += 1; b["occurrences"] += count
                b["files"] |= files_involved; b["categories"] |= categories
            if len(attack_cats) > 1:
                b = buckets["E_attack_cross_category"]
                b["distinct_count"] += 1; b["occurrences"] += count
                b["files"] |= files_involved; b["categories"] |= categories

        print(f"Processed {groups_processed} distinct hash groups.")
        if large_groups:
            print(f"NOTE: {large_groups} group(s) exceeded MAX_GROUP_DETAIL "
                  f"({MAX_GROUP_DETAIL}) occurrences. Informational only - "
                  f"counts/categories/partitions/files remain exact for these groups.")
    finally:
        for f in open_files:
            f.close()
        c_hash_file.close()

    buckets["C_benign_attack"] = c_bucket
    return buckets, c_hash_path


def report_bucket(title: str, bucket: dict) -> None:
    print(f"\n--- {title} ---")
    print(f"Distinct hashes involved: {bucket['distinct_count']}")
    print(f"Total row occurrences: {bucket['occurrences']}")
    if not bucket["distinct_count"]:
        print("(none)")
        return
    files = sorted(bucket["files"])
    print(f"Files involved ({len(files)}): {files[:20]}{' ...' if len(files) > 20 else ''}")
    print(f"Categories involved ({len(bucket['categories'])}): {sorted(bucket['categories'])}")


def report_c_hash_file(c_hash_path: Path, distinct_count: int) -> None:
    size_bytes = c_hash_path.stat().st_size if c_hash_path.exists() else 0
    print(f"\n--- C hash file (disk-backed, not held in memory) ---")
    print(f"Number of C hashes: {distinct_count}")
    print(f"Temporary C-hash file path: {c_hash_path}")
    print(f"Disk size: {size_bytes} bytes ({size_bytes / 1024:.2f} KB)")


# ---------------------------------------------------------------------------
# Targeted second scan: exact row-level detail for benign<->attack matches.
# Chooses a strategy based on how many C hashes there actually are.
# ---------------------------------------------------------------------------
def load_small_hash_set(c_hash_path: Path) -> set[str]:
    with open(c_hash_path, "r") as f:
        return {line.rstrip("\n") for line in f}


def print_match(rel_path: str, category: str, partition: str | None, row_idx: int, row: pd.Series, h: str) -> None:
    print(f"\nHash {h[:16]}...")
    print(f"  file: {rel_path}  category: {category}  partition: {partition}  "
          f"row_index: {row_idx}  physical_line: {row_idx + 2}")
    print(f"  row content: {row.to_dict()}")


def resolve_via_in_memory_set(
    c_hash_path: Path,
    canonical_dtypes: dict[str, str],
    file_to_partition: dict[str, str],
) -> None:
    print(f"C hash count is small enough ({C_HASH_SET_THRESHOLD:,} threshold) - using an in-memory set.")
    target_set = load_small_hash_set(c_hash_path)

    for path in sorted(DATA_DIR.rglob("*.csv")):
        rel_path = str(path.relative_to(DATA_DIR)).replace("\\", "/")
        category = category_of(path)

        df = pd.read_csv(path)
        for col in df.columns:
            target = canonical_dtypes.get(col)
            if target and str(df[col].dtype) != target:
                df[col] = df[col].astype(target)

        content_strings = row_content_strings(df)
        hashes = sha256_of_series(content_strings)

        for row_idx, h in enumerate(hashes):
            if h in target_set:
                print_match(rel_path, category, file_to_partition.get(rel_path), row_idx, df.iloc[row_idx], h)
        del df, content_strings, hashes


def resolve_via_streaming_merge_join(
    c_hash_path: Path,
    canonical_dtypes: dict[str, str],
    file_to_partition: dict[str, str],
) -> None:
    print(f"C hash count exceeds {C_HASH_SET_THRESHOLD:,} - using streaming merge-join "
          f"(the C-hash file is never fully loaded into memory).")

    for path in sorted(DATA_DIR.rglob("*.csv")):
        rel_path = str(path.relative_to(DATA_DIR)).replace("\\", "/")
        category = category_of(path)

        df = pd.read_csv(path)
        for col in df.columns:
            target = canonical_dtypes.get(col)
            if target and str(df[col].dtype) != target:
                df[col] = df[col].astype(target)

        content_strings = row_content_strings(df)
        hashes = sha256_of_series(content_strings)
        # bounded by THIS file's row count, same as the general per-file
        # memory model - not by the size of the C-hash file
        file_pairs = sorted(zip(hashes, range(len(hashes))))
        del content_strings, hashes

        with open(c_hash_path, "r") as c_f:
            c_iter = (line.rstrip("\n") for line in c_f)
            current_c = next(c_iter, None)
            i = 0
            n = len(file_pairs)
            while i < n and current_c is not None:
                h, row_idx = file_pairs[i]
                if h == current_c:
                    print_match(rel_path, category, file_to_partition.get(rel_path), row_idx, df.iloc[row_idx], h)
                    i += 1
                elif h < current_c:
                    i += 1
                else:
                    current_c = next(c_iter, None)
        del df, file_pairs


def resolve_benign_attack_detail(
    c_hash_path: Path,
    distinct_count: int,
    canonical_dtypes: dict[str, str],
    file_to_partition: dict[str, str],
) -> None:
    print("\n=== C. BENIGN <-> ATTACK: row-level detail (targeted re-scan) ===")
    if distinct_count == 0:
        print("No benign<->attack hash overlaps found. Nothing to resolve.")
        return

    if distinct_count <= C_HASH_SET_THRESHOLD:
        resolve_via_in_memory_set(c_hash_path, canonical_dtypes, file_to_partition)
    else:
        resolve_via_streaming_merge_join(c_hash_path, canonical_dtypes, file_to_partition)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    start_time = datetime.now(timezone.utc).isoformat()
    print("=== PROVENANCE ===")
    print(f"Script path: {Path(__file__).resolve()}")
    print(f"Dataset path: {DATA_DIR.resolve()}")
    print(f"Manifest path: {MANIFEST_PATH.resolve()}")
    print(f"Start time (UTC): {start_time}")

    files = discover_files()
    check_column_counts(files)

    manifest = load_manifest()
    file_to_partition = validate_manifest(files, manifest)

    column_dtypes = inspect_dtypes(files)
    canonical_dtypes = determine_canonical_dtypes(column_dtypes)

    chunk_dir = Path(tempfile.mkdtemp(prefix="ciciot_audit_chunks_"))
    print(f"\nChunk directory (not auto-deleted): {chunk_dir}")

    chunk_paths, total_rows = process_files_to_chunks(
        files, canonical_dtypes, file_to_partition, chunk_dir
    )

    print("\n=== TOTALS ===")
    print(f"Files processed: {len(files)}  (expected {EXPECTED_FILE_COUNT})")
    print(f"Total rows processed: {total_rows}  (expected {EXPECTED_TOTAL_ROWS})")
    if total_rows != EXPECTED_TOTAL_ROWS:
        fail("total row count does not match the previously verified figure")

    buckets, c_hash_path = merge_and_classify(chunk_paths, chunk_dir)

    report_bucket("A. BENIGN TRAIN <-> BENIGN VALIDATION", buckets["A_benign_train_val"])
    report_bucket("B. BENIGN TRAIN <-> BENIGN TEST", buckets["B_benign_train_test"])
    report_bucket("C. BENIGN <-> ATTACK (entire dataset) [HIGHEST PRIORITY]", buckets["C_benign_attack"])
    report_c_hash_file(c_hash_path, buckets["C_benign_attack"]["distinct_count"])
    report_bucket("D. ATTACK VALIDATION <-> ATTACK TEST", buckets["D_attack_val_test"])
    report_bucket("E. ATTACK CROSS-CATEGORY", buckets["E_attack_cross_category"])

    resolve_benign_attack_detail(
        c_hash_path, buckets["C_benign_attack"]["distinct_count"], canonical_dtypes, file_to_partition
    )

    end_time = datetime.now(timezone.utc).isoformat()
    print("\n=== PROVENANCE (end) ===")
    print(f"Files actually opened: {len(files)}")
    print(f"Total rows actually processed: {total_rows}")
    print(f"Chunk directory: {chunk_dir}")
    print(f"End time (UTC): {end_time}")


if __name__ == "__main__":
    main()
