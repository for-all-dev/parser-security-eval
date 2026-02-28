"""Enrich benchmark records with data from arvo.db and ARVO Docker images.

Fills three gaps in the benchmark dataset:
1. crash_report.txt — replace 3-line stubs with full ASAN output from arvo.db
2. crash_input — extract /tmp/poc from n132/arvo:<id>-vul Docker images
3. cwe — deterministic mapping from crash_type to CWE ID
"""

from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Deterministic crash_type → CWE mapping based on ASAN/MSAN crash type strings.
# These are conservative, well-established mappings.
CRASH_TYPE_TO_CWE: dict[str, str] = {
    "Heap-buffer-overflow": "CWE-122",
    "Stack-buffer-overflow": "CWE-121",
    "Global-buffer-overflow": "CWE-125",
    "Heap-use-after-free": "CWE-416",
    "Heap-double-free": "CWE-415",
    "Use-of-uninitialized-value": "CWE-457",
    "Stack-use-after-scope": "CWE-562",
    "Invalid-free": "CWE-761",
    "Memcpy-param-overlap": "CWE-126",
    "Bad-free": "CWE-761",
    "Bad-cast": "CWE-843",
    "UNKNOWN": "CWE-119",  # generic memory corruption
    "Index-out-of-bounds": "CWE-129",
}


def _crash_type_to_cwe(crash_type: str) -> str | None:
    """Map a crash_type string to a CWE ID.

    Handles suffixed forms like 'Heap-buffer-overflow READ 4' by matching
    the prefix before the access direction.  Case-insensitive matching to
    handle both ARVO ('Heap-buffer-overflow') and OSV ('heap-buffer-overflow')
    formats.  Also strips trailing function names like 'in jpeg_free_large'.
    """
    # Normalize: build a lowercase lookup table
    lc_table = {k.lower(): v for k, v in CRASH_TYPE_TO_CWE.items()}
    ct = crash_type.lower()

    # Strip trailing " in <function>" suffix (OSV format)
    if " in " in ct:
        ct = ct.split(" in ")[0].strip()

    # Try exact match first
    if ct in lc_table:
        return lc_table[ct]

    # Strip access qualifiers: "heap-buffer-overflow write {*}" → "heap-buffer-overflow"
    base = ct.split(" read")[0].split(" write")[0].strip()
    if base in lc_table:
        # For buffer overflows, distinguish read vs write
        if "buffer-overflow" in base and " read" in ct:
            return "CWE-125"  # Out-of-bounds Read
        return lc_table[base]

    # Handle "Segv on unknown address" and similar
    if "segv" in ct:
        return "CWE-476"  # NULL Pointer Dereference (common cause)

    # Handle "use-after-poison" (ASan-specific for stack-use-after-scope)
    if "use-after-poison" in ct:
        return "CWE-562"

    # Handle "Dynamic-stack-buffer-overflow"
    if "dynamic-stack-buffer-overflow" in ct:
        return "CWE-121"

    logger.warning("No CWE mapping for crash_type: %s", crash_type)
    return None


def _parse_arvo_id(record_id: str) -> int | None:
    """Extract numeric local ID from 'ARVO-{id}' format."""
    if not record_id.startswith("ARVO-"):
        return None
    try:
        return int(record_id.removeprefix("ARVO-"))
    except ValueError:
        return None


def enrich_crash_reports(
    benchmark_dir: Path,
    cache_dir: Path,
) -> tuple[int, int]:
    """Replace stub crash reports with full ASAN output from arvo.db.

    Returns ``(enriched_count, total_arvo_count)``.
    """
    metadata_path = benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    records = metadata.get("records", [])

    db_path = cache_dir / "arvo.db"
    if not db_path.exists():
        logger.error("arvo.db not found at %s — run fetch-artifacts first", db_path)
        return 0, 0

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    arvo_records = []
    for rec in records:
        lid = _parse_arvo_id(rec["id"])
        if lid is not None:
            arvo_records.append((lid, rec))

    total = len(arvo_records)
    enriched = 0

    for lid, rec in arvo_records:
        row = conn.execute(
            "SELECT crash_output, crash_type, sanitizer, fuzz_target "
            "FROM arvo WHERE localId = ?",
            (lid,),
        ).fetchone()
        if not row or not row["crash_output"]:
            continue

        vuln_dir = benchmark_dir / "arvo" / rec["id"]
        vuln_dir.mkdir(parents=True, exist_ok=True)
        report_path = vuln_dir / "crash_report.txt"
        report_path.write_text(row["crash_output"])

        rec["crash_report_path"] = f"arvo/{rec['id']}/crash_report.txt"
        enriched += 1

    conn.close()

    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info("Enriched %d / %d crash reports with ASAN output", enriched, total)
    return enriched, total


def enrich_cwe(benchmark_dir: Path) -> tuple[int, int]:
    """Populate CWE field from deterministic crash_type mapping.

    Returns ``(mapped_count, total_count)``.
    """
    metadata_path = benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    records = metadata.get("records", [])

    mapped = 0
    for rec in records:
        if rec.get("cwe"):
            mapped += 1
            continue
        cwe = _crash_type_to_cwe(rec.get("crash_type", ""))
        if cwe:
            rec["cwe"] = cwe
            mapped += 1

    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info("CWE mapped for %d / %d records", mapped, len(records))
    return mapped, len(records)


def extract_crash_inputs(
    benchmark_dir: Path,
    *,
    timeout_per_image: int = 120,
) -> tuple[int, int, int]:
    """Extract crash inputs from ARVO Docker images.

    For each ARVO record, pulls ``n132/arvo:<id>-vul`` and copies ``/tmp/poc``
    to ``benchmark/arvo/ARVO-<id>/crash_input``.

    Returns ``(extracted_count, skipped_count, total_arvo_count)``.
    """
    metadata_path = benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    records = metadata.get("records", [])

    arvo_records = []
    for rec in records:
        lid = _parse_arvo_id(rec["id"])
        if lid is not None:
            arvo_records.append((lid, rec))

    total = len(arvo_records)
    extracted = 0
    skipped = 0

    for lid, rec in arvo_records:
        vuln_dir = benchmark_dir / "arvo" / rec["id"]
        crash_input_path = vuln_dir / "crash_input"

        # Skip if already extracted
        if crash_input_path.exists() and crash_input_path.stat().st_size > 0:
            rec["crash_input_path"] = f"arvo/{rec['id']}/crash_input"
            skipped += 1
            extracted += 1
            continue

        image = f"n132/arvo:{lid}-vul"
        logger.info("Extracting crash input from %s …", image)

        # Pull image
        try:
            subprocess.run(
                ["docker", "pull", image],
                check=True,
                capture_output=True,
                timeout=timeout_per_image,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.warning("Failed to pull %s: %s", image, e)
            continue

        # Extract /tmp/poc
        vuln_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", image, "cat", "/tmp/poc"],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning("Failed to extract /tmp/poc from %s", image)
                continue

            crash_input_path.write_bytes(result.stdout)
            rec["crash_input_path"] = f"arvo/{rec['id']}/crash_input"
            extracted += 1

            if extracted % 20 == 0:
                logger.info(
                    "Progress: %d / %d crash inputs extracted", extracted, total
                )
        except subprocess.TimeoutExpired:
            logger.warning("Timeout extracting from %s", image)
            continue

    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info(
        "Extracted %d crash inputs (%d already cached), %d total ARVO records",
        extracted - skipped,
        skipped,
        total,
    )
    return extracted, skipped, total
