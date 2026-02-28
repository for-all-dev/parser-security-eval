"""Dataset curation: filter, validate, and export vulnerability datasets."""

import json
from pathlib import Path

from parser_security_eval.models import VulnerabilityRecord


class DatasetCurator:
    """Curates a benchmark dataset from raw vulnerability sources."""

    def __init__(self, benchmark_dir: Path) -> None:
        self.benchmark_dir = benchmark_dir
        self.records: list[VulnerabilityRecord] = []

    def add_records(self, records: list[VulnerabilityRecord]) -> None:
        """Add vulnerability records, deduplicating by ID."""
        existing_ids = {r.id for r in self.records}
        for record in records:
            if record.id not in existing_ids:
                self.records.append(record)
                existing_ids.add(record.id)

    def filter_by_target(self, target: str) -> list[VulnerabilityRecord]:
        """Filter records to a specific parser target."""
        return [r for r in self.records if r.target == target]

    def filter_by_difficulty(self, difficulty: str) -> list[VulnerabilityRecord]:
        """Filter records by difficulty tier."""
        return [r for r in self.records if r.difficulty == difficulty]

    def validate(self) -> list[str]:
        """Validate all records have required fields and artifacts exist.

        Returns a list of validation error messages (empty = all valid).
        """
        errors: list[str] = []
        required_fields = ("id", "target", "crash_type", "affected_file")

        for record in self.records:
            # Check required string fields are non-empty
            for field in required_fields:
                value = getattr(record, field)
                if not value or not str(value).strip():
                    errors.append(f"{record.id}: required field '{field}' is empty")

            # Check artifact paths exist on disk when set
            artifact_paths = (
                ("crash_input_path", record.crash_input_path),
                ("crash_report_path", record.crash_report_path),
                ("reference_patch_path", record.reference_patch_path),
            )
            for field_name, path in artifact_paths:
                if path is not None:
                    full_path = self.benchmark_dir / path
                    if not full_path.exists():
                        errors.append(
                            f"{record.id}: artifact '{field_name}' not found at {full_path}"
                        )

        return errors

    def export_metadata(self) -> None:
        """Write benchmark/metadata.json with all curated records."""
        metadata = {
            "version": "0.1.0",
            "total_vulnerabilities": len(self.records),
            "targets": sorted({r.target for r in self.records}),
            "records": [r.model_dump(mode="json") for r in self.records],
        }
        output = self.benchmark_dir / "metadata.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(metadata, indent=2, default=str))

    def export_inspect_dataset(self) -> None:
        """Export as an Inspect-AI compatible dataset (JSONL).

        Each line is a JSON object with 'input' and 'target' fields:
        - input: crash report text, triggering input reference, source code reference
        - target: reference patch content (for scoring comparison)
        """
        output = self.benchmark_dir / "dataset.jsonl"
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w") as f:
            for record in self.records:
                # Build input text from available information
                input_parts: list[str] = []
                input_parts.append(f"Vulnerability ID: {record.id}")
                input_parts.append(f"Target: {record.target}")
                input_parts.append(f"Crash Type: {record.crash_type}")
                input_parts.append(f"Sanitizer: {record.sanitizer}")
                input_parts.append(f"Affected File: {record.affected_file}")

                if record.affected_function:
                    input_parts.append(f"Affected Function: {record.affected_function}")
                if record.cwe:
                    input_parts.append(f"CWE: {record.cwe}")

                # Include crash report content if available
                if record.crash_report_path:
                    report_path = self.benchmark_dir / record.crash_report_path
                    if report_path.exists():
                        input_parts.append(
                            f"\n--- Crash Report ---\n{report_path.read_text()}"
                        )

                # Reference the triggering input
                if record.crash_input_path:
                    input_parts.append(f"\nTriggering Input: {record.crash_input_path}")

                # Reference source ref
                if record.vulnerable_source_ref:
                    input_parts.append(
                        f"Vulnerable Source Ref: {record.vulnerable_source_ref}"
                    )

                # Build target from reference patch
                target_text = ""
                if record.reference_patch_path:
                    patch_path = self.benchmark_dir / record.reference_patch_path
                    if patch_path.exists():
                        target_text = patch_path.read_text()

                sample = {
                    "input": "\n".join(input_parts),
                    "target": target_text,
                }
                f.write(json.dumps(sample) + "\n")

    def summary(self) -> dict:
        """Summary statistics of the curated dataset."""
        from collections import Counter

        return {
            "total": len(self.records),
            "by_target": dict(Counter(r.target for r in self.records)),
            "by_severity": dict(Counter(r.severity for r in self.records)),
            "by_difficulty": dict(Counter(r.difficulty for r in self.records)),
            "by_crash_type": dict(Counter(r.crash_type for r in self.records)),
        }
