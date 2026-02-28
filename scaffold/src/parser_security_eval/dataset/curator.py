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
        raise NotImplementedError

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
        """Export as an Inspect-AI compatible dataset (JSONL)."""
        raise NotImplementedError

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
