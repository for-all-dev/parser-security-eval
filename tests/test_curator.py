"""Tests for dataset curation."""

import json
from pathlib import Path

from parser_security_eval.dataset.curator import DatasetCurator
from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
    VulnerabilityRecord,
)


def _make_record(id: str, target: str = "libpng", difficulty: str = "medium") -> VulnerabilityRecord:
    return VulnerabilityRecord(
        id=id,
        target=target,
        severity=Severity.HIGH,
        difficulty=Difficulty(difficulty),
        crash_type="heap-buffer-overflow",
        sanitizer=Sanitizer.ADDRESS,
        affected_file="test.c",
    )


class TestDatasetCurator:
    def test_add_records_deduplicates(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        records = [_make_record("CVE-1"), _make_record("CVE-2"), _make_record("CVE-1")]
        curator.add_records(records)
        assert len(curator.records) == 2

    def test_filter_by_target(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records([
            _make_record("CVE-1", target="libpng"),
            _make_record("CVE-2", target="libxml2"),
            _make_record("CVE-3", target="libpng"),
        ])
        assert len(curator.filter_by_target("libpng")) == 2
        assert len(curator.filter_by_target("libxml2")) == 1

    def test_filter_by_difficulty(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records([
            _make_record("CVE-1", difficulty="easy"),
            _make_record("CVE-2", difficulty="medium"),
            _make_record("CVE-3", difficulty="hard"),
        ])
        assert len(curator.filter_by_difficulty("easy")) == 1

    def test_export_metadata(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records([_make_record("CVE-1"), _make_record("CVE-2", target="libxml2")])
        curator.export_metadata()

        metadata_path = tmp_path / "metadata.json"
        assert metadata_path.exists()

        metadata = json.loads(metadata_path.read_text())
        assert metadata["total_vulnerabilities"] == 2
        assert "libpng" in metadata["targets"]
        assert "libxml2" in metadata["targets"]

    def test_summary(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records([
            _make_record("CVE-1", target="libpng"),
            _make_record("CVE-2", target="libpng"),
            _make_record("CVE-3", target="libxml2"),
        ])
        summary = curator.summary()
        assert summary["total"] == 3
        assert summary["by_target"]["libpng"] == 2
