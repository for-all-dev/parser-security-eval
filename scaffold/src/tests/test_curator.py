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


def _make_record(
    id: str, target: str = "libpng", difficulty: str = "medium"
) -> VulnerabilityRecord:
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
        curator.add_records(
            [
                _make_record("CVE-1", target="libpng"),
                _make_record("CVE-2", target="libxml2"),
                _make_record("CVE-3", target="libpng"),
            ]
        )
        assert len(curator.filter_by_target("libpng")) == 2
        assert len(curator.filter_by_target("libxml2")) == 1

    def test_filter_by_difficulty(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records(
            [
                _make_record("CVE-1", difficulty="easy"),
                _make_record("CVE-2", difficulty="medium"),
                _make_record("CVE-3", difficulty="hard"),
            ]
        )
        assert len(curator.filter_by_difficulty("easy")) == 1

    def test_export_metadata(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records(
            [_make_record("CVE-1"), _make_record("CVE-2", target="libxml2")]
        )
        curator.export_metadata()

        metadata_path = tmp_path / "metadata.json"
        assert metadata_path.exists()

        metadata = json.loads(metadata_path.read_text())
        assert metadata["total_vulnerabilities"] == 2
        assert "libpng" in metadata["targets"]
        assert "libxml2" in metadata["targets"]

    def test_summary(self, tmp_path: Path) -> None:
        curator = DatasetCurator(tmp_path)
        curator.add_records(
            [
                _make_record("CVE-1", target="libpng"),
                _make_record("CVE-2", target="libpng"),
                _make_record("CVE-3", target="libxml2"),
            ]
        )
        summary = curator.summary()
        assert summary["total"] == 3
        assert summary["by_target"]["libpng"] == 2

    def test_validate_passes_for_valid_records(self, tmp_path: Path) -> None:
        """Records with no artifact paths set should validate cleanly."""
        curator = DatasetCurator(tmp_path)
        curator.add_records([_make_record("CVE-1"), _make_record("CVE-2")])
        errors = curator.validate()
        assert errors == []

    def test_validate_passes_with_existing_artifacts(self, tmp_path: Path) -> None:
        """Records with artifact paths that exist on disk should validate cleanly."""
        # Create artifact files
        (tmp_path / "inputs").mkdir()
        (tmp_path / "inputs" / "crash.bin").write_bytes(b"\x00\x01")
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports" / "report.txt").write_text("ASAN report here")
        (tmp_path / "patches").mkdir()
        (tmp_path / "patches" / "fix.patch").write_text("diff --git ...")

        record = VulnerabilityRecord(
            id="CVE-100",
            target="libpng",
            severity=Severity.HIGH,
            difficulty=Difficulty.MEDIUM,
            crash_type="heap-buffer-overflow",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="png.c",
            crash_input_path=Path("inputs/crash.bin"),
            crash_report_path=Path("reports/report.txt"),
            reference_patch_path=Path("patches/fix.patch"),
        )
        curator = DatasetCurator(tmp_path)
        curator.add_records([record])
        errors = curator.validate()
        assert errors == []

    def test_validate_catches_missing_artifacts(self, tmp_path: Path) -> None:
        """Validation should report errors when artifact files are missing."""
        record = VulnerabilityRecord(
            id="CVE-200",
            target="libxml2",
            severity=Severity.MEDIUM,
            difficulty=Difficulty.HARD,
            crash_type="use-after-free",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="parser.c",
            crash_input_path=Path("nonexistent/crash.bin"),
            crash_report_path=Path("nonexistent/report.txt"),
            reference_patch_path=Path("nonexistent/fix.patch"),
        )
        curator = DatasetCurator(tmp_path)
        curator.add_records([record])
        errors = curator.validate()
        assert len(errors) == 3
        assert any("crash_input_path" in e for e in errors)
        assert any("crash_report_path" in e for e in errors)
        assert any("reference_patch_path" in e for e in errors)

    def test_validate_catches_partially_missing_artifacts(self, tmp_path: Path) -> None:
        """Validation should only flag missing files, not existing ones."""
        (tmp_path / "inputs").mkdir()
        (tmp_path / "inputs" / "crash.bin").write_bytes(b"\x00")

        record = VulnerabilityRecord(
            id="CVE-300",
            target="libpng",
            severity=Severity.LOW,
            difficulty=Difficulty.EASY,
            crash_type="stack-overflow",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="png.c",
            crash_input_path=Path("inputs/crash.bin"),
            crash_report_path=Path("missing/report.txt"),
        )
        curator = DatasetCurator(tmp_path)
        curator.add_records([record])
        errors = curator.validate()
        assert len(errors) == 1
        assert "crash_report_path" in errors[0]

    def test_export_inspect_dataset_creates_jsonl(self, tmp_path: Path) -> None:
        """export_inspect_dataset should create a valid JSONL file."""
        curator = DatasetCurator(tmp_path)
        curator.add_records([_make_record("CVE-1"), _make_record("CVE-2")])
        curator.export_inspect_dataset()

        dataset_path = tmp_path / "dataset.jsonl"
        assert dataset_path.exists()

        lines = dataset_path.read_text().strip().splitlines()
        assert len(lines) == 2

        for line in lines:
            sample = json.loads(line)
            assert "input" in sample
            assert "target" in sample
            assert "CVE-" in sample["input"]

    def test_export_inspect_dataset_includes_artifact_content(
        self, tmp_path: Path
    ) -> None:
        """Export should inline crash report and reference patch content."""
        # Create artifacts
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports" / "report.txt").write_text(
            "ERROR: AddressSanitizer: heap-buffer-overflow"
        )
        (tmp_path / "patches").mkdir()
        (tmp_path / "patches" / "fix.patch").write_text(
            "--- a/png.c\n+++ b/png.c\n@@ -1 +1 @@\n-bad\n+good"
        )

        record = VulnerabilityRecord(
            id="CVE-400",
            target="libpng",
            severity=Severity.HIGH,
            difficulty=Difficulty.MEDIUM,
            crash_type="heap-buffer-overflow",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="png.c",
            crash_report_path=Path("reports/report.txt"),
            reference_patch_path=Path("patches/fix.patch"),
        )
        curator = DatasetCurator(tmp_path)
        curator.add_records([record])
        curator.export_inspect_dataset()

        dataset_path = tmp_path / "dataset.jsonl"
        line = dataset_path.read_text().strip()
        sample = json.loads(line)

        assert "AddressSanitizer" in sample["input"]
        assert "--- a/png.c" in sample["target"]
