"""Tests for the end-to-end curation pipeline.

These tests mock the network-dependent ingestion functions (ARVO clone,
OSV API) and verify that the pipeline orchestration, deduplication,
filtering, validation, and export logic works correctly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from parser_security_eval.cli import (
    CATEGORY1_TARGETS,
    _format_summary,
    run_curation_pipeline,
)
from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
    VulnerabilityRecord,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    id: str,
    target: str = "libpng",
    severity: Severity = Severity.HIGH,
    difficulty: Difficulty = Difficulty.MEDIUM,
    crash_type: str = "heap-buffer-overflow",
    sanitizer: Sanitizer = Sanitizer.ADDRESS,
    affected_file: str = "test.c",
    cwe: str | None = None,
) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        id=id,
        target=target,
        severity=severity,
        difficulty=difficulty,
        crash_type=crash_type,
        sanitizer=sanitizer,
        affected_file=affected_file,
        cwe=cwe,
    )


def _make_osv_bug(
    bug_id: str = "OSS-FUZZ-12345",
    crash_type: str = "heap-buffer-overflow",
    sanitizer: str = "address",
    affected_file: str = "parser.c",
    lines_changed: int | None = 3,
) -> dict[str, Any]:
    return {
        "id": bug_id,
        "summary": f"{crash_type} in parse_element",
        "database_specific": {
            "crash_type": crash_type,
            "sanitizer": sanitizer,
            "affected_file": affected_file,
            **({"lines_changed_in_fix": lines_changed} if lines_changed else {}),
        },
        "aliases": [],
        "references": [],
        "severity": [],
    }


# ---------------------------------------------------------------------------
# Tests: CATEGORY1_TARGETS constant
# ---------------------------------------------------------------------------


class TestCategory1Targets:
    def test_contains_expected_targets(self) -> None:
        assert "libpng" in CATEGORY1_TARGETS
        assert "libjpeg-turbo" in CATEGORY1_TARGETS
        assert "libxml2" in CATEGORY1_TARGETS
        assert "zlib" in CATEGORY1_TARGETS

    def test_exactly_four_targets(self) -> None:
        assert len(CATEGORY1_TARGETS) == 4


# ---------------------------------------------------------------------------
# Tests: _format_summary
# ---------------------------------------------------------------------------


class TestFormatSummary:
    def test_format_output(self) -> None:
        summary = {
            "total": 10,
            "by_target": {"libpng": 5, "zlib": 5},
            "by_severity": {"high": 6, "medium": 4},
            "by_difficulty": {"easy": 3, "medium": 4, "hard": 3},
            "by_crash_type": {"heap-buffer-overflow": 7, "null-dereference": 3},
        }
        text = _format_summary(summary)
        assert "Total vulnerabilities: 10" in text
        assert "libpng: 5" in text
        assert "zlib: 5" in text
        assert "high: 6" in text
        assert "easy: 3" in text
        assert "heap-buffer-overflow: 7" in text


# ---------------------------------------------------------------------------
# Tests: run_curation_pipeline
# ---------------------------------------------------------------------------


class TestRunCurationPipeline:
    """Test the orchestration function with mocked ingestion."""

    def _mock_arvo_records(self, targets: list[str]) -> list[VulnerabilityRecord]:
        """Generate mock ARVO records for the given targets."""
        records = []
        for i, target in enumerate(targets):
            for j in range(5):
                records.append(
                    _make_record(
                        id=f"ARVO-{i * 100 + j}",
                        target=target,
                        severity=[Severity.HIGH, Severity.MEDIUM, Severity.LOW][j % 3],
                        difficulty=[
                            Difficulty.EASY,
                            Difficulty.MEDIUM,
                            Difficulty.HARD,
                        ][j % 3],
                        crash_type=[
                            "heap-buffer-overflow",
                            "null-dereference",
                            "use-after-free",
                        ][j % 3],
                    )
                )
        # Also include some non-category1 records to test filtering
        records.append(
            _make_record(id="ARVO-999", target="ffmpeg", crash_type="timeout")
        )
        return records

    def _mock_ossfuzz_bugs(self, target: str, count: int = 5) -> list[dict[str, Any]]:
        """Generate mock OSV bugs for a target."""
        return [
            _make_osv_bug(
                bug_id=f"OSS-FUZZ-{target}-{i}",
                crash_type=[
                    "heap-buffer-overflow",
                    "stack-buffer-overflow",
                    "null-dereference",
                ][i % 3],
                lines_changed=[2, 10, 50][i % 3],
            )
            for i in range(count)
        ]

    def test_arvo_source(self, tmp_path: Path) -> None:
        """Pipeline with source='arvo' should only call ARVO ingestion."""
        mock_records = self._mock_arvo_records(CATEGORY1_TARGETS)
        # ingest_arvo now filters by targets internally, so the mock
        # should only return matching records (simulating that behavior).
        cat1_set = {t.lower() for t in CATEGORY1_TARGETS}
        filtered_records = [r for r in mock_records if r.target.lower() in cat1_set]

        with patch(
            "parser_security_eval.cli.ingest_arvo", return_value=filtered_records
        ) as mock_ingest:
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        mock_ingest.assert_called_once()
        assert summary["total"] == 20  # 4 targets * 5 records each
        assert "ffmpeg" not in summary["by_target"]
        # Check exports exist
        assert (tmp_path / "metadata.json").exists()
        assert (tmp_path / "dataset.jsonl").exists()
        assert (tmp_path / "summary.json").exists()

    def test_ossfuzz_source(self, tmp_path: Path) -> None:
        """Pipeline with source='ossfuzz' should fetch bugs for each target."""

        def mock_fetch(project: str, cache_dir: Path) -> list[dict[str, Any]]:
            return self._mock_ossfuzz_bugs(project, count=3)

        with (
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                side_effect=mock_fetch,
            ) as mock_fetch_fn,
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                side_effect=lambda bug, proj: _make_record(id=bug["id"], target=proj),
            ),
        ):
            summary = run_curation_pipeline(
                source="ossfuzz",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        assert mock_fetch_fn.call_count == 4  # one per target
        assert summary["total"] == 12  # 4 targets * 3 bugs each

    def test_all_source_merges_both(self, tmp_path: Path) -> None:
        """Pipeline with source='all' should merge ARVO + oss-fuzz."""
        arvo_records = [
            _make_record(id="ARVO-1", target="libpng"),
            _make_record(id="ARVO-2", target="zlib"),
        ]

        def mock_fetch(project: str, cache_dir: Path) -> list[dict[str, Any]]:
            return [_make_osv_bug(bug_id=f"OSS-FUZZ-{project}-1")]

        with (
            patch("parser_security_eval.cli.ingest_arvo", return_value=arvo_records),
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                side_effect=mock_fetch,
            ),
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                side_effect=lambda bug, proj: _make_record(id=bug["id"], target=proj),
            ),
        ):
            summary = run_curation_pipeline(
                source="all",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        # 2 ARVO + 4 ossfuzz (one per target) = 6
        assert summary["total"] == 6

    def test_deduplication(self, tmp_path: Path) -> None:
        """Records with the same ID from different sources are deduplicated."""
        arvo_records = [
            _make_record(id="SHARED-1", target="libpng"),
            _make_record(id="ARVO-1", target="libpng"),
        ]

        def mock_fetch(project: str, cache_dir: Path) -> list[dict[str, Any]]:
            if project == "libpng":
                return [_make_osv_bug(bug_id="SHARED-1")]
            return []

        with (
            patch("parser_security_eval.cli.ingest_arvo", return_value=arvo_records),
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                side_effect=mock_fetch,
            ),
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                side_effect=lambda bug, proj: _make_record(id=bug["id"], target=proj),
            ),
        ):
            summary = run_curation_pipeline(
                source="all",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
            )

        # SHARED-1 should only appear once
        assert summary["total"] == 2  # SHARED-1 + ARVO-1

    def test_target_filtering(self, tmp_path: Path) -> None:
        """ARVO records for non-requested targets are excluded.

        ingest_arvo now filters by targets internally, so the mock
        should only return matching records.
        """
        # Only records matching requested targets (ingest_arvo filters)
        arvo_records = [
            _make_record(id="ARVO-1", target="libpng"),
            _make_record(id="ARVO-3", target="zlib"),
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=arvo_records):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=["libpng", "zlib"],
                cache_dir=tmp_path / "cache",
            )

        assert summary["total"] == 2
        assert "ffmpeg" not in summary["by_target"]

    def test_limit_parameter(self, tmp_path: Path) -> None:
        """The limit parameter should cap per-source ingestion."""
        arvo_records = [
            _make_record(id=f"ARVO-{i}", target="libpng") for i in range(100)
        ]

        with patch(
            "parser_security_eval.cli.ingest_arvo", return_value=arvo_records
        ) as mock_ingest:
            run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
                limit=10,
            )

        # limit is passed through to ingest_arvo
        _, kwargs = mock_ingest.call_args
        assert kwargs.get("limit") == 10

    def test_ossfuzz_limit(self, tmp_path: Path) -> None:
        """The limit parameter caps oss-fuzz records per target."""

        def mock_fetch(project: str, cache_dir: Path) -> list[dict[str, Any]]:
            return self._mock_ossfuzz_bugs(project, count=20)

        parsed_count = 0

        def mock_parse(bug: dict, proj: str) -> VulnerabilityRecord:
            nonlocal parsed_count
            parsed_count += 1
            return _make_record(id=bug["id"], target=proj)

        with (
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                side_effect=mock_fetch,
            ),
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                side_effect=mock_parse,
            ),
        ):
            summary = run_curation_pipeline(
                source="ossfuzz",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
                limit=5,
            )

        # Should be capped at 5 per target
        assert summary["total"] == 5

    def test_metadata_json_structure(self, tmp_path: Path) -> None:
        """Exported metadata.json should have the expected structure."""
        arvo_records = [
            _make_record(id="ARVO-1", target="libpng"),
            _make_record(id="ARVO-2", target="zlib", severity=Severity.LOW),
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=arvo_records):
            run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        metadata = json.loads((tmp_path / "metadata.json").read_text())
        assert metadata["version"] == "0.1.0"
        assert metadata["total_vulnerabilities"] == 2
        assert "libpng" in metadata["targets"]
        assert "zlib" in metadata["targets"]
        assert len(metadata["records"]) == 2

    def test_dataset_jsonl_structure(self, tmp_path: Path) -> None:
        """Exported dataset.jsonl should have input/target fields."""
        arvo_records = [_make_record(id="ARVO-1", target="libpng")]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=arvo_records):
            run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
            )

        lines = (tmp_path / "dataset.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        sample = json.loads(lines[0])
        assert "input" in sample
        assert "target" in sample
        assert "ARVO-1" in sample["input"]
        assert "libpng" in sample["input"]

    def test_summary_json_written(self, tmp_path: Path) -> None:
        """Summary statistics should be written to summary.json."""
        arvo_records = [
            _make_record(id="ARVO-1", target="libpng"),
            _make_record(id="ARVO-2", target="libpng", difficulty=Difficulty.HARD),
            _make_record(id="ARVO-3", target="zlib", severity=Severity.CRITICAL),
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=arvo_records):
            run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        summary = json.loads((tmp_path / "summary.json").read_text())
        assert summary["total"] == 3
        assert summary["by_target"]["libpng"] == 2
        assert summary["by_target"]["zlib"] == 1

    def test_empty_results(self, tmp_path: Path) -> None:
        """Pipeline handles the case where no records match."""
        with patch("parser_security_eval.cli.ingest_arvo", return_value=[]):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        assert summary["total"] == 0
        assert (tmp_path / "metadata.json").exists()
        assert (tmp_path / "dataset.jsonl").exists()

    def test_ossfuzz_parse_returns_none_skipped(self, tmp_path: Path) -> None:
        """Records where parse_ossfuzz_bug returns None are skipped."""

        def mock_fetch(project: str, cache_dir: Path) -> list[dict[str, Any]]:
            return [
                _make_osv_bug(bug_id="GOOD-1"),
                _make_osv_bug(bug_id=""),  # will return None from parse
                _make_osv_bug(bug_id="GOOD-2"),
            ]

        call_count = 0

        def mock_parse(bug: dict, proj: str) -> VulnerabilityRecord | None:
            nonlocal call_count
            call_count += 1
            if not bug.get("id"):
                return None
            return _make_record(id=bug["id"], target=proj)

        with (
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                side_effect=mock_fetch,
            ),
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                side_effect=mock_parse,
            ),
        ):
            summary = run_curation_pipeline(
                source="ossfuzz",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
            )

        assert summary["total"] == 2


# ---------------------------------------------------------------------------
# Tests: summary statistics accuracy
# ---------------------------------------------------------------------------


class TestSummaryStatistics:
    def test_severity_distribution(self, tmp_path: Path) -> None:
        records = [
            _make_record(id="V-1", target="libpng", severity=Severity.CRITICAL),
            _make_record(id="V-2", target="libpng", severity=Severity.CRITICAL),
            _make_record(id="V-3", target="libpng", severity=Severity.HIGH),
            _make_record(id="V-4", target="zlib", severity=Severity.MEDIUM),
            _make_record(id="V-5", target="zlib", severity=Severity.LOW),
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=records):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        assert summary["by_severity"]["critical"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_severity"]["low"] == 1

    def test_difficulty_distribution(self, tmp_path: Path) -> None:
        records = [
            _make_record(id="V-1", target="libpng", difficulty=Difficulty.EASY),
            _make_record(id="V-2", target="libpng", difficulty=Difficulty.EASY),
            _make_record(id="V-3", target="libpng", difficulty=Difficulty.MEDIUM),
            _make_record(id="V-4", target="zlib", difficulty=Difficulty.HARD),
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=records):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        assert summary["by_difficulty"]["easy"] == 2
        assert summary["by_difficulty"]["medium"] == 1
        assert summary["by_difficulty"]["hard"] == 1

    def test_crash_type_distribution(self, tmp_path: Path) -> None:
        records = [
            _make_record(id="V-1", target="libpng", crash_type="heap-buffer-overflow"),
            _make_record(id="V-2", target="libpng", crash_type="heap-buffer-overflow"),
            _make_record(id="V-3", target="zlib", crash_type="null-dereference"),
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=records):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        assert summary["by_crash_type"]["heap-buffer-overflow"] == 2
        assert summary["by_crash_type"]["null-dereference"] == 1

    def test_vulns_per_target(self, tmp_path: Path) -> None:
        records = [
            _make_record(id=f"V-{i}", target=target)
            for i, target in enumerate(
                ["libpng"] * 10 + ["zlib"] * 5 + ["libxml2"] * 3 + ["libjpeg-turbo"] * 2
            )
        ]

        with patch("parser_security_eval.cli.ingest_arvo", return_value=records):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=CATEGORY1_TARGETS,
                cache_dir=tmp_path / "cache",
            )

        assert summary["by_target"]["libpng"] == 10
        assert summary["by_target"]["zlib"] == 5
        assert summary["by_target"]["libxml2"] == 3
        assert summary["by_target"]["libjpeg-turbo"] == 2


# ---------------------------------------------------------------------------
# Tests: validation integration
# ---------------------------------------------------------------------------


class TestValidation:
    def test_validation_with_missing_artifacts_logs_warnings(
        self, tmp_path: Path
    ) -> None:
        """Records with artifact paths pointing to nonexistent files produce warnings."""
        record = _make_record(id="ARVO-1", target="libpng")
        record.crash_report_path = Path("nonexistent/report.txt")

        with patch("parser_security_eval.cli.ingest_arvo", return_value=[record]):
            # Should not raise, just log warnings
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
            )

        assert summary["total"] == 1

    def test_validation_passes_with_existing_artifacts(self, tmp_path: Path) -> None:
        """Records with valid artifact paths should validate cleanly."""
        # Create artifact
        (tmp_path / "reports").mkdir()
        (tmp_path / "reports" / "report.txt").write_text("crash report")

        record = _make_record(id="ARVO-1", target="libpng")
        record.crash_report_path = Path("reports/report.txt")

        with patch("parser_security_eval.cli.ingest_arvo", return_value=[record]):
            summary = run_curation_pipeline(
                source="arvo",
                output=tmp_path,
                targets=["libpng"],
                cache_dir=tmp_path / "cache",
            )

        assert summary["total"] == 1
