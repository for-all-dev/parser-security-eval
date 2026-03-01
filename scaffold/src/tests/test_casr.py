"""Tests for CASR crash triage integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from parser_security_eval.triage.casr import (
    CASRTriager,
    CrashCluster,
    CrashReport,
    Exploitability,
    TriageResult,
)

# ---------------------------------------------------------------------------
# Sample CASR JSON fixture
# ---------------------------------------------------------------------------

SAMPLE_CASR_JSON: dict[str, object] = {
    "CrashLine": "src/parser.c:42",
    "CrashSeverity": {
        "ShortDescription": "heap-buffer-overflow(read)",
        "Type": "EXPLOITABLE",
        "Description": "Heap buffer overread in parse_chunk",
        "Exploitability": "EXPLOITABLE",
    },
    "Stacktrace": [
        "#0 parse_chunk src/parser.c:42",
        "#1 parse_document src/parser.c:200",
        "#2 main src/main.c:100",
    ],
    "Title": "heap-buffer-overflow(read) in parse_chunk",
}


# ---------------------------------------------------------------------------
# CrashReport.from_casr_json
# ---------------------------------------------------------------------------


class TestCrashReportFromCasrJson:
    def test_basic_fields(self, tmp_path: Path) -> None:
        crash_file = tmp_path / "crash-001"
        crash_file.write_bytes(b"\x00\x01\x02")
        report = CrashReport.from_casr_json(SAMPLE_CASR_JSON, crash_file)

        assert report.crash_file == crash_file
        assert report.crash_line == "src/parser.c:42"
        assert report.title == "heap-buffer-overflow(read) in parse_chunk"
        assert len(report.stacktrace) == 3
        assert report.stacktrace[0] == "#0 parse_chunk src/parser.c:42"

    def test_severity_parsed(self, tmp_path: Path) -> None:
        crash_file = tmp_path / "crash-001"
        crash_file.write_bytes(b"\x00")
        report = CrashReport.from_casr_json(SAMPLE_CASR_JSON, crash_file)

        assert report.severity is not None
        assert report.severity.exploitability == Exploitability.EXPLOITABLE
        assert report.severity.short_description == "heap-buffer-overflow(read)"
        assert "Heap buffer overread" in report.severity.description

    def test_report_file_stored(self, tmp_path: Path) -> None:
        crash_file = tmp_path / "crash-001"
        crash_file.write_bytes(b"\x00")
        report_file = tmp_path / "crash-001.casrep"
        report = CrashReport.from_casr_json(
            SAMPLE_CASR_JSON, crash_file, report_file=report_file
        )
        assert report.casr_report_file == report_file

    def test_unknown_exploitability(self, tmp_path: Path) -> None:
        data: dict[str, object] = {
            "CrashLine": "src/foo.c:1",
            "CrashSeverity": {
                "ShortDescription": "signal",
                "Exploitability": "SOME_NEW_VALUE",
                "Description": "",
            },
            "Stacktrace": [],
            "Title": "",
        }
        crash_file = tmp_path / "crash-002"
        crash_file.write_bytes(b"\xff")
        report = CrashReport.from_casr_json(data, crash_file)
        assert report.severity is not None
        assert report.severity.exploitability == Exploitability.UNKNOWN

    def test_missing_severity(self, tmp_path: Path) -> None:
        data: dict[str, object] = {
            "CrashLine": "",
            "Stacktrace": [],
            "Title": "",
        }
        crash_file = tmp_path / "crash-003"
        crash_file.write_bytes(b"\x00")
        report = CrashReport.from_casr_json(data, crash_file)
        assert report.severity is None

    def test_empty_stacktrace(self, tmp_path: Path) -> None:
        data: dict[str, object] = {
            "CrashLine": "",
            "CrashSeverity": {
                "ShortDescription": "x",
                "Exploitability": "NOT_EXPLOITABLE",
                "Description": "",
            },
            "Stacktrace": [],
            "Title": "",
        }
        crash_file = tmp_path / "crash-004"
        crash_file.write_bytes(b"\x00")
        report = CrashReport.from_casr_json(data, crash_file)
        assert report.stacktrace == []


# ---------------------------------------------------------------------------
# CrashCluster.size
# ---------------------------------------------------------------------------


class TestCrashClusterSize:
    def test_singleton(self, tmp_path: Path) -> None:
        rep = CrashReport(crash_file=tmp_path / "c1")
        cluster = CrashCluster(cluster_id=1, representative=rep, members=[])
        assert cluster.size == 1

    def test_with_members(self, tmp_path: Path) -> None:
        rep = CrashReport(crash_file=tmp_path / "c1")
        m1 = CrashReport(crash_file=tmp_path / "c2")
        m2 = CrashReport(crash_file=tmp_path / "c3")
        cluster = CrashCluster(cluster_id=1, representative=rep, members=[m1, m2])
        assert cluster.size == 3


# ---------------------------------------------------------------------------
# TriageResult.summary
# ---------------------------------------------------------------------------


class TestTriageResultSummary:
    def test_non_empty_string(self, tmp_path: Path) -> None:
        rep = CrashReport.from_casr_json(SAMPLE_CASR_JSON, tmp_path / "crash-001")
        cluster = CrashCluster(cluster_id=1, representative=rep)
        result = TriageResult(
            target_name="libxml2",
            total_crashes=3,
            clusters=[cluster],
            exploitable_count=1,
            probably_exploitable_count=0,
            not_exploitable_count=0,
            unknown_count=2,
        )
        summary = result.summary()
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_contains_target_name(self, tmp_path: Path) -> None:
        result = TriageResult(
            target_name="libpng",
            total_crashes=0,
            clusters=[],
        )
        assert "libpng" in result.summary()

    def test_contains_counts(self, tmp_path: Path) -> None:
        rep = CrashReport.from_casr_json(SAMPLE_CASR_JSON, tmp_path / "crash-001")
        cluster = CrashCluster(cluster_id=1, representative=rep)
        result = TriageResult(
            target_name="libpng",
            total_crashes=5,
            clusters=[cluster],
            exploitable_count=1,
            probably_exploitable_count=2,
            not_exploitable_count=1,
            unknown_count=1,
        )
        summary = result.summary()
        assert "5" in summary
        assert "1" in summary

    def test_cluster_title_in_summary(self, tmp_path: Path) -> None:
        rep = CrashReport.from_casr_json(SAMPLE_CASR_JSON, tmp_path / "crash-001")
        cluster = CrashCluster(cluster_id=1, representative=rep)
        result = TriageResult(
            target_name="libxml2",
            total_crashes=1,
            clusters=[cluster],
            exploitable_count=1,
        )
        summary = result.summary()
        assert "parse_chunk" in summary


# ---------------------------------------------------------------------------
# CASRTriager._stack_hash_dedup
# ---------------------------------------------------------------------------


class TestStackHashDedup:
    def _make_report(self, tmp_path: Path, name: str, frames: list[str]) -> CrashReport:
        f = tmp_path / name
        f.write_bytes(b"\x00")
        return CrashReport(crash_file=f, stacktrace=frames)

    def test_two_same_one_different(self, tmp_path: Path) -> None:
        """Two reports with same top-5 frames cluster together; one different is alone."""
        shared_frames = [
            "#0 parse_chunk src/parser.c:42",
            "#1 parse_document src/parser.c:200",
            "#2 main src/main.c:100",
            "#3 __libc_start_main",
            "#4 _start",
        ]
        r1 = self._make_report(tmp_path, "crash-001", shared_frames)
        r2 = self._make_report(tmp_path, "crash-002", shared_frames)
        r3 = self._make_report(
            tmp_path,
            "crash-003",
            ["#0 totally_different src/other.c:99"],
        )

        triager = CASRTriager(work_dir=tmp_path)
        clusters = triager._stack_hash_dedup([r1, r2, r3])

        assert len(clusters) == 2
        sizes = sorted(c.size for c in clusters)
        assert sizes == [1, 2]

    def test_all_unique(self, tmp_path: Path) -> None:
        """Each crash with unique frames gets its own cluster."""
        reports = [
            self._make_report(tmp_path, f"crash-{i:03d}", [f"#0 func_{i} x.c:{i}"])
            for i in range(4)
        ]
        triager = CASRTriager(work_dir=tmp_path)
        clusters = triager._stack_hash_dedup(reports)
        assert len(clusters) == 4
        assert all(c.size == 1 for c in clusters)

    def test_empty_input(self, tmp_path: Path) -> None:
        triager = CASRTriager(work_dir=tmp_path)
        clusters = triager._stack_hash_dedup([])
        assert clusters == []

    def test_no_stacktrace_groups_together(self, tmp_path: Path) -> None:
        """Reports with empty stacktrace all hash identically and form one cluster."""
        reports = [self._make_report(tmp_path, f"crash-{i:03d}", []) for i in range(3)]
        triager = CASRTriager(work_dir=tmp_path)
        clusters = triager._stack_hash_dedup(reports)
        assert len(clusters) == 1
        assert clusters[0].size == 3

    def test_top5_frames_only(self, tmp_path: Path) -> None:
        """Only the first 5 frames are used for the hash (deeper frames ignored)."""
        base_frames = [f"#0 func_{i} x.c:{i}" for i in range(5)]
        r1 = self._make_report(tmp_path, "crash-001", base_frames + ["#5 extra_a"])
        r2 = self._make_report(tmp_path, "crash-002", base_frames + ["#5 extra_b"])
        triager = CASRTriager(work_dir=tmp_path)
        clusters = triager._stack_hash_dedup([r1, r2])
        assert len(clusters) == 1
        assert clusters[0].size == 2


# ---------------------------------------------------------------------------
# CASRTriager.triage_crashes — fallback path
# ---------------------------------------------------------------------------


class TestCASRTriagerFallback:
    @pytest.mark.asyncio
    async def test_falls_back_when_casr_unavailable(self, tmp_path: Path) -> None:
        """When _casr_available returns False, triage uses stack-hash dedup."""
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        (crashes_dir / "crash-001").write_bytes(b"\x00\x01")
        (crashes_dir / "crash-002").write_bytes(b"\x02\x03")

        triager = CASRTriager(work_dir=tmp_path)

        with patch.object(
            CASRTriager, "_casr_available", new_callable=AsyncMock, return_value=False
        ):
            result = await triager.triage_crashes(
                crashes_dir=crashes_dir,
                target_name="libxml2",
            )

        assert result.target_name == "libxml2"
        assert result.total_crashes == 2
        # Without stack traces both crashes hash to the same bucket
        assert len(result.clusters) == 1
        assert result.clusters[0].size == 2

    @pytest.mark.asyncio
    async def test_empty_crashes_dir(self, tmp_path: Path) -> None:
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()

        triager = CASRTriager(work_dir=tmp_path)

        with patch.object(
            CASRTriager, "_casr_available", new_callable=AsyncMock, return_value=False
        ):
            result = await triager.triage_crashes(
                crashes_dir=crashes_dir,
                target_name="libpng",
            )

        assert result.total_crashes == 0
        assert result.clusters == []

    @pytest.mark.asyncio
    async def test_nonexistent_crashes_dir(self, tmp_path: Path) -> None:
        crashes_dir = tmp_path / "does-not-exist"

        triager = CASRTriager(work_dir=tmp_path)

        with patch.object(
            CASRTriager, "_casr_available", new_callable=AsyncMock, return_value=False
        ):
            result = await triager.triage_crashes(
                crashes_dir=crashes_dir,
                target_name="zlib",
            )

        assert result.total_crashes == 0
        assert result.clusters == []

    @pytest.mark.asyncio
    async def test_exploitability_counts(self, tmp_path: Path) -> None:
        """Unknown exploitability (no severity) is counted in unknown_count."""
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        for i in range(3):
            (crashes_dir / f"crash-{i:03d}").write_bytes(bytes([i]))

        triager = CASRTriager(work_dir=tmp_path)

        with patch.object(
            CASRTriager, "_casr_available", new_callable=AsyncMock, return_value=False
        ):
            result = await triager.triage_crashes(
                crashes_dir=crashes_dir,
                target_name="libjpeg",
            )

        # Fallback reports have no severity → all unknown
        assert result.unknown_count == len(result.clusters)
        assert result.exploitable_count == 0
        assert result.probably_exploitable_count == 0
        assert result.not_exploitable_count == 0
