"""Tests for ARVO dataset ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from parser_security_eval.dataset.arvo import (
    _build_tags,
    _estimate_difficulty,
    _extract_affected_file,
    _map_sanitizer,
    _map_severity,
    fetch_arvo_index,
    ingest_arvo,
    is_parser_project,
    parse_arvo_entry,
)
from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_entry(
    *,
    project: str = "libpng",
    crash_type: str = "Heap-buffer-overflow READ 4",
    severity: str = "Medium",
    sanitizer: str = "address",
    local_id: int = 12345,
    job_type: str = "libfuzzer_asan_libpng",
    fuzz_target: str = "libpng_read_fuzzer",
    platform: str = "linux",
    reproducer: str = "https://example.com/repro",
) -> dict:
    """Build a synthetic ARVO metadata entry."""
    return {
        "project": project,
        "job_type": job_type,
        "platform": platform,
        "crash_type": crash_type,
        "crash_address": "0x603000000450",
        "severity": severity,
        "regressed": "https://example.com/regressed",
        "reproducer": reproducer,
        "verified_fixed": "https://example.com/fixed",
        "localId": local_id,
        "sanitizer": sanitizer,
        "fuzz_target": fuzz_target,
    }


def _write_metadata_jsonl(path: Path, entries: list[dict]) -> None:
    """Write a list of dicts as JSONL to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# is_parser_project
# ---------------------------------------------------------------------------


class TestIsParserProject:
    def test_allowlisted_project(self) -> None:
        assert is_parser_project("libpng") is True
        assert is_parser_project("freetype2") is True
        assert is_parser_project("libxml2") is True

    def test_keyword_match(self) -> None:
        assert is_parser_project("my-json-parser") is True
        assert is_parser_project("xml-decoder") is True
        assert is_parser_project("image_reader") is True

    def test_case_insensitive(self) -> None:
        assert is_parser_project("LibPNG") is True
        assert is_parser_project("FREETYPE2") is True

    def test_non_parser_project(self) -> None:
        assert is_parser_project("linux-kernel") is False
        assert is_parser_project("systemd") is False
        assert is_parser_project("containerd") is False

    def test_empty_string(self) -> None:
        assert is_parser_project("") is False


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


class TestMapSeverity:
    def test_known_values(self) -> None:
        assert _map_severity("Critical") == Severity.CRITICAL
        assert _map_severity("High") == Severity.HIGH
        assert _map_severity("Medium") == Severity.MEDIUM
        assert _map_severity("Low") == Severity.LOW

    def test_case_insensitive(self) -> None:
        assert _map_severity("HIGH") == Severity.HIGH
        assert _map_severity("  medium  ") == Severity.MEDIUM

    def test_unknown_defaults_to_medium(self) -> None:
        assert _map_severity("unknown") == Severity.MEDIUM
        assert _map_severity("") == Severity.MEDIUM


class TestMapSanitizer:
    def test_known_values(self) -> None:
        assert _map_sanitizer("address") == Sanitizer.ADDRESS
        assert _map_sanitizer("undefined") == Sanitizer.UNDEFINED
        assert _map_sanitizer("memory") == Sanitizer.MEMORY

    def test_unknown_defaults_to_address(self) -> None:
        assert _map_sanitizer("unknown") == Sanitizer.ADDRESS


class TestEstimateDifficulty:
    def test_easy_crash_types(self) -> None:
        assert _estimate_difficulty("Null-dereference") == Difficulty.EASY
        assert _estimate_difficulty("Stack-buffer-overflow READ 1") == Difficulty.EASY
        assert _estimate_difficulty("Integer-overflow") == Difficulty.EASY

    def test_hard_crash_types(self) -> None:
        assert _estimate_difficulty("Heap-use-after-free") == Difficulty.HARD
        assert _estimate_difficulty("Double-free") == Difficulty.HARD

    def test_medium_default(self) -> None:
        assert _estimate_difficulty("Heap-buffer-overflow READ 4") == Difficulty.MEDIUM


class TestExtractAffectedFile:
    def test_fuzz_target_preferred(self) -> None:
        assert _extract_affected_file("libfuzzer_asan_proj", "my_fuzzer") == "my_fuzzer"

    def test_fallback_to_job_type(self) -> None:
        assert _extract_affected_file("libfuzzer_asan_freetype2", None) == "freetype2"

    def test_short_job_type(self) -> None:
        assert _extract_affected_file("something", None) == "something"


class TestBuildTags:
    def test_overflow_tag(self) -> None:
        tags = _build_tags(
            {"crash_type": "Heap-buffer-overflow READ 4", "platform": "linux"}
        )
        assert "overflow" in tags
        assert "platform:linux" in tags

    def test_uaf_tag(self) -> None:
        tags = _build_tags({"crash_type": "Heap-use-after-free"})
        assert "use-after-free" in tags

    def test_no_tags_for_unknown(self) -> None:
        tags = _build_tags({"crash_type": "Unknown-crash"})
        assert tags == []


# ---------------------------------------------------------------------------
# parse_arvo_entry
# ---------------------------------------------------------------------------


class TestParseArvoEntry:
    def test_parser_project_produces_record(self) -> None:
        entry = _make_entry(project="libpng")
        record = parse_arvo_entry(entry)
        assert record is not None
        assert record.id == "ARVO-12345"
        assert record.target == "libpng"
        assert record.crash_type == "Heap-buffer-overflow READ 4"
        assert record.sanitizer == Sanitizer.ADDRESS

    def test_non_parser_project_returns_none(self) -> None:
        entry = _make_entry(project="systemd")
        assert parse_arvo_entry(entry) is None

    def test_missing_local_id_returns_none(self) -> None:
        entry = _make_entry(project="libpng")
        del entry["localId"]
        assert parse_arvo_entry(entry) is None

    def test_severity_mapping(self) -> None:
        entry = _make_entry(severity="High")
        record = parse_arvo_entry(entry)
        assert record is not None
        assert record.severity == Severity.HIGH

    def test_difficulty_estimation(self) -> None:
        entry = _make_entry(crash_type="Heap-use-after-free")
        record = parse_arvo_entry(entry)
        assert record is not None
        assert record.difficulty == Difficulty.HARD

    def test_tags_present(self) -> None:
        entry = _make_entry(crash_type="Heap-buffer-overflow READ 4", platform="linux")
        record = parse_arvo_entry(entry)
        assert record is not None
        assert "overflow" in record.tags
        assert "platform:linux" in record.tags


# ---------------------------------------------------------------------------
# fetch_arvo_index (mocked git)
# ---------------------------------------------------------------------------


class TestFetchArvoIndex:
    def test_clones_on_first_run(self, tmp_path: Path) -> None:
        """When no clone exists, fetch_arvo_index should call git clone."""
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "ARVO"

        # Pre-create the metadata file so the function finds it
        metadata = repo_dir / "arvo" / "NewTracker" / "metadata.jsonl"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text('{"project": "libpng", "localId": 1}\n')

        calls: list[list[str]] = []

        def mock_run(cmd: list[str], **_kwargs: object) -> None:
            calls.append(cmd)
            # Simulate git clone creating the .git dir
            if cmd[1] == "clone":
                (repo_dir / ".git").mkdir(parents=True, exist_ok=True)

        with patch(
            "parser_security_eval.dataset.arvo.subprocess.run", side_effect=mock_run
        ):
            result = fetch_arvo_index(cache_dir)

        assert result == metadata
        # Should have called clone + sparse-checkout
        assert any("clone" in c for c in calls)
        assert any("sparse-checkout" in c for c in calls)

    def test_pulls_on_subsequent_run(self, tmp_path: Path) -> None:
        """When a clone already exists, fetch_arvo_index should git pull."""
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "ARVO"
        (repo_dir / ".git").mkdir(parents=True, exist_ok=True)

        metadata = repo_dir / "arvo" / "NewTracker" / "metadata.jsonl"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text('{"project": "libpng", "localId": 1}\n')

        calls: list[list[str]] = []

        def mock_run(cmd: list[str], **_kwargs: object) -> None:
            calls.append(cmd)

        with patch(
            "parser_security_eval.dataset.arvo.subprocess.run", side_effect=mock_run
        ):
            result = fetch_arvo_index(cache_dir)

        assert result == metadata
        assert any("pull" in c for c in calls)
        assert not any("clone" in c for c in calls)

    def test_raises_if_metadata_missing(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "ARVO"

        def mock_run(cmd: list[str], **_kwargs: object) -> None:
            if cmd[1] == "clone":
                (repo_dir / ".git").mkdir(parents=True, exist_ok=True)

        with (
            patch(
                "parser_security_eval.dataset.arvo.subprocess.run", side_effect=mock_run
            ),
            pytest.raises(FileNotFoundError, match="metadata.jsonl not found"),
        ):
            fetch_arvo_index(cache_dir)


# ---------------------------------------------------------------------------
# ingest_arvo (integration test with mocked git)
# ---------------------------------------------------------------------------


class TestIngestArvo:
    def _setup_metadata(self, tmp_path: Path, entries: list[dict]) -> Path:
        """Write fake metadata and return cache_dir."""
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "ARVO"
        (repo_dir / ".git").mkdir(parents=True, exist_ok=True)
        metadata = repo_dir / "arvo" / "NewTracker" / "metadata.jsonl"
        _write_metadata_jsonl(metadata, entries)
        return cache_dir

    def test_end_to_end(self, tmp_path: Path) -> None:
        entries = [
            _make_entry(project="libpng", local_id=100),
            _make_entry(project="systemd", local_id=200),  # should be filtered out
            _make_entry(project="freetype2", local_id=300),
        ]
        cache_dir = self._setup_metadata(tmp_path, entries)
        output_dir = tmp_path / "output"

        with patch("parser_security_eval.dataset.arvo.subprocess.run"):
            records = ingest_arvo(cache_dir, output_dir)

        assert len(records) == 2
        assert {r.id for r in records} == {"ARVO-100", "ARVO-300"}

        # Check artifact files were written
        assert (output_dir / "ARVO-100" / "crash_report.txt").exists()
        assert (output_dir / "ARVO-100" / "reference_patch.diff").exists()
        assert (output_dir / "ARVO-100" / "reproducer_url.txt").exists()
        assert (output_dir / "records.jsonl").exists()

    def test_limit(self, tmp_path: Path) -> None:
        entries = [_make_entry(project="libpng", local_id=i) for i in range(10)]
        cache_dir = self._setup_metadata(tmp_path, entries)
        output_dir = tmp_path / "output"

        with patch("parser_security_eval.dataset.arvo.subprocess.run"):
            records = ingest_arvo(cache_dir, output_dir, limit=3)

        assert len(records) == 3

    def test_empty_dataset(self, tmp_path: Path) -> None:
        cache_dir = self._setup_metadata(tmp_path, [])
        output_dir = tmp_path / "output"

        with patch("parser_security_eval.dataset.arvo.subprocess.run"):
            records = ingest_arvo(cache_dir, output_dir)

        assert records == []
        assert (output_dir / "records.jsonl").exists()

    def test_records_jsonl_roundtrip(self, tmp_path: Path) -> None:
        entries = [_make_entry(project="libxml2", local_id=42)]
        cache_dir = self._setup_metadata(tmp_path, entries)
        output_dir = tmp_path / "output"

        with patch("parser_security_eval.dataset.arvo.subprocess.run"):
            ingest_arvo(cache_dir, output_dir)

        # Read back the JSONL and verify it round-trips
        lines = (output_dir / "records.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["id"] == "ARVO-42"
        assert data["target"] == "libxml2"
