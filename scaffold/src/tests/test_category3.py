"""Tests for Category 3 dataset classification."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from parser_security_eval.dataset.category3 import (
    FuzzTargetProfile,
    ParserRelevance,
    ProjectAuditEntry,
    SampleRegistryEntry,
    Category3SampleRegistry,
    build_audit_list,
    classify_fuzz_target,
    compile_registry,
    load_registry,
    read_audit_toml,
    save_registry,
    write_audit_toml,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_metadata_jsonl(path: Path, entries: list[dict]) -> None:
    """Write a list of dicts as JSONL to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")


def _make_entry(
    *,
    project: str = "ffmpeg",
    local_id: int = 1000,
    fuzz_target: str = "ffmpeg_demuxer_fuzzer",
    crash_type: str = "heap-buffer-overflow",
    severity: str = "medium",
    sanitizer: str = "address",
) -> dict:
    """Build a synthetic ARVO metadata entry."""
    return {
        "project": project,
        "localId": local_id,
        "fuzz_target": fuzz_target,
        "crash_type": crash_type,
        "severity": severity,
        "sanitizer": sanitizer,
        "job_type": f"libfuzzer_asan_{project}",
        "platform": "linux",
    }


# ---------------------------------------------------------------------------
# classify_fuzz_target
# ---------------------------------------------------------------------------


class TestClassifyFuzzTarget:
    def test_parser_keywords(self) -> None:
        assert (
            classify_fuzz_target("ffmpeg", "ffmpeg_demuxer_fuzzer")
            == ParserRelevance.PARSER
        )
        assert classify_fuzz_target("curl", "curl_parse_url") == ParserRelevance.PARSER
        assert classify_fuzz_target("proj", "my_decoder_test") == ParserRelevance.PARSER
        assert (
            classify_fuzz_target("proj", "read_frame_fuzzer") == ParserRelevance.PARSER
        )
        assert classify_fuzz_target("proj", "inflate_fuzzer") == ParserRelevance.PARSER
        assert classify_fuzz_target("proj", "deserialize_msg") == ParserRelevance.PARSER

    def test_non_parser_keywords(self) -> None:
        assert (
            classify_fuzz_target("ffmpeg", "ffmpeg_encoder_fuzzer")
            == ParserRelevance.NOT_PARSER
        )
        assert classify_fuzz_target("proj", "muxer_test") == ParserRelevance.NOT_PARSER
        assert (
            classify_fuzz_target("proj", "compress_fuzzer")
            == ParserRelevance.NOT_PARSER
        )
        assert classify_fuzz_target("proj", "hash_data") == ParserRelevance.NOT_PARSER
        assert (
            classify_fuzz_target("proj", "render_frame") == ParserRelevance.NOT_PARSER
        )
        assert (
            classify_fuzz_target("proj", "serialize_data") == ParserRelevance.NOT_PARSER
        )
        # BSF = bitstream filter in ffmpeg, not parsing
        assert (
            classify_fuzz_target("ffmpeg", "ffmpeg_BSF_NOISE_fuzzer")
            == ParserRelevance.NOT_PARSER
        )

    def test_uncertain_no_keywords(self) -> None:
        assert (
            classify_fuzz_target("proj", "some_random_fuzzer")
            == ParserRelevance.UNCERTAIN
        )

    def test_mixed_keywords_uncertain(self) -> None:
        # Both parser and non-parser keywords present
        assert (
            classify_fuzz_target("proj", "encoder_decoder_fuzzer")
            == ParserRelevance.UNCERTAIN
        )

    def test_case_insensitive(self) -> None:
        assert classify_fuzz_target("proj", "DEMUXER_FUZZER") == ParserRelevance.PARSER
        assert (
            classify_fuzz_target("proj", "ENCODER_TEST") == ParserRelevance.NOT_PARSER
        )


# ---------------------------------------------------------------------------
# build_audit_list
# ---------------------------------------------------------------------------


class TestBuildAuditList:
    def test_groups_by_project_and_fuzz_target(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(
                project="ffmpeg", local_id=1, fuzz_target="ffmpeg_demuxer_fuzzer"
            ),
            _make_entry(
                project="ffmpeg", local_id=2, fuzz_target="ffmpeg_demuxer_fuzzer"
            ),
            _make_entry(
                project="ffmpeg", local_id=3, fuzz_target="ffmpeg_encoder_fuzzer"
            ),
        ]
        _write_metadata_jsonl(metadata, entries)

        result = build_audit_list(metadata)
        assert len(result) == 1
        assert result[0].name == "ffmpeg"
        assert result[0].total_records == 3
        assert len(result[0].fuzz_targets) == 2

        demuxer = next(
            ft for ft in result[0].fuzz_targets if ft.name == "ffmpeg_demuxer_fuzzer"
        )
        assert demuxer.record_count == 2
        assert demuxer.relevance == ParserRelevance.PARSER

        encoder = next(
            ft for ft in result[0].fuzz_targets if ft.name == "ffmpeg_encoder_fuzzer"
        )
        assert encoder.record_count == 1
        assert encoder.relevance == ParserRelevance.NOT_PARSER

    def test_excludes_category1_projects(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(project="ffmpeg", local_id=1),
            _make_entry(project="libpng", local_id=2, fuzz_target="libpng_read_fuzzer"),
        ]
        _write_metadata_jsonl(metadata, entries)

        result = build_audit_list(metadata, exclude_projects={"libpng"})
        projects = [e.name for e in result]
        assert "libpng" not in projects
        assert "ffmpeg" in projects

    def test_excludes_non_parser_projects(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(project="systemd", local_id=1, fuzz_target="systemd_fuzzer"),
            _make_entry(project="ffmpeg", local_id=2),
        ]
        _write_metadata_jsonl(metadata, entries)

        result = build_audit_list(metadata)
        projects = [e.name for e in result]
        assert "systemd" not in projects

    def test_empty_metadata(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        metadata.write_text("")

        result = build_audit_list(metadata)
        assert result == []

    def test_pre_includes_parser_targets(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(
                project="ffmpeg", local_id=1, fuzz_target="ffmpeg_demuxer_fuzzer"
            ),
        ]
        _write_metadata_jsonl(metadata, entries)

        result = build_audit_list(metadata)
        ft = result[0].fuzz_targets[0]
        assert ft.include is True
        assert ft.relevance == ParserRelevance.PARSER

    def test_pre_excludes_non_parser_targets(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(
                project="ffmpeg", local_id=1, fuzz_target="ffmpeg_encoder_fuzzer"
            ),
        ]
        _write_metadata_jsonl(metadata, entries)

        result = build_audit_list(metadata)
        ft = result[0].fuzz_targets[0]
        assert ft.include is False
        assert ft.relevance == ParserRelevance.NOT_PARSER

    def test_filters_projects_not_in_ossfuzz(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(project="ffmpeg", local_id=1),
            _make_entry(project="libtiff", local_id=2, fuzz_target="tiff_fuzzer"),
        ]
        _write_metadata_jsonl(metadata, entries)

        # Only ffmpeg exists in our mock oss-fuzz project set
        result = build_audit_list(metadata, ossfuzz_projects={"ffmpeg"})
        projects = [e.name for e in result]
        assert "ffmpeg" in projects
        assert "libtiff" not in projects

    def test_ossfuzz_projects_none_skips_filter(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(project="ffmpeg", local_id=1),
            _make_entry(project="libtiff", local_id=2, fuzz_target="tiff_fuzzer"),
        ]
        _write_metadata_jsonl(metadata, entries)

        # When ossfuzz_projects is None, no filtering occurs
        result = build_audit_list(metadata, ossfuzz_projects=None)
        projects = [e.name for e in result]
        assert "ffmpeg" in projects
        assert "libtiff" in projects


# ---------------------------------------------------------------------------
# TOML round-trip
# ---------------------------------------------------------------------------


class TestTomlRoundTrip:
    def test_write_and_read_preserves_fields(self, tmp_path: Path) -> None:
        entries = [
            ProjectAuditEntry(
                name="ffmpeg",
                total_records=100,
                fuzz_targets=[
                    FuzzTargetProfile(
                        name="ffmpeg_demuxer_fuzzer",
                        record_count=80,
                        relevance=ParserRelevance.PARSER,
                        include=True,
                    ),
                    FuzzTargetProfile(
                        name="ffmpeg_encoder_fuzzer",
                        record_count=20,
                        relevance=ParserRelevance.NOT_PARSER,
                        include=False,
                    ),
                ],
            ),
            ProjectAuditEntry(
                name="curl",
                total_records=50,
                include=True,
                fuzz_targets=[
                    FuzzTargetProfile(
                        name="curl_fuzzer",
                        record_count=50,
                        relevance=ParserRelevance.UNCERTAIN,
                    ),
                ],
            ),
        ]

        toml_path = tmp_path / "audit.toml"
        write_audit_toml(entries, toml_path)

        assert toml_path.exists()
        read_back = read_audit_toml(toml_path)

        assert len(read_back) == 2

        # ffmpeg
        ffmpeg = read_back[0]
        assert ffmpeg.name == "ffmpeg"
        assert ffmpeg.total_records == 100
        assert ffmpeg.include is None  # no project-level override
        assert len(ffmpeg.fuzz_targets) == 2
        assert ffmpeg.fuzz_targets[0].name == "ffmpeg_demuxer_fuzzer"
        assert ffmpeg.fuzz_targets[0].relevance == ParserRelevance.PARSER
        assert ffmpeg.fuzz_targets[0].include is True
        assert ffmpeg.fuzz_targets[1].name == "ffmpeg_encoder_fuzzer"
        assert ffmpeg.fuzz_targets[1].relevance == ParserRelevance.NOT_PARSER
        assert ffmpeg.fuzz_targets[1].include is False

        # curl
        curl = read_back[1]
        assert curl.name == "curl"
        assert curl.total_records == 50
        assert curl.include is True
        assert len(curl.fuzz_targets) == 1
        assert curl.fuzz_targets[0].relevance == ParserRelevance.UNCERTAIN
        # uncertain with no include set in TOML
        assert curl.fuzz_targets[0].include is None

    def test_reasoning_preserved(self, tmp_path: Path) -> None:
        entries = [
            ProjectAuditEntry(
                name="proj",
                total_records=10,
                fuzz_targets=[
                    FuzzTargetProfile(
                        name="some_fuzzer",
                        record_count=10,
                        relevance=ParserRelevance.PARSER,
                        include=True,
                        reasoning="Parses input headers",
                    ),
                ],
            ),
        ]

        toml_path = tmp_path / "audit.toml"
        write_audit_toml(entries, toml_path)
        read_back = read_audit_toml(toml_path)

        assert read_back[0].fuzz_targets[0].reasoning == "Parses input headers"


# ---------------------------------------------------------------------------
# compile_registry
# ---------------------------------------------------------------------------


class TestCompileRegistry:
    def test_collects_included_local_ids(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(
                project="ffmpeg", local_id=1, fuzz_target="ffmpeg_demuxer_fuzzer"
            ),
            _make_entry(
                project="ffmpeg", local_id=2, fuzz_target="ffmpeg_encoder_fuzzer"
            ),
            _make_entry(
                project="ffmpeg", local_id=3, fuzz_target="ffmpeg_demuxer_fuzzer"
            ),
        ]
        _write_metadata_jsonl(metadata, entries)

        audit_entries = [
            ProjectAuditEntry(
                name="ffmpeg",
                total_records=3,
                fuzz_targets=[
                    FuzzTargetProfile(
                        name="ffmpeg_demuxer_fuzzer",
                        record_count=2,
                        relevance=ParserRelevance.PARSER,
                        include=True,
                    ),
                    FuzzTargetProfile(
                        name="ffmpeg_encoder_fuzzer",
                        record_count=1,
                        relevance=ParserRelevance.NOT_PARSER,
                        include=False,
                    ),
                ],
            ),
        ]

        registry = compile_registry(audit_entries, metadata)
        assert registry.total_samples == 2
        assert registry.local_ids == {1, 3}

    def test_project_override_includes_all(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(project="curl", local_id=10, fuzz_target="curl_fuzzer"),
            _make_entry(project="curl", local_id=11, fuzz_target="curl_other"),
        ]
        _write_metadata_jsonl(metadata, entries)

        audit_entries = [
            ProjectAuditEntry(
                name="curl",
                total_records=2,
                include=True,
                fuzz_targets=[
                    FuzzTargetProfile(
                        name="curl_fuzzer",
                        record_count=1,
                        relevance=ParserRelevance.UNCERTAIN,
                    ),
                    FuzzTargetProfile(
                        name="curl_other",
                        record_count=1,
                        relevance=ParserRelevance.UNCERTAIN,
                    ),
                ],
            ),
        ]

        registry = compile_registry(audit_entries, metadata)
        assert registry.total_samples == 2
        assert registry.local_ids == {10, 11}

    def test_project_override_excludes_all(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        entries = [
            _make_entry(project="proj", local_id=20, fuzz_target="fuzzer_a"),
        ]
        _write_metadata_jsonl(metadata, entries)

        audit_entries = [
            ProjectAuditEntry(
                name="proj",
                total_records=1,
                include=False,
                fuzz_targets=[
                    FuzzTargetProfile(
                        name="fuzzer_a",
                        record_count=1,
                        relevance=ParserRelevance.PARSER,
                        include=True,
                    ),
                ],
            ),
        ]

        registry = compile_registry(audit_entries, metadata)
        # Project-level override takes precedence over fuzz-target-level
        assert registry.total_samples == 0

    def test_empty_audit(self, tmp_path: Path) -> None:
        metadata = tmp_path / "metadata.jsonl"
        metadata.write_text("")

        registry = compile_registry([], metadata)
        assert registry.total_samples == 0
        assert registry.projects == 0


# ---------------------------------------------------------------------------
# Registry persistence
# ---------------------------------------------------------------------------


class TestRegistryPersistence:
    def test_save_and_load(self, tmp_path: Path) -> None:
        registry = Category3SampleRegistry(
            generated="2026-05-20T00:00:00+00:00",
            total_samples=2,
            projects=1,
            samples=[
                SampleRegistryEntry(
                    local_id=1, project="ffmpeg", fuzz_target="demuxer"
                ),
                SampleRegistryEntry(
                    local_id=2, project="ffmpeg", fuzz_target="demuxer"
                ),
            ],
        )

        path = tmp_path / "registry.json"
        save_registry(registry, path)
        loaded = load_registry(path)

        assert loaded.total_samples == 2
        assert loaded.projects == 1
        assert loaded.local_ids == {1, 2}
        assert loaded.samples[0].project == "ffmpeg"


# ---------------------------------------------------------------------------
# ingest_arvo with local_ids
# ---------------------------------------------------------------------------


class TestIngestArvoLocalIds:
    def _setup_metadata(self, tmp_path: Path, entries: list[dict]) -> Path:
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "ARVO"
        (repo_dir / ".git").mkdir(parents=True, exist_ok=True)
        metadata = repo_dir / "arvo" / "NewTracker" / "metadata.jsonl"
        _write_metadata_jsonl(metadata, entries)
        return cache_dir

    def test_local_ids_includes_non_target_records(self, tmp_path: Path) -> None:
        """local_ids should include records even if their project isn't in targets."""
        from parser_security_eval.dataset.arvo import ingest_arvo

        entries = [
            _make_entry(
                project="ffmpeg", local_id=100, fuzz_target="ffmpeg_demuxer_fuzzer"
            ),
            _make_entry(
                project="ffmpeg", local_id=200, fuzz_target="ffmpeg_encoder_fuzzer"
            ),
            _make_entry(
                project="libpng", local_id=300, fuzz_target="libpng_read_fuzzer"
            ),
        ]
        cache_dir = self._setup_metadata(tmp_path, entries)
        output_dir = tmp_path / "output"

        with patch("parser_security_eval.dataset.arvo.subprocess.run"):
            records = ingest_arvo(
                cache_dir,
                output_dir,
                targets={"libpng"},
                local_ids={100},
            )

        ids = {r.id for r in records}
        # libpng-300 via targets, ffmpeg-100 via local_ids
        assert "ARVO-100" in ids
        assert "ARVO-300" in ids
        # ffmpeg-200 not included (not in local_ids, ffmpeg not in targets)
        assert "ARVO-200" not in ids

    def test_local_ids_none_is_backward_compatible(self, tmp_path: Path) -> None:
        """When local_ids is None, behavior is unchanged."""
        from parser_security_eval.dataset.arvo import ingest_arvo

        entries = [
            _make_entry(
                project="libpng", local_id=100, fuzz_target="libpng_read_fuzzer"
            ),
        ]
        cache_dir = self._setup_metadata(tmp_path, entries)
        output_dir = tmp_path / "output"

        with patch("parser_security_eval.dataset.arvo.subprocess.run"):
            records = ingest_arvo(cache_dir, output_dir, local_ids=None)

        assert len(records) == 1
        assert records[0].id == "ARVO-100"
