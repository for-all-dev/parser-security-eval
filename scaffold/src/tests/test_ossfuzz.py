"""Tests for oss-fuzz data ingestion and target import."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from parser_security_eval.dataset.ossfuzz import (
    BootstrapResult,
    _detect_format_type,
    _dockerfile_creates_build_sh,
    _estimate_difficulty,
    _extract_affected_file,
    _extract_crash_type,
    _extract_sanitizer,
    _extract_severity,
    _is_parser_project,
    _read_project_yaml,
    bootstrap_targets,
    clone_ossfuzz_repo,
    fetch_ossfuzz_bugs,
    import_ossfuzz_target,
    list_parser_projects,
    parse_ossfuzz_bug,
)
from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures: synthetic OSV bug records
# ---------------------------------------------------------------------------


def _make_osv_bug(
    bug_id: str = "OSS-FUZZ-12345",
    *,
    crash_type: str = "heap-buffer-overflow",
    sanitizer: str = "address",
    affected_file: str = "parser.c",
    affected_function: str | None = "parse_element",
    lines_changed: int | None = 3,
    aliases: list[str] | None = None,
    severity_score: float | None = None,
    summary: str = "heap-buffer-overflow in parse_element",
) -> dict[str, Any]:
    """Build a synthetic OSV bug dict."""
    bug: dict[str, Any] = {
        "id": bug_id,
        "summary": summary,
        "database_specific": {
            "crash_type": crash_type,
            "sanitizer": sanitizer,
            "affected_file": affected_file,
        },
        "aliases": aliases or [],
        "references": [],
        "severity": [],
    }
    if affected_function is not None:
        bug["database_specific"]["affected_function"] = affected_function
    if lines_changed is not None:
        bug["database_specific"]["lines_changed_in_fix"] = lines_changed
    if severity_score is not None:
        bug["severity"] = [{"score": str(severity_score)}]
    return bug


# ---------------------------------------------------------------------------
# Synthetic oss-fuzz repo fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def ossfuzz_repo(tmp_path: Path) -> Path:
    """Create a synthetic oss-fuzz repository layout."""
    repo = tmp_path / "oss-fuzz"
    projects_dir = repo / "projects"

    # libpng — a known parser project
    libpng = projects_dir / "libpng"
    libpng.mkdir(parents=True)
    (libpng / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    (libpng / "build.sh").write_text("#!/bin/bash\nmake\n")
    (libpng / "project.yaml").write_text(
        "language: c\n"
        "sanitizers:\n"
        "  - address\n"
        "  - undefined\n"
        "fuzzing_engines:\n"
        "  - libfuzzer\n"
        "  - afl\n"
    )
    corpus = libpng / "corpus"
    corpus.mkdir()
    (corpus / "seed1.png").write_bytes(b"\x89PNG")
    (libpng / "png.dict").write_text('kw1="PNG"\n')

    # libxml2 — another parser project
    libxml2 = projects_dir / "libxml2"
    libxml2.mkdir(parents=True)
    (libxml2 / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    (libxml2 / "build.sh").write_text("#!/bin/bash\nmake\n")
    (libxml2 / "project.yaml").write_text("language: c\n")

    # file — project with extra fuzzer harness files referenced via COPY
    file_proj = projects_dir / "file"
    file_proj.mkdir(parents=True)
    (file_proj / "Dockerfile").write_text(
        "FROM gcr.io/oss-fuzz-base/base-builder\n"
        "COPY build.sh fuzzer_temp_file.h magic_fuzzer.cc $SRC/\n"
    )
    (file_proj / "build.sh").write_text("#!/bin/bash\nmake\n")
    (file_proj / "project.yaml").write_text("language: c\n")
    (file_proj / "fuzzer_temp_file.h").write_text("#pragma once\n")
    (file_proj / "magic_fuzzer.cc").write_text("int main() {}\n")
    # Also include a subdirectory (like ghostscript's pdf_seeds/)
    seeds = file_proj / "pdf_seeds"
    seeds.mkdir()
    (seeds / "sample.pdf").write_bytes(b"%PDF-1.4")

    # unrelated_project — should not be listed as parser
    unrelated = projects_dir / "unrelated_project"
    unrelated.mkdir(parents=True)
    (unrelated / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    (unrelated / "build.sh").write_text("#!/bin/bash\nmake\n")

    # my_json_lib — should match keyword heuristic
    jsonlib = projects_dir / "my_json_lib"
    jsonlib.mkdir(parents=True)
    (jsonlib / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    (jsonlib / "build.sh").write_text("#!/bin/bash\nmake\n")

    # embedded_build — has Dockerfile that creates build.sh, but no static build.sh
    embedded = projects_dir / "embedded_build"
    embedded.mkdir(parents=True)
    (embedded / "Dockerfile").write_text(
        "FROM gcr.io/oss-fuzz-base/base-builder\n"
        "RUN git clone --depth 1 https://example.com/embedded_build.git\n"
        "RUN cp $SRC/embedded_build/fuzz/build_fuzzers.sh $SRC/build.sh\n"
    )
    (embedded / "project.yaml").write_text("language: c\n")

    return repo


# ---------------------------------------------------------------------------
# Tests: parse_ossfuzz_bug
# ---------------------------------------------------------------------------


class TestParseOssfuzzBug:
    def test_basic_parse(self) -> None:
        bug = _make_osv_bug()
        record = parse_ossfuzz_bug(bug, "libpng")
        assert record is not None
        assert record.id == "OSS-FUZZ-12345"
        assert record.target == "libpng"
        assert record.crash_type == "heap-buffer-overflow"
        assert record.sanitizer == Sanitizer.ADDRESS
        assert record.affected_file == "parser.c"
        assert record.affected_function == "parse_element"
        assert record.lines_changed_in_fix == 3
        assert record.difficulty == Difficulty.EASY  # 3 lines

    def test_returns_none_for_empty_id(self) -> None:
        bug = _make_osv_bug(bug_id="")
        assert parse_ossfuzz_bug(bug, "libpng") is None

    def test_cwe_extraction(self) -> None:
        bug = _make_osv_bug(aliases=["CVE-2021-1234", "CWE-125"])
        record = parse_ossfuzz_bug(bug, "libpng")
        assert record is not None
        assert record.cwe == "CWE-125"

    def test_no_cwe(self) -> None:
        bug = _make_osv_bug(aliases=["CVE-2021-1234"])
        record = parse_ossfuzz_bug(bug, "libpng")
        assert record is not None
        assert record.cwe is None

    def test_severity_from_cvss(self) -> None:
        bug = _make_osv_bug(severity_score=9.5)
        record = parse_ossfuzz_bug(bug, "libpng")
        assert record is not None
        assert record.severity == Severity.CRITICAL

    def test_severity_from_crash_type(self) -> None:
        bug = _make_osv_bug(crash_type="null-dereference")
        record = parse_ossfuzz_bug(bug, "libpng")
        assert record is not None
        assert record.severity == Severity.LOW


# ---------------------------------------------------------------------------
# Tests: helper extractors
# ---------------------------------------------------------------------------


class TestExtractors:
    def test_crash_type_from_db_specific(self) -> None:
        bug = _make_osv_bug(crash_type="Heap-Use-After-Free")
        assert _extract_crash_type(bug) == "heap-use-after-free"

    def test_crash_type_fallback_to_summary(self) -> None:
        bug: dict[str, Any] = {
            "summary": "stack-buffer-overflow in foo",
            "database_specific": {},
        }
        assert _extract_crash_type(bug) == "stack-buffer-overflow"

    def test_sanitizer_from_db_specific(self) -> None:
        bug = _make_osv_bug(sanitizer="undefined")
        assert _extract_sanitizer(bug) == Sanitizer.UNDEFINED

    def test_sanitizer_from_summary_fallback(self) -> None:
        bug: dict[str, Any] = {
            "summary": "memorysanitizer: use-of-uninitialized-value",
            "database_specific": {},
        }
        assert _extract_sanitizer(bug) == Sanitizer.MEMORY

    def test_sanitizer_defaults_to_address(self) -> None:
        bug: dict[str, Any] = {"summary": "crash", "database_specific": {}}
        assert _extract_sanitizer(bug) == Sanitizer.ADDRESS

    def test_severity_cvss_ranges(self) -> None:
        for score, expected in [
            (9.5, Severity.CRITICAL),
            (7.5, Severity.HIGH),
            (5.0, Severity.MEDIUM),
            (2.0, Severity.LOW),
        ]:
            bug: dict[str, Any] = {
                "severity": [{"score": str(score)}],
                "database_specific": {},
            }
            assert _extract_severity(bug, "unknown") == expected

    def test_severity_fallback_crash_type(self) -> None:
        bug: dict[str, Any] = {"severity": [], "database_specific": {}}
        assert _extract_severity(bug, "heap-buffer-overflow") == Severity.HIGH
        assert _extract_severity(bug, "timeout") == Severity.LOW
        assert _extract_severity(bug, "something-exotic") == Severity.MEDIUM

    def test_affected_file_from_db_specific(self) -> None:
        bug = _make_osv_bug(affected_file="src/decode.c")
        assert _extract_affected_file(bug) == "src/decode.c"

    def test_affected_file_from_reference_url(self) -> None:
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [
                {"url": "https://github.com/foo/bar/blob/main/src/parser.c"},
            ],
        }
        assert _extract_affected_file(bug) == "src/parser.c"

    def test_affected_file_unknown_fallback(self) -> None:
        bug: dict[str, Any] = {"database_specific": {}, "references": []}
        assert _extract_affected_file(bug) == "unknown"

    # --- new tests for OSV crash-state and package-name strategies ---

    def test_affected_file_from_crash_state_cc(self) -> None:
        """A bare .cc filename in the crash state block is returned."""
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [],
            "details": (
                "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32964\n\n"
                "```\n"
                "Crash type: Heap-buffer-overflow WRITE 1\n"
                "Crash state:\n"
                "get_word_rgb_row\n"
                "tjLoadImage\n"
                "compress.cc\n"
                "```\n"
            ),
        }
        assert _extract_affected_file(bug) == "compress.cc"

    def test_affected_file_from_crash_state_c(self) -> None:
        """A bare .c filename in the crash state block is returned."""
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [],
            "details": (
                "OSS-Fuzz report: https://example.com\n\n"
                "```\n"
                "Crash type: Heap-use-after-free READ 1\n"
                "Crash state:\n"
                "xmlTextReaderRead\n"
                "xml.c\n"
                "xmlTextReaderFreeNode\n"
                "```\n"
            ),
        }
        assert _extract_affected_file(bug) == "xml.c"

    def test_affected_file_crash_state_only_functions_skips(self) -> None:
        """Crash state with only function names does not trigger file strategy."""
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [],
            "details": (
                "```\n"
                "Crash type: Heap-buffer-overflow READ 2\n"
                "Crash state:\n"
                "decompress_smooth_data\n"
                "process_data_context_main\n"
                "jpeg_read_scanlines\n"
                "```\n"
            ),
            "affected": [
                {"package": {"name": "libjpeg-turbo", "ecosystem": "OSS-Fuzz"}}
            ],
        }
        # No file in crash state -> falls through to package name
        assert _extract_affected_file(bug) == "libjpeg-turbo"

    def test_affected_file_from_package_name_fallback(self) -> None:
        """When no file is found anywhere, package name is returned."""
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [],
            "details": "",
            "affected": [{"package": {"name": "libpng", "ecosystem": "OSS-Fuzz"}}],
        }
        assert _extract_affected_file(bug) == "libpng"

    def test_affected_file_db_specific_takes_priority_over_crash_state(self) -> None:
        """Strategy 1 (db_specific) beats Strategy 2 (crash state)."""
        bug: dict[str, Any] = {
            "database_specific": {"affected_file": "explicit.c"},
            "references": [],
            "details": ("```\nCrash state:\nsome_func\nother.c\n```\n"),
        }
        assert _extract_affected_file(bug) == "explicit.c"

    def test_affected_file_crash_state_beats_reference_url(self) -> None:
        """Strategy 2 (crash state file) beats Strategy 3 (reference URL)."""
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [
                {"url": "https://github.com/foo/bar/blob/main/src/other.c"},
            ],
            "details": (
                "```\nCrash type: foo\nCrash state:\nmy_func\ndecompress_yuv.cc\n```\n"
            ),
        }
        assert _extract_affected_file(bug) == "decompress_yuv.cc"

    def test_affected_file_no_affected_block_returns_unknown(self) -> None:
        """Completely empty bug with no useful fields returns 'unknown'."""
        bug: dict[str, Any] = {
            "database_specific": {},
            "references": [],
            "details": "",
            "affected": [],
        }
        assert _extract_affected_file(bug) == "unknown"

    def test_affected_file_real_osv_2021_609_shape(self) -> None:
        """Mirrors the structure of OSV-2021-609 (libjpeg-turbo compress.cc)."""
        bug: dict[str, Any] = {
            "id": "OSV-2021-609",
            "summary": "Heap-buffer-overflow in get_word_rgb_row",
            "details": (
                "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32964\n\n"
                "```\n"
                "Crash type: Heap-buffer-overflow WRITE 1\n"
                "Crash state:\n"
                "get_word_rgb_row\n"
                "tjLoadImage\n"
                "compress.cc\n"
                "```\n"
            ),
            "references": [
                {
                    "type": "REPORT",
                    "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=32964",
                }
            ],
            "database_specific": {},
            "affected": [
                {
                    "package": {"name": "libjpeg-turbo", "ecosystem": "OSS-Fuzz"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/libjpeg-turbo/libjpeg-turbo",
                            "events": [
                                {
                                    "introduced": "d2d4465548902cebba3384480f19578059767d59"
                                },
                                {"fixed": "f35fd27ec641c42d6b115bfa595e483ec58188d2"},
                            ],
                        }
                    ],
                    "database_specific": {
                        "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/libjpeg-turbo/OSV-2021-609.yaml"
                    },
                }
            ],
        }
        assert _extract_affected_file(bug) == "compress.cc"

    def test_affected_file_real_osv_2017_41_shape(self) -> None:
        """Mirrors OSV-2017-41 (libpng, no file in crash state) -> package name."""
        bug: dict[str, Any] = {
            "id": "OSV-2017-41",
            "summary": "Heap-buffer-overflow in OSS_FUZZ_png_combine_row",
            "details": (
                "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=3606\n\n"
                "```\n"
                "Crash type: Heap-buffer-overflow WRITE 4\n"
                "Crash state:\n"
                "OSS_FUZZ_png_combine_row\n"
                "OSS_FUZZ_png_read_row\n"
                "_start\n"
                "```\n"
            ),
            "references": [
                {
                    "type": "REPORT",
                    "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=3606",
                }
            ],
            "database_specific": {},
            "affected": [
                {
                    "package": {"name": "libpng", "ecosystem": "OSS-Fuzz"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "repo": "https://github.com/glennrp/libpng.git",
                            "events": [
                                {
                                    "introduced": "ab791fc9d69580c1982af726c9f61b533357234f"
                                },
                                {"fixed": "a3d1057a735d923626f1f6bdc0f662a13d0cba6f"},
                            ],
                        }
                    ],
                    "database_specific": {
                        "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/libpng/OSV-2017-41.yaml"
                    },
                }
            ],
        }
        # No file in crash state (only function names), fallback to package name
        assert _extract_affected_file(bug) == "libpng"

    def test_difficulty_easy(self) -> None:
        bug: dict[str, Any] = {"database_specific": {"lines_changed_in_fix": 2}}
        assert _estimate_difficulty(bug) == Difficulty.EASY

    def test_difficulty_medium(self) -> None:
        bug: dict[str, Any] = {"database_specific": {"lines_changed_in_fix": 15}}
        assert _estimate_difficulty(bug) == Difficulty.MEDIUM

    def test_difficulty_hard(self) -> None:
        bug: dict[str, Any] = {"database_specific": {"lines_changed_in_fix": 100}}
        assert _estimate_difficulty(bug) == Difficulty.HARD

    def test_difficulty_default(self) -> None:
        bug: dict[str, Any] = {"database_specific": {}}
        assert _estimate_difficulty(bug) == Difficulty.MEDIUM


# ---------------------------------------------------------------------------
# Tests: fetch_ossfuzz_bugs (mocked HTTP)
# ---------------------------------------------------------------------------


class TestFetchOssfuzzBugs:
    def test_fetches_and_caches(self, tmp_path: Path) -> None:
        fake_response = {
            "vulns": [_make_osv_bug(), _make_osv_bug(bug_id="OSS-FUZZ-99999")]
        }
        response_bytes = json.dumps(fake_response).encode()

        with patch(
            "parser_security_eval.dataset.ossfuzz.urllib.request.urlopen"
        ) as mock_urlopen:
            mock_resp = mock_urlopen.return_value.__enter__.return_value
            mock_resp.read.return_value = response_bytes
            bugs = fetch_ossfuzz_bugs("libpng", tmp_path)

        assert len(bugs) == 2
        # Verify cache was written
        cache_file = tmp_path / "osv_libpng.json"
        assert cache_file.exists()

    def test_uses_cache(self, tmp_path: Path) -> None:
        cached_bugs = [_make_osv_bug()]
        cache_file = tmp_path / "osv_libpng.json"
        cache_file.write_text(json.dumps(cached_bugs))

        # Should not call urlopen at all
        with patch(
            "parser_security_eval.dataset.ossfuzz.urllib.request.urlopen"
        ) as mock_urlopen:
            bugs = fetch_ossfuzz_bugs("libpng", tmp_path)
            mock_urlopen.assert_not_called()

        assert len(bugs) == 1

    def test_pagination(self, tmp_path: Path) -> None:
        page1 = {"vulns": [_make_osv_bug(bug_id="BUG-1")], "next_page_token": "tok2"}
        page2 = {"vulns": [_make_osv_bug(bug_id="BUG-2")]}

        responses = iter([json.dumps(page1).encode(), json.dumps(page2).encode()])

        with patch(
            "parser_security_eval.dataset.ossfuzz.urllib.request.urlopen"
        ) as mock_urlopen:
            mock_resp = mock_urlopen.return_value.__enter__.return_value
            mock_resp.read.side_effect = responses
            bugs = fetch_ossfuzz_bugs("libpng", tmp_path)

        assert len(bugs) == 2
        assert bugs[0]["id"] == "BUG-1"
        assert bugs[1]["id"] == "BUG-2"


# ---------------------------------------------------------------------------
# Tests: import_ossfuzz_target
# ---------------------------------------------------------------------------


class TestImportOssfuzzTarget:
    def test_basic_import(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        target = import_ossfuzz_target("libpng", ossfuzz_repo, targets_dir)

        assert target.name == "libpng"
        assert target.language == "c"
        assert target.ossfuzz_project == "libpng"
        assert target.format_type == "binary-image"
        assert target.dockerfile_path == Path("Dockerfile")
        assert target.build_sh_path == Path("build.sh")
        assert target.corpus_dir == Path("corpus")
        assert target.dictionary_path == Path("png.dict")

        # Verify files were copied
        dst = targets_dir / "libpng"
        assert (dst / "Dockerfile").exists()
        assert (dst / "build.sh").exists()
        assert (dst / "metadata.yaml").exists()
        assert (dst / "corpus" / "seed1.png").exists()
        assert (dst / "png.dict").exists()

    def test_metadata_yaml_content(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        import_ossfuzz_target("libpng", ossfuzz_repo, targets_dir)

        metadata_text = (targets_dir / "libpng" / "metadata.yaml").read_text()
        assert "name: libpng" in metadata_text
        assert "language: c" in metadata_text
        assert "address" in metadata_text
        assert "undefined" in metadata_text
        assert "format_type: binary-image" in metadata_text
        assert "ossfuzz_project: libpng" in metadata_text
        assert "has_corpus: True" in metadata_text
        assert "has_dictionary: True" in metadata_text

    def test_minimal_project(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        """Import a project with no corpus/dict."""
        targets_dir = tmp_path / "targets"
        target = import_ossfuzz_target("libxml2", ossfuzz_repo, targets_dir)
        assert target.corpus_dir is None
        assert target.dictionary_path is None

    def test_missing_project_raises(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            import_ossfuzz_target("nonexistent", ossfuzz_repo, tmp_path)

    def test_missing_dockerfile_raises(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        proj = repo / "projects" / "bad"
        proj.mkdir(parents=True)
        (proj / "build.sh").write_text("#!/bin/bash\n")
        with pytest.raises(FileNotFoundError, match="Dockerfile"):
            import_ossfuzz_target("bad", repo, tmp_path / "targets")

    def test_missing_build_sh_raises(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        proj = repo / "projects" / "bad"
        proj.mkdir(parents=True)
        (proj / "Dockerfile").write_text("FROM base\n")
        with pytest.raises(FileNotFoundError, match="build.sh"):
            import_ossfuzz_target("bad", repo, tmp_path / "targets")

    def test_dockerfile_embedded_build_sh(
        self, ossfuzz_repo: Path, tmp_path: Path
    ) -> None:
        """Import a project whose Dockerfile creates build.sh at image build time."""
        targets_dir = tmp_path / "targets"
        target = import_ossfuzz_target("embedded_build", ossfuzz_repo, targets_dir)

        assert target.name == "embedded_build"
        dst = targets_dir / "embedded_build"
        assert (dst / "Dockerfile").exists()
        assert (dst / "build.sh").exists()
        assert (dst / "metadata.yaml").exists()

        # Stub build.sh should be executable and mention "stub"
        build_sh_text = (dst / "build.sh").read_text()
        assert "stub" in build_sh_text.lower()

        # Metadata should record the source
        metadata_text = (dst / "metadata.yaml").read_text()
        assert "build_sh_source: dockerfile" in metadata_text

    def test_dockerfile_embedded_build_sh_is_executable(
        self, ossfuzz_repo: Path, tmp_path: Path
    ) -> None:
        import stat

        targets_dir = tmp_path / "targets"
        import_ossfuzz_target("embedded_build", ossfuzz_repo, targets_dir)
        build_sh = targets_dir / "embedded_build" / "build.sh"
        assert build_sh.stat().st_mode & stat.S_IXUSR

    def test_copies_extra_project_files(
        self, ossfuzz_repo: Path, tmp_path: Path
    ) -> None:
        """Extra files (harnesses, headers, subdirs) are copied from oss-fuzz."""
        targets_dir = tmp_path / "targets"
        import_ossfuzz_target("file", ossfuzz_repo, targets_dir)

        dst = targets_dir / "file"
        assert (dst / "Dockerfile").exists()
        assert (dst / "build.sh").exists()
        assert (dst / "fuzzer_temp_file.h").exists()
        assert (dst / "magic_fuzzer.cc").exists()
        assert (dst / "pdf_seeds" / "sample.pdf").exists()
        # project.yaml should NOT be copied (converted to metadata.yaml)
        assert not (dst / "project.yaml").exists()


# ---------------------------------------------------------------------------
# Tests: _dockerfile_creates_build_sh
# ---------------------------------------------------------------------------


class TestDockerfileCreatesBuildSh:
    def test_cp_pattern(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text(
            "FROM gcr.io/oss-fuzz-base/base-builder\n"
            "RUN cp $SRC/poppler/test/ossfuzz/build_fuzzers.sh $SRC/build.sh\n"
        )
        assert _dockerfile_creates_build_sh(df) is True

    def test_no_build_sh_reference(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM gcr.io/oss-fuzz-base/base-builder\nRUN make\n")
        assert _dockerfile_creates_build_sh(df) is False

    def test_copy_instruction(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM gcr.io/oss-fuzz-base/base-builder\nCOPY build.sh $SRC/\n")
        assert _dockerfile_creates_build_sh(df) is True

    def test_mv_pattern(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text(
            "FROM gcr.io/oss-fuzz-base/base-builder\n"
            "RUN mv /tmp/build_fuzzers.sh $SRC/build.sh\n"
        )
        assert _dockerfile_creates_build_sh(df) is True

    def test_cp_build_sh_to_src_dir(self, tmp_path: Path) -> None:
        """Matches `cp .../build.sh $SRC/` (dest is directory, not full path)."""
        df = tmp_path / "Dockerfile"
        df.write_text(
            "FROM gcr.io/oss-fuzz-base/base-builder\n"
            "RUN git clone --depth 1 https://example.com/libconfig.git libconfig \\\n"
            "        && cp libconfig/fuzz/build.sh $SRC/\n"
        )
        assert _dockerfile_creates_build_sh(df) is True


# ---------------------------------------------------------------------------
# Tests: list_parser_projects
# ---------------------------------------------------------------------------


class TestListParserProjects:
    def test_lists_parser_projects(self, ossfuzz_repo: Path) -> None:
        projects = list_parser_projects(ossfuzz_repo)
        assert "libpng" in projects
        assert "libxml2" in projects
        assert "my_json_lib" in projects  # keyword match on "json"
        assert "unrelated_project" not in projects

    def test_sorted_output(self, ossfuzz_repo: Path) -> None:
        projects = list_parser_projects(ossfuzz_repo)
        assert projects == sorted(projects)

    def test_missing_projects_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            list_parser_projects(tmp_path / "nonexistent")


# ---------------------------------------------------------------------------
# Tests: _is_parser_project heuristic
# ---------------------------------------------------------------------------


class TestIsParserProject:
    def test_allowlist_match(self) -> None:
        assert _is_parser_project("libpng") is True
        assert _is_parser_project("libxml2") is True
        assert _is_parser_project("zstd") is True

    def test_keyword_match(self) -> None:
        assert _is_parser_project("my-xml-parser") is True
        assert _is_parser_project("cool_json_thing") is True
        assert _is_parser_project("image_decoder") is True

    def test_no_match(self) -> None:
        assert _is_parser_project("linux_kernel") is False
        assert _is_parser_project("my_game") is False


# ---------------------------------------------------------------------------
# Tests: _detect_format_type
# ---------------------------------------------------------------------------


class TestDetectFormatType:
    def test_known_types(self) -> None:
        assert _detect_format_type("libpng") == "binary-image"
        assert _detect_format_type("libxml2") == "text-markup"
        assert _detect_format_type("jsoncpp") == "text-data"
        assert _detect_format_type("protobuf") == "binary-serialization"
        assert _detect_format_type("mupdf") == "document"
        assert _detect_format_type("openssl") == "protocol"
        assert _detect_format_type("zstd") == "compression"
        assert _detect_format_type("freetype2") == "font"
        assert _detect_format_type("pcre2") == "regex"
        assert _detect_format_type("ffmpeg") == "media"
        assert _detect_format_type("sqlite3") == "database"
        assert _detect_format_type("libpcap") == "network-capture"

    def test_unknown_fallback(self) -> None:
        assert _detect_format_type("completely_unknown") == "unknown"


# ---------------------------------------------------------------------------
# Tests: _read_project_yaml
# ---------------------------------------------------------------------------


class TestReadProjectYaml:
    def test_simple_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "project.yaml"
        yaml_file.write_text(
            "language: c\n"
            "sanitizers:\n"
            "  - address\n"
            "  - undefined\n"
            "fuzzing_engines:\n"
            "  - libfuzzer\n"
        )
        result = _read_project_yaml(yaml_file)
        assert result["language"] == "c"
        assert result["sanitizers"] == ["address", "undefined"]
        assert result["fuzzing_engines"] == ["libfuzzer"]

    def test_inline_list(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "project.yaml"
        yaml_file.write_text("sanitizers: [address, memory]\n")
        result = _read_project_yaml(yaml_file)
        assert result["sanitizers"] == ["address", "memory"]

    def test_comments_and_blanks(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "project.yaml"
        yaml_file.write_text("# A comment\nlanguage: cpp\n\n# Another\n")
        result = _read_project_yaml(yaml_file)
        assert result["language"] == "cpp"


# ---------------------------------------------------------------------------
# Tests: clone_ossfuzz_repo
# ---------------------------------------------------------------------------


class TestCloneOssfuzzRepo:
    def test_clones_fresh_repo(self, tmp_path: Path) -> None:
        """First call should run git clone."""
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "oss-fuzz"

        with patch("parser_security_eval.dataset.ossfuzz.subprocess.run") as mock_run:
            # After clone, create the expected directory structure.
            def _side_effect(*args: Any, **kwargs: Any) -> None:
                (repo_dir / "projects").mkdir(parents=True, exist_ok=True)
                (repo_dir / ".git").mkdir(parents=True, exist_ok=True)

            mock_run.side_effect = _side_effect

            result = clone_ossfuzz_repo(cache_dir)

        assert result == repo_dir
        # Should have called clone (first call) then sparse-checkout (second call).
        assert mock_run.call_count == 2
        first_call_args = mock_run.call_args_list[0][0][0]
        assert "clone" in first_call_args

    def test_pulls_existing_repo(self, tmp_path: Path) -> None:
        """Second call (repo exists) should run git pull."""
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "oss-fuzz"
        (repo_dir / ".git").mkdir(parents=True)
        (repo_dir / "projects").mkdir(parents=True)

        with patch("parser_security_eval.dataset.ossfuzz.subprocess.run") as mock_run:
            result = clone_ossfuzz_repo(cache_dir)

        assert result == repo_dir
        assert mock_run.call_count == 1
        call_args = mock_run.call_args_list[0][0][0]
        assert "pull" in call_args

    def test_raises_if_projects_missing(self, tmp_path: Path) -> None:
        """Should raise if projects/ dir doesn't exist after clone."""
        cache_dir = tmp_path / "cache"
        repo_dir = cache_dir / "oss-fuzz"

        with patch("parser_security_eval.dataset.ossfuzz.subprocess.run") as mock_run:
            # Create .git but NOT projects/
            def _side_effect(*args: Any, **kwargs: Any) -> None:
                (repo_dir / ".git").mkdir(parents=True, exist_ok=True)

            mock_run.side_effect = _side_effect

            with pytest.raises(FileNotFoundError, match="projects/"):
                clone_ossfuzz_repo(cache_dir)


# ---------------------------------------------------------------------------
# Tests: bootstrap_targets
# ---------------------------------------------------------------------------


class TestBootstrapTargets:
    def test_success(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        result = bootstrap_targets(["libpng", "libxml2"], ossfuzz_repo, targets_dir)
        assert result.succeeded == ["libpng", "libxml2"]
        assert result.skipped == []
        assert result.failed == {}
        assert (targets_dir / "libpng" / "Dockerfile").exists()
        assert (targets_dir / "libxml2" / "Dockerfile").exists()

    def test_skip_existing(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        (targets_dir / "libpng").mkdir(parents=True)

        result = bootstrap_targets(["libpng"], ossfuzz_repo, targets_dir)
        assert result.skipped == ["libpng"]
        assert result.succeeded == []

    def test_force_overwrite(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        (targets_dir / "libpng").mkdir(parents=True)

        result = bootstrap_targets(["libpng"], ossfuzz_repo, targets_dir, force=True)
        assert result.succeeded == ["libpng"]
        assert result.skipped == []
        assert (targets_dir / "libpng" / "Dockerfile").exists()

    def test_missing_project_failure(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        result = bootstrap_targets(["nonexistent_project"], ossfuzz_repo, targets_dir)
        assert result.succeeded == []
        assert "nonexistent_project" in result.failed

    def test_deduplication(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        result = bootstrap_targets(
            ["libpng", "libpng", "libpng"], ossfuzz_repo, targets_dir
        )
        assert result.succeeded == ["libpng"]
        assert len(result.skipped) == 0

    def test_executable_bit(self, ossfuzz_repo: Path, tmp_path: Path) -> None:
        targets_dir = tmp_path / "targets"
        bootstrap_targets(["libpng"], ossfuzz_repo, targets_dir)
        import stat

        build_sh = targets_dir / "libpng" / "build.sh"
        mode = build_sh.stat().st_mode
        assert mode & stat.S_IXUSR

    def test_summary_property(self) -> None:
        result = BootstrapResult(
            succeeded=["a", "b"],
            skipped=["c"],
            failed={"d": "some error"},
        )
        summary = result.summary
        assert "2 succeeded" in summary
        assert "1 skipped" in summary
        assert "1 failed" in summary
        assert "d: some error" in summary
