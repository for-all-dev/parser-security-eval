"""Tests for Pydantic data models."""

import pytest

from parser_security_eval.models.scoring import PatchResult, ScoringResult
from parser_security_eval.models.target import ParserTarget
from parser_security_eval.models.vulnerability import (
    CrashReport,
    Difficulty,
    Sanitizer,
    Severity,
    VulnerabilityRecord,
)


class TestVulnerabilityRecord:
    def test_create_minimal(self) -> None:
        record = VulnerabilityRecord(
            id="CVE-2019-7317",
            target="libpng",
            severity=Severity.HIGH,
            difficulty=Difficulty.MEDIUM,
            crash_type="heap-use-after-free",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="png.c",
        )
        assert record.id == "CVE-2019-7317"
        assert record.target == "libpng"

    def test_create_full(self) -> None:
        record = VulnerabilityRecord(
            id="oss-fuzz-12345",
            target="libxml2",
            cwe="CWE-125",
            severity=Severity.MEDIUM,
            difficulty=Difficulty.EASY,
            crash_type="heap-buffer-overflow",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="parser.c",
            affected_function="xmlParseElement",
            lines_changed_in_fix=3,
            root_cause="Missing bounds check in element name parsing",
            tags=["oob-read", "xml-parser"],
        )
        assert record.cwe == "CWE-125"
        assert len(record.tags) == 2


class TestCrashReport:
    def test_create(self) -> None:
        report = CrashReport(
            crash_type="heap-buffer-overflow",
            sanitizer=Sanitizer.ADDRESS,
            stack_trace="#0 0x... in xmlParseElement\n#1 0x...",
            asan_output="READ of size 1 at 0x...",
        )
        assert report.crash_type == "heap-buffer-overflow"


class TestParserTarget:
    def test_create(self) -> None:
        target = ParserTarget(
            name="libpng",
            format_type="binary-image",
            language="c",
            ossfuzz_project="libpng-read-fuzzer",
            dockerfile_path="Dockerfile",
            build_sh_path="build.sh",
        )
        assert target.name == "libpng"


class TestPatchResult:
    def test_success(self) -> None:
        result = PatchResult(
            patch_applies=True,
            compiles=True,
            crash_eliminated=True,
            tests_pass=True,
            diff_lines=3,
        )
        assert result.success is True

    def test_failure_compile(self) -> None:
        result = PatchResult(
            patch_applies=True,
            compiles=False,
            crash_eliminated=False,
            tests_pass=False,
            diff_lines=10,
        )
        assert result.success is False


class TestScoringResult:
    def test_success_rate(self) -> None:
        result = ScoringResult(
            total_vulnerabilities=10,
            patches_attempted=10,
            patches_compiled=8,
            crashes_eliminated=6,
            tests_passed=5,
            full_successes=3,
        )
        assert result.success_rate == pytest.approx(0.3)

    def test_empty(self) -> None:
        result = ScoringResult(
            total_vulnerabilities=0,
            patches_attempted=0,
            patches_compiled=0,
            crashes_eliminated=0,
            tests_passed=0,
            full_successes=0,
        )
        assert result.success_rate == 0.0
