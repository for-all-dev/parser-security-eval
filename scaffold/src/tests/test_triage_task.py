"""Tests for the crash triage Inspect-AI task."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from inspect_ai import Task
from inspect_ai.scorer import Target

from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
    VulnerabilityRecord,
)
from parser_security_eval.tasks.triage import (
    _build_sample_input,
    _cwe_matches,
    _get_all_parents,
    _load_records,
    _normalize_cwe,
    _parse_triage_output,
    crash_triage,
    cwe_scorer,
    load_triage_dataset,
    severity_scorer,
    triage_scorer,
    triage_solver,
)

# ---------------------------------------------------------------------------
# _normalize_cwe
# ---------------------------------------------------------------------------


class TestNormalizeCwe:
    def test_standard_format(self) -> None:
        assert _normalize_cwe("CWE-416") == "CWE-416"

    def test_lowercase(self) -> None:
        assert _normalize_cwe("cwe-125") == "CWE-125"

    def test_number_only(self) -> None:
        assert _normalize_cwe("787") == "CWE-787"

    def test_spaces(self) -> None:
        assert _normalize_cwe(" CWE-119 ") == "CWE-119"

    def test_no_number(self) -> None:
        assert _normalize_cwe("unknown") == "UNKNOWN"


# ---------------------------------------------------------------------------
# _get_all_parents
# ---------------------------------------------------------------------------


class TestGetAllParents:
    def test_direct_parent(self) -> None:
        parents = _get_all_parents("CWE-787")
        assert "CWE-119" in parents

    def test_transitive_parents(self) -> None:
        # CWE-122 -> CWE-787 -> CWE-119
        parents = _get_all_parents("CWE-122")
        assert "CWE-787" in parents
        assert "CWE-119" in parents

    def test_no_parents(self) -> None:
        parents = _get_all_parents("CWE-119")
        assert len(parents) == 0

    def test_unknown_cwe(self) -> None:
        parents = _get_all_parents("CWE-9999")
        assert len(parents) == 0


# ---------------------------------------------------------------------------
# _cwe_matches
# ---------------------------------------------------------------------------


class TestCweMatches:
    def test_exact_match(self) -> None:
        assert _cwe_matches("CWE-416", "CWE-416") is True

    def test_case_insensitive_match(self) -> None:
        assert _cwe_matches("cwe-416", "CWE-416") is True

    def test_parent_match_predicted_is_parent(self) -> None:
        # CWE-119 is parent of CWE-787
        assert _cwe_matches("CWE-119", "CWE-787") is True

    def test_parent_match_gt_is_parent(self) -> None:
        # CWE-119 is parent of CWE-787
        assert _cwe_matches("CWE-787", "CWE-119") is True

    def test_transitive_parent_match(self) -> None:
        # CWE-122 -> CWE-787 -> CWE-119
        assert _cwe_matches("CWE-119", "CWE-122") is True

    def test_no_match(self) -> None:
        assert _cwe_matches("CWE-416", "CWE-125") is False

    def test_sibling_no_match(self) -> None:
        # CWE-125 and CWE-787 are siblings (both children of CWE-119)
        assert _cwe_matches("CWE-125", "CWE-787") is False


# ---------------------------------------------------------------------------
# _parse_triage_output
# ---------------------------------------------------------------------------


class TestParseTriageOutput:
    def test_json_in_code_block(self) -> None:
        text = """Here is my analysis:

```json
{
  "cwe": "CWE-416",
  "severity": "high",
  "root_cause": "Use after free in parser",
  "explanation": "The parser frees memory then accesses it"
}
```
"""
        result = _parse_triage_output(text)
        assert result["cwe"] == "CWE-416"
        assert result["severity"] == "high"
        assert result["root_cause"] == "Use after free in parser"

    def test_raw_json(self) -> None:
        text = '{"cwe": "CWE-125", "severity": "medium", "root_cause": "OOB read", "explanation": "Buffer overread"}'
        result = _parse_triage_output(text)
        assert result["cwe"] == "CWE-125"

    def test_json_with_surrounding_text(self) -> None:
        text = 'Analysis complete. {"cwe": "CWE-787", "severity": "critical", "root_cause": "OOB write", "explanation": "Heap overflow"} End.'
        result = _parse_triage_output(text)
        assert result["cwe"] == "CWE-787"

    def test_no_json(self) -> None:
        text = "I think this is a buffer overflow."
        result = _parse_triage_output(text)
        assert result == {}

    def test_invalid_json(self) -> None:
        text = "```json\n{invalid json}\n```"
        result = _parse_triage_output(text)
        assert result == {}

    def test_code_block_without_json_tag(self) -> None:
        text = '```\n{"cwe": "CWE-476", "severity": "low", "root_cause": "null deref", "explanation": "details"}\n```'
        result = _parse_triage_output(text)
        assert result["cwe"] == "CWE-476"


# ---------------------------------------------------------------------------
# _load_records
# ---------------------------------------------------------------------------


class TestLoadRecords:
    def test_loads_from_metadata(self, tmp_path: Path) -> None:
        metadata = {
            "version": "0.1.0",
            "total_vulnerabilities": 1,
            "targets": ["libpng"],
            "records": [
                {
                    "id": "CVE-2019-7317",
                    "target": "libpng",
                    "cwe": "CWE-416",
                    "severity": "high",
                    "difficulty": "medium",
                    "crash_type": "heap-use-after-free",
                    "sanitizer": "address",
                    "affected_file": "png.c",
                    "root_cause": "Use after free in png_image_free",
                }
            ],
        }
        (tmp_path / "metadata.json").write_text(json.dumps(metadata))

        records = _load_records(tmp_path)
        assert len(records) == 1
        assert records[0].id == "CVE-2019-7317"
        assert records[0].cwe == "CWE-416"

    def test_filter_by_target(self, tmp_path: Path) -> None:
        metadata = {
            "records": [
                {
                    "id": "vuln-1",
                    "target": "libpng",
                    "severity": "high",
                    "difficulty": "easy",
                    "crash_type": "oob-read",
                    "sanitizer": "address",
                    "affected_file": "a.c",
                },
                {
                    "id": "vuln-2",
                    "target": "libxml2",
                    "severity": "medium",
                    "difficulty": "medium",
                    "crash_type": "oob-write",
                    "sanitizer": "address",
                    "affected_file": "b.c",
                },
            ],
        }
        (tmp_path / "metadata.json").write_text(json.dumps(metadata))

        records = _load_records(tmp_path, target="libpng")
        assert len(records) == 1
        assert records[0].target == "libpng"

    def test_missing_metadata(self, tmp_path: Path) -> None:
        records = _load_records(tmp_path)
        assert records == []


# ---------------------------------------------------------------------------
# _build_sample_input
# ---------------------------------------------------------------------------


class TestBuildSampleInput:
    def test_basic_fields(self) -> None:
        record = VulnerabilityRecord(
            id="CVE-2019-7317",
            target="libpng",
            cwe="CWE-416",
            severity=Severity.HIGH,
            difficulty=Difficulty.MEDIUM,
            crash_type="heap-use-after-free",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="png.c",
            affected_function="png_image_free",
        )
        text = _build_sample_input(record, Path("/tmp/bench"))
        assert "CVE-2019-7317" in text
        assert "libpng" in text
        assert "heap-use-after-free" in text
        assert "png.c" in text
        assert "png_image_free" in text

    def test_includes_crash_report(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "reports"
        crash_dir.mkdir()
        (crash_dir / "crash.txt").write_text(
            "ERROR: AddressSanitizer: heap-use-after-free"
        )

        record = VulnerabilityRecord(
            id="test-1",
            target="libpng",
            severity=Severity.HIGH,
            difficulty=Difficulty.EASY,
            crash_type="heap-use-after-free",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="png.c",
            crash_report_path=Path("reports/crash.txt"),
        )
        text = _build_sample_input(record, tmp_path)
        assert "AddressSanitizer" in text


# ---------------------------------------------------------------------------
# load_triage_dataset
# ---------------------------------------------------------------------------


class TestLoadTriageDataset:
    def test_creates_samples(self, tmp_path: Path) -> None:
        metadata = {
            "records": [
                {
                    "id": "CVE-2019-7317",
                    "target": "libpng",
                    "cwe": "CWE-416",
                    "severity": "high",
                    "difficulty": "medium",
                    "crash_type": "heap-use-after-free",
                    "sanitizer": "address",
                    "affected_file": "png.c",
                    "root_cause": "Use after free in png_image_free",
                }
            ],
        }
        (tmp_path / "metadata.json").write_text(json.dumps(metadata))

        samples = load_triage_dataset(str(tmp_path))
        assert len(samples) == 1
        assert samples[0].id == "CVE-2019-7317"

        # Check target contains ground truth JSON
        gt = json.loads(samples[0].target)
        assert gt["cwe"] == "CWE-416"
        assert gt["severity"] == "high"
        assert gt["root_cause"] == "Use after free in png_image_free"

    def test_empty_benchmark(self, tmp_path: Path) -> None:
        samples = load_triage_dataset(str(tmp_path))
        assert samples == []

    def test_metadata_fields(self, tmp_path: Path) -> None:
        metadata = {
            "records": [
                {
                    "id": "test-1",
                    "target": "libpng",
                    "cwe": "CWE-125",
                    "severity": "medium",
                    "difficulty": "easy",
                    "crash_type": "oob-read",
                    "sanitizer": "address",
                    "affected_file": "a.c",
                    "root_cause": "Missing bounds check",
                }
            ],
        }
        (tmp_path / "metadata.json").write_text(json.dumps(metadata))

        samples = load_triage_dataset(str(tmp_path))
        assert samples[0].metadata is not None
        assert samples[0].metadata["cwe"] == "CWE-125"
        assert samples[0].metadata["severity"] == "medium"


# ---------------------------------------------------------------------------
# triage_solver
# ---------------------------------------------------------------------------


class TestTriageSolver:
    def test_returns_solver(self) -> None:
        s = triage_solver()
        # The @solver decorator returns a Solver; just verify it's callable
        assert callable(s)


# ---------------------------------------------------------------------------
# triage_scorer
# ---------------------------------------------------------------------------


class TestTriageScorer:
    def test_returns_list_of_scorers(self) -> None:
        scorers = triage_scorer()
        assert isinstance(scorers, list)
        assert len(scorers) == 3


# ---------------------------------------------------------------------------
# CWE scorer unit tests
# ---------------------------------------------------------------------------


class TestCweScorer:
    @pytest.fixture
    def scorer_fn(self):
        return cwe_scorer()

    def _make_state(self, completion: str) -> MagicMock:
        state = MagicMock()
        state.output.completion = completion
        return state

    def _make_target(
        self, cwe: str, severity: str = "high", root_cause: str = ""
    ) -> Target:
        return Target(
            json.dumps({"cwe": cwe, "severity": severity, "root_cause": root_cause})
        )

    @pytest.mark.asyncio
    async def test_exact_match(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state(
            '```json\n{"cwe": "CWE-416", "severity": "high", "root_cause": "uaf", "explanation": "x"}\n```'
        )
        target = self._make_target("CWE-416")
        result = await scorer_fn(state, target)
        assert result.value == "C"

    @pytest.mark.asyncio
    async def test_parent_match(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        # CWE-119 is parent of CWE-787
        state = self._make_state(
            '{"cwe": "CWE-119", "severity": "high", "root_cause": "x", "explanation": "x"}'
        )
        target = self._make_target("CWE-787")
        result = await scorer_fn(state, target)
        assert result.value == "C"

    @pytest.mark.asyncio
    async def test_mismatch(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state(
            '{"cwe": "CWE-416", "severity": "high", "root_cause": "x", "explanation": "x"}'
        )
        target = self._make_target("CWE-125")
        result = await scorer_fn(state, target)
        assert result.value == "I"

    @pytest.mark.asyncio
    async def test_no_output(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state("I don't know")
        target = self._make_target("CWE-416")
        result = await scorer_fn(state, target)
        assert result.value == "I"

    @pytest.mark.asyncio
    async def test_no_ground_truth(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state(
            '{"cwe": "CWE-416", "severity": "high", "root_cause": "x", "explanation": "x"}'
        )
        target = self._make_target("")
        result = await scorer_fn(state, target)
        assert result.value == "I"


# ---------------------------------------------------------------------------
# Severity scorer unit tests
# ---------------------------------------------------------------------------


class TestSeverityScorer:
    @pytest.fixture
    def scorer_fn(self):
        return severity_scorer()

    def _make_state(self, completion: str) -> MagicMock:
        state = MagicMock()
        state.output.completion = completion
        return state

    def _make_target(self, severity: str) -> Target:
        return Target(
            json.dumps({"cwe": "CWE-416", "severity": severity, "root_cause": ""})
        )

    @pytest.mark.asyncio
    async def test_exact_match(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state(
            '{"cwe": "CWE-416", "severity": "high", "root_cause": "x", "explanation": "x"}'
        )
        target = self._make_target("high")
        result = await scorer_fn(state, target)
        assert result.value == "C"

    @pytest.mark.asyncio
    async def test_mismatch(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state(
            '{"cwe": "CWE-416", "severity": "low", "root_cause": "x", "explanation": "x"}'
        )
        target = self._make_target("high")
        result = await scorer_fn(state, target)
        assert result.value == "I"

    @pytest.mark.asyncio
    async def test_invalid_severity(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state(
            '{"cwe": "CWE-416", "severity": "extreme", "root_cause": "x", "explanation": "x"}'
        )
        target = self._make_target("high")
        result = await scorer_fn(state, target)
        assert result.value == "I"

    @pytest.mark.asyncio
    async def test_no_output(self, scorer_fn) -> None:  # type: ignore[no-untyped-def]
        state = self._make_state("No structured output here")
        target = self._make_target("high")
        result = await scorer_fn(state, target)
        assert result.value == "I"


# ---------------------------------------------------------------------------
# crash_triage task
# ---------------------------------------------------------------------------


class TestCrashTriageTask:
    def test_empty_dataset_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="empty"):
            crash_triage(benchmark_dir=str(tmp_path))

    def test_returns_task_with_data(self, tmp_path: Path) -> None:
        metadata = {
            "records": [
                {
                    "id": "test-1",
                    "target": "libpng",
                    "cwe": "CWE-416",
                    "severity": "high",
                    "difficulty": "medium",
                    "crash_type": "heap-use-after-free",
                    "sanitizer": "address",
                    "affected_file": "png.c",
                    "root_cause": "UAF in free path",
                }
            ],
        }
        (tmp_path / "metadata.json").write_text(json.dumps(metadata))

        t = crash_triage(benchmark_dir=str(tmp_path))
        assert isinstance(t, Task)
