"""Tests for the vulnerability patching Inspect-AI task."""

import asyncio
import json
import stat
from pathlib import Path
from inspect_ai.scorer import Score
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from parser_security_eval.tasks.patching import (
    _extract_diff,
    _patch_result_to_score,
    _resolve_fuzz_binary,
    load_patching_dataset,
    patching_solver,
    vulnerability_patching,
)
from parser_security_eval.models.scoring import PatchResult


# ---------------------------------------------------------------------------
# Minimal benchmark fixture
# ---------------------------------------------------------------------------

VULN_RECORD = {
    "id": "OSS-FUZZ-12345",
    "target": "libpng",
    "severity": "high",
    "difficulty": "medium",
    "crash_type": "heap-buffer-overflow",
    "sanitizer": "address",
    "affected_file": "pngrutil.c",
    "affected_function": "png_read_row",
    "cwe": "CWE-125",
    "root_cause": "Off-by-one in row buffer allocation",
    "crash_input_path": "libpng/OSS-FUZZ-12345/crash.png",
    "crash_report_path": "libpng/OSS-FUZZ-12345/crash_report.txt",
    "reference_patch_path": "libpng/OSS-FUZZ-12345/fix.diff",
    "vulnerable_source_ref": "abc123",
    "tags": [],
    "lines_changed_in_fix": None,
    "ossfuzz_project": None,
}

METADATA = {
    "version": "0.1.0",
    "total_vulnerabilities": 1,
    "targets": ["libpng"],
    "records": [VULN_RECORD],
}

REFERENCE_PATCH = """\
--- a/pngrutil.c
+++ b/pngrutil.c
@@ -100,7 +100,7 @@
-   buf = malloc(len);
+   buf = malloc(len + 1);
    if (!buf) return -1;
"""

CRASH_REPORT = "AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef"


def make_benchmark(tmp_path: Path) -> Path:
    """Create a minimal benchmark directory with all required files."""
    record_dir = tmp_path / "libpng" / "OSS-FUZZ-12345"
    record_dir.mkdir(parents=True)

    (tmp_path / "metadata.json").write_text(json.dumps(METADATA))
    (record_dir / "crash.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (record_dir / "crash_report.txt").write_text(CRASH_REPORT)
    (record_dir / "fix.diff").write_text(REFERENCE_PATCH)

    return tmp_path


def make_target_dir(tmp_path: Path) -> Path:
    """Create a minimal target directory with metadata.yaml."""
    target_dir = tmp_path / "targets" / "libpng"
    target_dir.mkdir(parents=True)

    (target_dir / "metadata.yaml").write_text(
        "name: libpng\nfuzz_targets:\n  - libpng_read_fuzzer\n  - libpng_colormap_fuzzer\n"
    )
    (target_dir / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    build_sh = target_dir / "build.sh"
    build_sh.write_text("#!/bin/bash -eu\necho ok\n")
    build_sh.chmod(build_sh.stat().st_mode | stat.S_IXUSR)

    return target_dir


# ---------------------------------------------------------------------------
# _extract_diff
# ---------------------------------------------------------------------------


class TestExtractDiff:
    def test_fenced_diff_block(self) -> None:
        text = "Here is my fix:\n```diff\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n```"
        result = _extract_diff(text)
        assert result is not None
        assert "--- a/f.c" in result
        assert "+new" in result

    def test_fenced_generic_block(self) -> None:
        text = "Fix:\n```\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n```"
        result = _extract_diff(text)
        assert result is not None
        assert "--- a/f.c" in result

    def test_bare_diff(self) -> None:
        text = "Analysis...\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n"
        result = _extract_diff(text)
        assert result is not None
        assert "+++ b/f.c" in result

    def test_no_diff_returns_none(self) -> None:
        assert _extract_diff("I cannot generate a patch.") is None

    def test_empty_string_returns_none(self) -> None:
        assert _extract_diff("") is None

    def test_prefers_fenced_over_bare(self) -> None:
        text = (
            "--- stray/line\n"
            "```diff\n--- a/real.c\n+++ b/real.c\n@@ -1 +1 @@\n-old\n+new\n```"
        )
        result = _extract_diff(text)
        assert result is not None
        assert "real.c" in result


# ---------------------------------------------------------------------------
# _patch_result_to_score
# ---------------------------------------------------------------------------


class TestPatchResultToScore:
    def _result(self, **kwargs) -> PatchResult:
        defaults = dict(
            patch_applies=True,
            compiles=True,
            crash_eliminated=True,
            tests_pass=True,
            diff_lines=5,
        )
        defaults.update(kwargs)
        return PatchResult(**defaults)

    def test_full_success(self) -> None:
        assert _patch_result_to_score(self._result()) == 1.0

    def test_tests_fail(self) -> None:
        assert _patch_result_to_score(self._result(tests_pass=False)) == 0.7

    def test_crash_not_eliminated(self) -> None:
        result = self._result(crash_eliminated=False, tests_pass=False)
        assert _patch_result_to_score(result) == 0.5

    def test_compile_fails(self) -> None:
        result = self._result(compiles=False, crash_eliminated=False, tests_pass=False)
        assert _patch_result_to_score(result) == 0.2

    def test_patch_does_not_apply(self) -> None:
        result = self._result(
            patch_applies=False,
            compiles=False,
            crash_eliminated=False,
            tests_pass=False,
        )
        assert _patch_result_to_score(result) == 0.0


# ---------------------------------------------------------------------------
# _resolve_fuzz_binary
# ---------------------------------------------------------------------------


class TestResolveFuzzBinary:
    def test_reads_first_fuzz_target(self, tmp_path: Path) -> None:
        (tmp_path / "metadata.yaml").write_text(
            "fuzz_targets:\n  - libpng_read_fuzzer\n  - libpng_colormap_fuzzer\n"
        )
        result = _resolve_fuzz_binary(tmp_path, "libpng")
        assert result == "/out/libpng_read_fuzzer"

    def test_fallback_when_no_metadata(self, tmp_path: Path) -> None:
        result = _resolve_fuzz_binary(tmp_path, "libpng")
        assert result == "/out/libpng_fuzzer"

    def test_fallback_when_fuzz_targets_empty(self, tmp_path: Path) -> None:
        (tmp_path / "metadata.yaml").write_text("fuzz_targets: []\n")
        result = _resolve_fuzz_binary(tmp_path, "zlib")
        assert result == "/out/zlib_fuzzer"


# ---------------------------------------------------------------------------
# load_patching_dataset
# ---------------------------------------------------------------------------


class TestLoadPatchingDataset:
    def test_loads_samples(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        assert len(samples) == 1
        assert samples[0].id == "OSS-FUZZ-12345"

    def test_input_contains_crash_type(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        assert "heap-buffer-overflow" in samples[0].input

    def test_input_contains_crash_report(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        assert CRASH_REPORT in samples[0].input

    def test_target_is_reference_patch(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        assert samples[0].target == REFERENCE_PATCH

    def test_metadata_contains_vuln_fields(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        meta = samples[0].metadata
        assert meta["vuln_id"] == "OSS-FUZZ-12345"
        assert meta["target"] == "libpng"
        assert meta["sanitizer"] == "address"

    def test_filter_by_target(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir), target="libpng")
        assert len(samples) == 1

        samples = load_patching_dataset(str(bdir), target="zlib")
        assert len(samples) == 0

    def test_missing_metadata_json_returns_empty(self, tmp_path: Path) -> None:
        samples = load_patching_dataset(str(tmp_path))
        assert samples == []

    def test_input_contains_cwe(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        assert "CWE-125" in samples[0].input

    def test_input_contains_affected_function(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        samples = load_patching_dataset(str(bdir))
        assert "png_read_row" in samples[0].input


# ---------------------------------------------------------------------------
# patching_solver
# ---------------------------------------------------------------------------


class TestPatchingSolver:
    def test_returns_list(self) -> None:
        solvers = patching_solver()
        assert isinstance(solvers, list)
        assert len(solvers) >= 2

    def test_contains_system_message_and_generate(self) -> None:
        # Solver names follow inspect-ai conventions
        solvers = patching_solver()
        names = [type(s).__name__ for s in solvers]
        # system_message and generate are both Solver instances
        assert len(names) == 2


# ---------------------------------------------------------------------------
# vulnerability_patching task
# ---------------------------------------------------------------------------


class TestVulnerabilityPatching:
    def test_returns_task(self, tmp_path: Path) -> None:
        from inspect_ai import Task

        bdir = make_benchmark(tmp_path)
        t = vulnerability_patching(benchmark_dir=str(bdir))
        assert isinstance(t, Task)

    def test_task_has_dataset(self, tmp_path: Path) -> None:

        bdir = make_benchmark(tmp_path)
        t = vulnerability_patching(benchmark_dir=str(bdir))
        assert t.dataset is not None

    def test_target_filter_empty_raises(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        # zlib not in benchmark — should raise ValueError with a helpful message
        with pytest.raises(ValueError, match="No vulnerability records found"):
            vulnerability_patching(benchmark_dir=str(bdir), target="zlib")

    def test_libpng_filter_finds_sample(self, tmp_path: Path) -> None:
        from inspect_ai import Task

        bdir = make_benchmark(tmp_path)
        t = vulnerability_patching(benchmark_dir=str(bdir), target="libpng")
        assert isinstance(t, Task)
        assert t.dataset is not None


# ---------------------------------------------------------------------------
# patching_scorer (integration-style with mocked score_patch)
# ---------------------------------------------------------------------------


class TestPatchingScorer:
    """Test the scorer by driving its inner score() function directly."""

    def _make_state(self, completion: str, meta: dict) -> MagicMock:
        state = MagicMock()
        state.output.completion = completion
        state.metadata = meta
        return state

    def _make_target(self) -> MagicMock:
        t = MagicMock()
        t.text = REFERENCE_PATCH
        return t

    def _run_scorer(
        self,
        completion: str,
        meta: dict,
        patch_result: PatchResult | None = None,
        tmp_path: Path | None = None,
    ) -> Score:
        from parser_security_eval.tasks.patching import patching_scorer

        scorers = patching_scorer(targets_root=str(tmp_path or Path("targets")))
        # After @scorer wrapping, scorers[0] IS the async score(state, target) callable.
        score_fn = scorers[0]

        full_result = patch_result or PatchResult(
            patch_applies=True,
            compiles=True,
            crash_eliminated=True,
            tests_pass=True,
            diff_lines=3,
        )

        with (
            patch("parser_security_eval.tasks.patching.DockerSandbox") as MockSandbox,
            patch(
                "parser_security_eval.tasks.patching.score_patch",
                new=AsyncMock(return_value=full_result),
            ),
        ):
            mock_instance = AsyncMock()
            MockSandbox.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockSandbox.return_value.__aexit__ = AsyncMock(return_value=None)

            state = self._make_state(completion, meta)
            target = self._make_target()
            return asyncio.run(score_fn(state, target))

    def _default_meta(self, benchmark_dir: str = "/tmp/bench") -> dict:
        return {
            "target": "libpng",
            "sanitizer": "address",
            "crash_input_path": "libpng/OSS-FUZZ-12345/crash.png",
            "benchmark_dir": benchmark_dir,
        }

    def test_full_success_scores_one(self, tmp_path: Path) -> None:
        completion = f"```diff\n{REFERENCE_PATCH}```"
        score = self._run_scorer(completion, self._default_meta(), tmp_path=tmp_path)
        assert score.value == 1.0

    def test_no_diff_scores_zero(self, tmp_path: Path) -> None:
        score = self._run_scorer(
            "I could not generate a fix.", self._default_meta(), tmp_path=tmp_path
        )
        assert score.value == 0.0
        assert "No unified diff" in score.explanation

    def test_missing_crash_input_scores_zero(self, tmp_path: Path) -> None:
        meta = self._default_meta()
        meta["crash_input_path"] = None
        score = self._run_scorer(
            f"```diff\n{REFERENCE_PATCH}```", meta, tmp_path=tmp_path
        )
        assert score.value == 0.0
        assert "triggering input" in score.explanation

    def test_partial_score_compile_fails(self, tmp_path: Path) -> None:
        result = PatchResult(
            patch_applies=True,
            compiles=False,
            crash_eliminated=False,
            tests_pass=False,
            diff_lines=3,
        )
        completion = f"```diff\n{REFERENCE_PATCH}```"
        score = self._run_scorer(
            completion, self._default_meta(), patch_result=result, tmp_path=tmp_path
        )
        assert score.value == 0.2

    def test_explanation_contains_pipeline_fields(self, tmp_path: Path) -> None:
        completion = f"```diff\n{REFERENCE_PATCH}```"
        score = self._run_scorer(completion, self._default_meta(), tmp_path=tmp_path)
        assert "patch_applies" in score.explanation
        assert "compiles" in score.explanation
        assert "crash_eliminated" in score.explanation
