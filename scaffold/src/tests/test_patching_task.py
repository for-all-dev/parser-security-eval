"""Tests for the vulnerability patching Inspect-AI task."""

import asyncio
import json
import stat
from pathlib import Path
from inspect_ai.model import ChatMessageAssistant, ChatMessageUser
from inspect_ai.scorer import Score
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from inspect_ai.tool import ToolCall

from parser_security_eval.tasks.patching import (
    _extract_crash_line,
    _extract_diff,
    _extract_diff_from_state,
    _patch_result_to_score,
    _resolve_fuzz_binary,
    _truncate_source,
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
# _extract_diff_from_state
# ---------------------------------------------------------------------------

DIFF_TEXT = "```diff\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n```"


def _make_state_with_messages(messages: list, completion: str = "") -> MagicMock:
    state = MagicMock()
    state.messages = messages
    state.output.completion = completion
    return state


class TestExtractDiffFromState:
    def test_finds_diff_in_last_assistant_message(self) -> None:
        msgs = [
            ChatMessageUser(content="fix this"),
            ChatMessageAssistant(content="No diff yet."),
            ChatMessageAssistant(content=DIFF_TEXT),
        ]
        state = _make_state_with_messages(msgs)
        result = _extract_diff_from_state(state)
        assert result is not None
        assert "--- a/f.c" in result

    def test_picks_most_recent_diff(self) -> None:
        msgs = [
            ChatMessageAssistant(
                content="```diff\n--- a/old.c\n+++ b/old.c\n@@ -1 +1 @@\n-x\n+y\n```"
            ),
            ChatMessageAssistant(content="Improving patch."),
            ChatMessageAssistant(
                content="```diff\n--- a/new.c\n+++ b/new.c\n@@ -1 +1 @@\n-x\n+z\n```"
            ),
        ]
        state = _make_state_with_messages(msgs)
        result = _extract_diff_from_state(state)
        assert result is not None
        assert "new.c" in result

    def test_falls_back_to_completion_when_no_message_diff(self) -> None:
        msgs = [ChatMessageAssistant(content="I'll work on it.")]
        state = _make_state_with_messages(msgs, completion=DIFF_TEXT)
        result = _extract_diff_from_state(state)
        assert result is not None
        assert "--- a/f.c" in result

    def test_returns_none_when_no_diff_anywhere(self) -> None:
        msgs = [ChatMessageAssistant(content="No solution yet.")]
        state = _make_state_with_messages(msgs, completion="")
        result = _extract_diff_from_state(state)
        assert result is None

    def test_skips_non_assistant_messages(self) -> None:
        msgs = [
            ChatMessageUser(content=DIFF_TEXT),  # user message with diff — should skip
            ChatMessageAssistant(content="No diff here."),
        ]
        state = _make_state_with_messages(msgs, completion="")
        result = _extract_diff_from_state(state)
        assert result is None

    def test_recovers_diff_from_try_patch_tool_call(self) -> None:
        """Bug 3: when output.completion is empty and no text diff in messages,
        fall back to the diff argument of the last try_patch tool call."""
        raw_diff = "--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n"
        tc = ToolCall(id="tc1", function="try_patch", arguments={"diff": raw_diff})
        msg = ChatMessageAssistant(content="Applying patch.", tool_calls=[tc])
        state = _make_state_with_messages([msg], completion="")
        result = _extract_diff_from_state(state)
        assert result is not None
        assert "--- a/f.c" in result

    def test_ignores_non_try_patch_tool_calls(self) -> None:
        """Tool calls for compile_target or run_crash_input should not be used."""
        tc = ToolCall(
            id="tc2",
            function="compile_target",
            arguments={"diff": "--- a/x.c\n+++ b/x.c\n"},
        )
        msg = ChatMessageAssistant(content="Compiling.", tool_calls=[tc])
        state = _make_state_with_messages([msg], completion="")
        result = _extract_diff_from_state(state)
        assert result is None

    def test_prefers_message_text_over_tool_call_arg(self) -> None:
        """If a text diff exists in message content, prefer it over tool call arg."""
        text_diff = "--- a/text.c\n+++ b/text.c\n@@ -1 +1 @@\n-a\n+b\n"
        arg_diff = "--- a/tool.c\n+++ b/tool.c\n@@ -1 +1 @@\n-x\n+y\n"
        tc = ToolCall(id="tc3", function="try_patch", arguments={"diff": arg_diff})
        msg = ChatMessageAssistant(content=f"```diff\n{text_diff}```", tool_calls=[tc])
        state = _make_state_with_messages([msg], completion="")
        result = _extract_diff_from_state(state)
        assert result is not None
        assert "text.c" in result


# ---------------------------------------------------------------------------
# _extract_crash_line / _truncate_source (Bug 2 regression tests)
# ---------------------------------------------------------------------------


class TestExtractCrashLine:
    def test_finds_line_by_filename(self) -> None:
        report = "    #0 0x1234 in some_func /src/libpng/pngrutil.c:42"
        result = _extract_crash_line(report, "pngrutil.c")
        assert result == 42

    def test_returns_none_when_filename_absent(self) -> None:
        report = "    #0 0x1234 in foo /src/libpng/other.c:10"
        result = _extract_crash_line(report, "pngrutil.c")
        assert result is None

    def test_strategy2_finds_function_in_content(self) -> None:
        """When filename not in report, match ASAN function names against source."""
        report = "    #0 0xABCD in xmlSAX2CDataBlock /src/libxml2/SAX2.c:2805"
        content = (
            "\n" * 100 + "int xmlSAX2CDataBlock(void *ctx, const xmlChar *value) {\n"
        )
        # filename is a different file, so strategy 1 fails
        result = _extract_crash_line(report, "other_file.c", content)
        assert result == 101  # 100 blank lines + 1

    def test_strategy2_returns_none_when_no_match(self) -> None:
        report = "    #0 0xABCD in unknownFunc /src/foo/bar.c:10"
        content = "void someOtherFunc(void) {}\n"
        result = _extract_crash_line(report, "notbar.c", content)
        assert result is None


class TestTruncateSource:
    def test_short_file_returned_unchanged(self) -> None:
        content = "line1\nline2\n"
        result = _truncate_source(content, "f.c", None)
        assert result == content

    def test_default_max_lines_is_600(self) -> None:
        """The default max_lines should be 600, not 400."""
        import inspect as stdlib_inspect

        sig = stdlib_inspect.signature(_truncate_source)
        assert sig.parameters["max_lines"].default == 600

    def test_falls_back_to_start_when_no_anchor(self) -> None:
        content = "\n".join(f"line{i}" for i in range(700)) + "\n"
        result = _truncate_source(content, "nofile.c", None)
        assert "[lines 1–600 of 700]" in result

    def test_anchors_around_crash_line_in_filename(self) -> None:
        # Build a 700-line file; crash at line 650
        lines = [f"line{i}\n" for i in range(1, 701)]
        content = "".join(lines)
        report = "    #0 0x1 in foo /src/f.c:650"
        result = _truncate_source(content, "f.c", report, max_lines=100)
        # anchor=650, half=50, start=600, end=700
        assert "[lines 601–700 of 700]" in result

    def test_strategy2_anchors_when_filename_absent(self) -> None:
        """When filename not in report, function name scan should provide the anchor."""
        report = "    #0 0xABCD in targetFunc /src/other.c:10"
        # 700-line file, function definition at line 650
        lines = [f"// line {i}\n" for i in range(1, 650)]
        lines.append("int targetFunc(int x) {\n")  # line 650
        lines.extend([f"// line {i}\n" for i in range(651, 701)])
        content = "".join(lines)
        result = _truncate_source(content, "unrelated.c", report, max_lines=100)
        # anchor=650, half=50, start=600, end=700
        assert "[lines 601–700 of 700]" in result


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
# load_patching_dataset — seed / shuffle behaviour
# ---------------------------------------------------------------------------


def make_multi_benchmark(tmp_path: Path, n: int = 6) -> Path:
    """Create a benchmark with n vulnerability records across different targets."""
    records = []
    for i in range(n):
        target = "libpng" if i % 2 == 0 else "libxml2"
        vuln_id = f"OSS-FUZZ-{10000 + i}"
        record_dir = tmp_path / target / vuln_id
        record_dir.mkdir(parents=True, exist_ok=True)
        (record_dir / "crash_report.txt").write_text(f"ASAN: heap-buffer-overflow #{i}")
        records.append(
            {
                "id": vuln_id,
                "target": target,
                "severity": "high",
                "difficulty": "medium",
                "crash_type": "heap-buffer-overflow",
                "sanitizer": "address",
                "affected_file": "foo.c",
                "affected_function": None,
                "cwe": None,
                "root_cause": None,
                "crash_input_path": None,
                "crash_report_path": f"{target}/{vuln_id}/crash_report.txt",
                "reference_patch_path": None,
                "vulnerable_source_ref": None,
                "tags": [],
                "lines_changed_in_fix": None,
                "ossfuzz_project": None,
            }
        )

    metadata = {
        "version": "0.1.0",
        "total_vulnerabilities": n,
        "targets": ["libpng", "libxml2"],
        "records": records,
    }
    (tmp_path / "metadata.json").write_text(json.dumps(metadata))
    return tmp_path


class TestLoadPatchingDatasetSeed:
    def test_same_seed_produces_same_order(self, tmp_path: Path) -> None:
        bdir = make_multi_benchmark(tmp_path, n=6)
        ids_a = [s.id for s in load_patching_dataset(str(bdir), seed=42)]
        ids_b = [s.id for s in load_patching_dataset(str(bdir), seed=42)]
        assert ids_a == ids_b

    def test_different_seeds_produce_different_orders(self, tmp_path: Path) -> None:
        bdir = make_multi_benchmark(tmp_path, n=6)
        ids_seed1 = [s.id for s in load_patching_dataset(str(bdir), seed=1)]
        ids_seed2 = [s.id for s in load_patching_dataset(str(bdir), seed=99)]
        # With 6 elements it is astronomically unlikely both seeds produce
        # identical permutations; treat as a definitive mismatch.
        assert ids_seed1 != ids_seed2

    def test_seed_without_limit_returns_all_samples(self, tmp_path: Path) -> None:
        bdir = make_multi_benchmark(tmp_path, n=6)
        samples = load_patching_dataset(str(bdir), seed=7)
        assert len(samples) == 6

    def test_seed_with_target_filter_applied_before_shuffle(
        self, tmp_path: Path
    ) -> None:
        """Filter by target must happen before seed-shuffle so IDs are stable."""
        bdir = make_multi_benchmark(tmp_path, n=6)
        # Only libpng records (i=0,2,4 → ids 10000, 10002, 10004)
        samples_a = load_patching_dataset(str(bdir), target="libpng", seed=42)
        samples_b = load_patching_dataset(str(bdir), target="libpng", seed=42)
        assert [s.id for s in samples_a] == [s.id for s in samples_b]
        # All returned samples must be libpng
        assert all(s.metadata["target"] == "libpng" for s in samples_a)
        assert len(samples_a) == 3  # 3 libpng records out of 6

    def test_no_seed_preserves_original_order(self, tmp_path: Path) -> None:
        """Without a seed, records come out in metadata.json insertion order."""
        bdir = make_multi_benchmark(tmp_path, n=6)
        samples = load_patching_dataset(str(bdir))
        expected_ids = [f"OSS-FUZZ-{10000 + i}" for i in range(6)]
        assert [s.id for s in samples] == expected_ids


# ---------------------------------------------------------------------------
# patching_solver
# ---------------------------------------------------------------------------


class TestPatchingSolver:
    def test_returns_solver(self) -> None:
        s = patching_solver()
        # @solver decorator returns a callable (async function)
        assert callable(s)


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
