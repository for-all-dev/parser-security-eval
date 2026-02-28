"""Tests for the harness generation task — no Docker or model required."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from parser_security_eval.tasks.harness import (
    _extract_code_block,
    _find_existing_harnesses,
    _load_metadata,
    harness_generation,
    harness_scorer,
    harness_solver,
    load_harness_dataset,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_METADATA = """\
name: testlib
format_type: binary-image
language: c
ossfuzz_project: null
fuzz_targets:
  - fuzz_testlib
has_corpus: false
has_dictionary: false
"""

MINIMAL_BUILD_SH = """\
#!/bin/bash -eu
cd /src/testlib
make -j$(nproc)
$CXX $CXXFLAGS -o $OUT/fuzz_testlib fuzz.cc -L. -ltestlib $LIB_FUZZING_ENGINE
"""


@pytest.fixture
def target_dir(tmp_path: Path) -> Path:
    """Create a minimal target directory for testing."""
    d = tmp_path / "testlib"
    d.mkdir()
    (d / "metadata.yaml").write_text(MINIMAL_METADATA)
    (d / "build.sh").write_text(MINIMAL_BUILD_SH)
    (d / "Dockerfile").write_text("FROM gcr.io/oss-fuzz-base/base-builder\n")
    return d


@pytest.fixture
def target_dir_with_harness(target_dir: Path) -> Path:
    """Target directory that also has an existing harness file."""
    (target_dir / "fuzz_testlib.cc").write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        "  return 0;\n}\n"
    )
    return target_dir


# ---------------------------------------------------------------------------
# Unit: _load_metadata
# ---------------------------------------------------------------------------


class TestLoadMetadata:
    def test_loads_valid_metadata(self, target_dir: Path) -> None:
        meta = _load_metadata(target_dir)
        assert meta["name"] == "testlib"
        assert meta["format_type"] == "binary-image"
        assert meta["language"] == "c"
        assert meta["fuzz_targets"] == ["fuzz_testlib"]

    def test_missing_metadata_raises(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError, match="No metadata.yaml"):
            _load_metadata(empty_dir)


# ---------------------------------------------------------------------------
# Unit: _find_existing_harnesses
# ---------------------------------------------------------------------------


class TestFindExistingHarnesses:
    def test_no_harnesses(self, target_dir: Path) -> None:
        assert _find_existing_harnesses(target_dir) == []

    def test_finds_fuzz_files(self, target_dir_with_harness: Path) -> None:
        harnesses = _find_existing_harnesses(target_dir_with_harness)
        assert len(harnesses) == 1
        fname, content = harnesses[0]
        assert fname == "fuzz_testlib.cc"
        assert "LLVMFuzzerTestOneInput" in content

    def test_ignores_non_harness_files(self, target_dir: Path) -> None:
        (target_dir / "utils.c").write_text("int main() { return 0; }")
        assert _find_existing_harnesses(target_dir) == []


# ---------------------------------------------------------------------------
# Unit: _extract_code_block
# ---------------------------------------------------------------------------


class TestExtractCodeBlock:
    def test_fenced_c_block(self) -> None:
        text = "Here is the harness:\n```c\nint LLVMFuzzerTestOneInput() {}\n```\nDone."
        assert "LLVMFuzzerTestOneInput" in _extract_code_block(text)

    def test_fenced_cpp_block(self) -> None:
        text = "```cpp\nint LLVMFuzzerTestOneInput() {}\n```"
        assert "LLVMFuzzerTestOneInput" in _extract_code_block(text)

    def test_unfenced_code(self) -> None:
        text = "#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }"
        result = _extract_code_block(text)
        assert "LLVMFuzzerTestOneInput" in result

    def test_picks_longest_block(self) -> None:
        text = (
            "```c\nshort\n```\n\n"
            "```c\nint LLVMFuzzerTestOneInput() { /* longer block */ return 0; }\n```"
        )
        result = _extract_code_block(text)
        assert "longer block" in result

    def test_empty_input(self) -> None:
        assert _extract_code_block("") == ""

    def test_no_code_block(self) -> None:
        text = "I cannot write a harness for this target."
        result = _extract_code_block(text)
        assert result == text.strip()


# ---------------------------------------------------------------------------
# Integration: load_harness_dataset
# ---------------------------------------------------------------------------


class TestLoadHarnessDataset:
    def test_loads_single_sample(self, target_dir: Path) -> None:
        samples = load_harness_dataset(str(target_dir.parent), "testlib")
        assert len(samples) == 1

    def test_sample_input_contains_target_info(self, target_dir: Path) -> None:
        samples = load_harness_dataset(str(target_dir.parent), "testlib")
        sample = samples[0]
        assert isinstance(sample.input, str)
        assert "testlib" in sample.input
        assert "binary-image" in sample.input
        assert "LLVMFuzzerTestOneInput" in sample.input

    def test_sample_target_is_fuzz_target_name(self, target_dir: Path) -> None:
        samples = load_harness_dataset(str(target_dir.parent), "testlib")
        assert samples[0].target == "fuzz_testlib"

    def test_sample_id(self, target_dir: Path) -> None:
        samples = load_harness_dataset(str(target_dir.parent), "testlib")
        assert samples[0].id == "harness-testlib"

    def test_sample_metadata_keys(self, target_dir: Path) -> None:
        samples = load_harness_dataset(str(target_dir.parent), "testlib")
        meta = samples[0].metadata
        assert meta is not None
        assert "target_name" in meta
        assert "format_type" in meta
        assert "language" in meta
        assert "fuzz_targets" in meta
        assert "targets_dir" in meta
        assert meta["target_name"] == "testlib"

    def test_includes_build_script(self, target_dir: Path) -> None:
        samples = load_harness_dataset(str(target_dir.parent), "testlib")
        assert "make -j" in samples[0].input

    def test_includes_existing_harnesses(self, target_dir_with_harness: Path) -> None:
        samples = load_harness_dataset(str(target_dir_with_harness.parent), "testlib")
        assert "Existing harnesses" in samples[0].input
        assert "fuzz_testlib.cc" in samples[0].input

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Target directory not found"):
            load_harness_dataset(str(tmp_path), "nonexistent")

    def test_default_fuzz_target_when_none_listed(self, tmp_path: Path) -> None:
        d = tmp_path / "nolist"
        d.mkdir()
        (d / "metadata.yaml").write_text(
            "name: nolist\nformat_type: text\nlanguage: c\nfuzz_targets: []\n"
        )
        (d / "build.sh").write_text("#!/bin/bash\n")
        samples = load_harness_dataset(str(tmp_path), "nolist")
        assert samples[0].target == "fuzz_nolist"


# ---------------------------------------------------------------------------
# Integration: harness_solver
# ---------------------------------------------------------------------------


class TestHarnessSolver:
    def test_returns_solver_list(self) -> None:
        solvers = harness_solver()
        assert isinstance(solvers, list)
        assert len(solvers) == 2


# ---------------------------------------------------------------------------
# Integration: harness_scorer
# ---------------------------------------------------------------------------


class TestHarnessScorer:
    def test_returns_callable(self) -> None:
        s = harness_scorer(fuzz_duration=60, engine="libfuzzer")
        assert callable(s)

    @pytest.mark.asyncio
    async def test_rejects_missing_harness(self) -> None:
        """Score should be INCORRECT when model output has no harness."""
        s = harness_scorer(fuzz_duration=10, engine="libfuzzer")

        state = MagicMock()
        state.output.completion = "I don't know how to write a harness."
        state.metadata = {
            "target_name": "testlib",
            "targets_dir": "/nonexistent",
        }

        from inspect_ai.scorer import INCORRECT, Target

        target = Target("fuzz_testlib")
        result = await s(state, target)
        assert result is not None
        assert result.value == INCORRECT
        assert "does not contain" in (result.explanation or "")


# ---------------------------------------------------------------------------
# Integration: harness_generation task
# ---------------------------------------------------------------------------


class TestHarnessGenerationTask:
    def test_creates_task(self, target_dir: Path) -> None:
        from inspect_ai import Task

        t = harness_generation(
            targets_dir=str(target_dir.parent),
            target="testlib",
            fuzz_duration=60,
            engine="libfuzzer",
        )
        assert isinstance(t, Task)
