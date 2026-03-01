"""Tests for the prompts loader (parser_security_eval.prompts)."""

from __future__ import annotations

import pytest

from parser_security_eval import prompts
from parser_security_eval.prompts.loader import render


# ---------------------------------------------------------------------------
# load() — plain .prompt files
# ---------------------------------------------------------------------------


class TestLoadPlainPrompts:
    def test_patching_system_returns_string(self) -> None:
        text = prompts.load("patching.system")
        assert isinstance(text, str)
        assert len(text) > 0

    def test_triage_system_returns_string(self) -> None:
        text = prompts.load("triage.system")
        assert isinstance(text, str)
        assert len(text) > 0

    def test_harness_system_returns_string(self) -> None:
        text = prompts.load("harness.system")
        assert isinstance(text, str)
        assert len(text) > 0

    def test_fuzzing_system_returns_string(self) -> None:
        text = prompts.load("fuzzing.system", max_repair=5, cycle_cap=1800)
        assert isinstance(text, str)
        assert len(text) > 0

    def test_triage_root_cause_grading_returns_string(self) -> None:
        text = prompts.load("triage.root_cause_grading")
        assert isinstance(text, str)
        assert len(text) > 0


# ---------------------------------------------------------------------------
# load() — .prompt.template files with Jinja2 rendering
# ---------------------------------------------------------------------------


class TestLoadTemplatePrompts:
    def test_harness_user_renders_variables(self) -> None:
        text = prompts.load(
            "harness.user",
            target_name="libpng",
            format_type="image",
            language="c",
            build_sh="./configure && make",
            existing_harnesses_section="No existing harnesses available.",
        )
        assert "libpng" in text
        assert "image" in text
        assert "./configure && make" in text

    def test_fuzzing_user_renders_variables(self) -> None:
        text = prompts.load(
            "fuzzing.user",
            target_name="libxml2",
            format_type="xml",
            language="c",
            ossfuzz_project="libxml2",
            fuzz_targets=["fuzz_xml"],
            cwe_hints=["CWE-119"],
            build_sh="make",
            source_snippets="(no source)",
            memory_section="",
        )
        assert "libxml2" in text
        assert "xml" in text

    def test_harness_user_target_name_appears_in_path(self) -> None:
        text = prompts.load(
            "harness.user",
            target_name="myparser",
            format_type="binary",
            language="c++",
            build_sh="cmake .",
            existing_harnesses_section="## Existing harnesses",
        )
        # target_name should appear in src path reference
        assert "myparser" in text

    def test_fuzzing_user_harness_path_uses_target_name(self) -> None:
        text = prompts.load(
            "fuzzing.user",
            target_name="libjpeg",
            format_type="image",
            language="c",
            ossfuzz_project="libjpeg-turbo",
            fuzz_targets=["fuzz_jpeg"],
            cwe_hints=["CWE-125"],
            build_sh="make",
            source_snippets="(no source)",
            memory_section="",
        )
        assert "libjpeg" in text

    def test_render_alias_works(self) -> None:
        text = render(
            "harness.user",
            target_name="libpng",
            format_type="image",
            language="c",
            build_sh="make",
            existing_harnesses_section="",
        )
        assert "libpng" in text


# ---------------------------------------------------------------------------
# Missing prompt raises FileNotFoundError
# ---------------------------------------------------------------------------


class TestMissingPrompt:
    def test_missing_domain_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="nonexistent.prompt"):
            prompts.load("nonexistent.prompt")

    def test_missing_key_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="patching.nosuchkey"):
            prompts.load("patching.nosuchkey")

    def test_invalid_name_format_raises(self) -> None:
        with pytest.raises(ValueError, match="domain.key"):
            prompts.load("nodot")


# ---------------------------------------------------------------------------
# Smoke tests — migrated task prompts contain key phrases
# ---------------------------------------------------------------------------


class TestPromptContent:
    def test_patching_system_mentions_asan(self) -> None:
        text = prompts.load("patching.system")
        assert "AddressSanitizer" in text

    def test_patching_system_mentions_unified_diff(self) -> None:
        text = prompts.load("patching.system")
        assert "unified diff" in text.lower() or "diff" in text

    def test_patching_system_mentions_try_patch(self) -> None:
        text = prompts.load("patching.system")
        assert "try_patch" in text

    def test_triage_system_mentions_cwe(self) -> None:
        text = prompts.load("triage.system")
        assert "CWE" in text

    def test_triage_system_requires_json(self) -> None:
        text = prompts.load("triage.system")
        assert "JSON" in text or "json" in text.lower()

    def test_triage_root_cause_grading_has_criterion_placeholder(self) -> None:
        text = prompts.load("triage.root_cause_grading")
        assert "{criterion}" in text
        assert "{answer}" in text

    def test_triage_root_cause_grading_mentions_grade(self) -> None:
        text = prompts.load("triage.root_cause_grading")
        assert "Grade" in text or "grade" in text.lower()

    def test_harness_system_mentions_llvm_fuzzer(self) -> None:
        text = prompts.load("harness.system")
        assert "LLVMFuzzerTestOneInput" in text

    def test_harness_system_mentions_coverage(self) -> None:
        text = prompts.load("harness.system")
        assert "coverage" in text.lower() or "exercise" in text.lower()

    def test_fuzzing_system_mentions_workflow(self) -> None:
        text = prompts.load("fuzzing.system", max_repair=5, cycle_cap=1800)
        assert "write_harness" in text

    def test_fuzzing_system_mentions_crashes(self) -> None:
        text = prompts.load("fuzzing.system", max_repair=5, cycle_cap=1800)
        assert "crash" in text.lower()

    def test_harness_user_contains_llvm_signature(self) -> None:
        text = prompts.load(
            "harness.user",
            target_name="t",
            format_type="f",
            language="c",
            build_sh="b",
            existing_harnesses_section="",
        )
        assert "LLVMFuzzerTestOneInput" in text

    def test_fuzzing_user_contains_target_name(self) -> None:
        text = prompts.load(
            "fuzzing.user",
            target_name="testlib",
            format_type="f",
            language="c",
            ossfuzz_project="N/A",
            fuzz_targets=[],
            cwe_hints="(none)",
            build_sh="b",
            source_snippets="(none)",
            memory_section="",
        )
        assert "testlib" in text
