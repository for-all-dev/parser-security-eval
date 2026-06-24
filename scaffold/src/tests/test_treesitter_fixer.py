"""Tests for the tree-sitter fixer (LLM mocked) and the apply/verify flow."""

from __future__ import annotations

import sys
import types
from pathlib import Path

from parser_security_eval.treesitter import fixer as fixer_mod
from parser_security_eval.treesitter import runtime
from parser_security_eval.treesitter.fixer import (
    FixProposal,
    LLMFixer,
    run_fix,
    select_fix_target,
)
from parser_security_eval.treesitter.models import (
    BugClass,
    GrammarTarget,
    Tier,
    TSBuildResult,
    TSCrash,
)

MODEL_REPLY = """\
RATIONALE: missing bounds check before indexing the lexeme buffer.
```c
#include "tree_sitter/parser.h"
int scan(void) { return 0; /* fixed */ }
```
trailing prose that must be ignored
"""


def _target() -> GrammarTarget:
    return GrammarTarget(
        name="toml",
        repo_url="https://example/x",
        tier=Tier.less_popular,
        language="TOML",
    )


def test_extract_file_picks_largest_fenced_block() -> None:
    content = fixer_mod._extract_file(MODEL_REPLY)
    assert "fixed" in content
    assert "trailing prose" not in content


def test_extract_file_handles_truncated_unclosed_fence() -> None:
    # Model hit the token cap mid-file: opening fence, no closing fence.
    truncated = "RATIONALE: bounds check\n```c\nint scan(void){ return 0; }\n// cut off"
    out = fixer_mod._extract_file(truncated)
    assert "int scan" in out
    assert "```" not in out
    assert "RATIONALE" not in out


def test_llm_fixer_parses_reply(monkeypatch) -> None:
    block = types.SimpleNamespace(type="text", text=MODEL_REPLY)
    usage = types.SimpleNamespace(input_tokens=11, output_tokens=22)
    msg = types.SimpleNamespace(content=[block], usage=usage)

    class _Stream:  # context manager mimicking client.messages.stream(...)
        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *a):  # noqa: ANN002, ANN204
            return False

        def get_final_message(self):  # noqa: ANN202
            return msg

    client = types.SimpleNamespace(
        messages=types.SimpleNamespace(stream=lambda **_: _Stream())
    )
    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda *a, **k: client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    crash = TSCrash(bug_class=BugClass.heap_buffer_overflow, asan_summary="boom")
    proposal = LLMFixer(model="claude-test").propose(
        crash, _target(), "old source", "scanner.c", "asan report", "c"
    )
    assert isinstance(proposal, FixProposal)
    assert "fixed" in proposal.new_content
    assert proposal.rationale.startswith("missing bounds check")
    assert proposal.input_tokens == 11
    assert proposal.output_tokens == 22


def test_select_fix_target_prefers_scanner(tmp_path: Path) -> None:
    scanner = tmp_path / "scanner.c"
    scanner.write_text("// scanner")
    crash = TSCrash(in_scanner=True)
    build = TSBuildResult(built=True, scanner_file=str(scanner))
    assert select_fix_target(crash, build, tmp_path) == scanner


def test_select_fix_target_runtime_crash_returns_none(tmp_path: Path) -> None:
    crash = TSCrash(in_scanner=False, implicated_file="lib/src/subtree.c")
    build = TSBuildResult(built=True)
    assert select_fix_target(crash, build, tmp_path) is None


class _StubFixer:
    name = "stub"

    def propose(self, crash, target, source, implicated_file, asan_report, lang_hint):  # noqa: ANN001, ANN201, PLR0913
        return FixProposal(
            new_content="int scan(void){return 0;}\n",
            rationale="add guard",
            input_tokens=3,
            output_tokens=4,
        )


def test_run_fix_applies_rebuilds_and_verifies(tmp_path: Path, monkeypatch) -> None:
    # Lay out a grammar with src/scanner.c so select_fix_target finds it.
    grammar = tmp_path / "g"
    src = grammar / "src"
    src.mkdir(parents=True)
    scanner = src / "scanner.c"
    scanner.write_text("int scan(void){buf[i];}\n")
    (src / "parser.c").write_text("// parser")

    target = _target()
    spec = runtime.BuildSpec(
        target=target,
        runtime_dir=tmp_path / "rt",
        grammar_dir=grammar,
        work_dir=tmp_path / "work",
    )
    build = TSBuildResult(
        built=True, binary_path=str(tmp_path / "fuzz_orig"), scanner_file=str(scanner)
    )
    crash = TSCrash(
        bug_class=BugClass.heap_buffer_overflow,
        in_scanner=True,
        implicated_file="scanner.c",
    )
    crash_file = tmp_path / "crash-1"
    crash_file.write_bytes(b"bad")

    # Rebuild produces a *different* binary; original crashes, patched is clean.
    monkeypatch.setattr(
        runtime,
        "build",
        lambda _spec: TSBuildResult(
            built=True, binary_path=str(tmp_path / "fuzz_patched")
        ),
    )

    def fake_reproduce(binary, crash_file, timeout=60):  # noqa: ANN001, ANN202
        if "orig" in str(binary):
            return 1, "==ERROR: AddressSanitizer: heap-buffer-overflow"
        return 0, "clean exit"

    monkeypatch.setattr(runtime, "reproduce", fake_reproduce)

    attempt, new_build = run_fix(
        crash, crash_file, target, spec, build, _StubFixer(), "asan report"
    )
    assert attempt.reproduced_original is True
    assert attempt.applied is True
    assert attempt.rebuilt is True
    assert attempt.verified is True
    assert attempt.target_file == str(scanner)
    assert attempt.patch  # unified diff captured
    assert scanner.with_suffix(".c.orig").exists()  # backup made
    assert new_build.built is True


def test_run_fix_skips_when_original_does_not_reproduce(
    tmp_path: Path, monkeypatch
) -> None:
    # Foam-style: the saved artifact does not crash the original build → no fix,
    # no false-positive "verified".
    grammar = tmp_path / "g"
    src = grammar / "src"
    src.mkdir(parents=True)
    scanner = src / "scanner.c"
    scanner.write_text("int scan(void){return 0;}\n")
    (src / "parser.c").write_text("// parser")
    target = _target()
    spec = runtime.BuildSpec(
        target=target,
        runtime_dir=tmp_path / "rt",
        grammar_dir=grammar,
        work_dir=tmp_path / "work",
    )
    build = TSBuildResult(
        built=True, binary_path=str(tmp_path / "fuzz"), scanner_file=str(scanner)
    )
    crash = TSCrash(
        bug_class=BugClass.segv, in_scanner=True, implicated_file="scanner.c"
    )
    crash_file = tmp_path / "crash-1"
    crash_file.write_bytes(b"bad")

    # Original never crashes on replay.
    monkeypatch.setattr(runtime, "reproduce", lambda *a, **k: (0, "clean"))
    build_calls = {"n": 0}

    def counting_build(_spec):  # noqa: ANN001, ANN202
        build_calls["n"] += 1
        return TSBuildResult(built=True, binary_path=str(tmp_path / "fuzz2"))

    monkeypatch.setattr(runtime, "build", counting_build)

    attempt, _ = run_fix(crash, crash_file, target, spec, build, _StubFixer(), "report")
    assert attempt.reproduced_original is False
    assert attempt.verified is False
    assert attempt.applied is False  # never patched
    assert build_calls["n"] == 0  # no rebuild / no fixer call wasted
    assert "did not reproduce" in attempt.error


def test_run_fix_patch_that_does_not_eliminate_is_not_verified(
    tmp_path: Path, monkeypatch
) -> None:
    grammar = tmp_path / "g"
    src = grammar / "src"
    src.mkdir(parents=True)
    scanner = src / "scanner.c"
    scanner.write_text("int scan(void){buf[i];}\n")
    (src / "parser.c").write_text("// parser")
    target = _target()
    spec = runtime.BuildSpec(
        target=target,
        runtime_dir=tmp_path / "rt",
        grammar_dir=grammar,
        work_dir=tmp_path / "work",
    )
    build = TSBuildResult(
        built=True, binary_path=str(tmp_path / "fuzz"), scanner_file=str(scanner)
    )
    crash = TSCrash(
        bug_class=BugClass.heap_buffer_overflow,
        in_scanner=True,
        implicated_file="scanner.c",
    )
    crash_file = tmp_path / "crash-1"
    crash_file.write_bytes(b"bad")

    # Crash reproduces on BOTH original and patched (fix didn't help).
    monkeypatch.setattr(
        runtime, "reproduce", lambda *a, **k: (1, "==ERROR: AddressSanitizer: SEGV")
    )
    monkeypatch.setattr(
        runtime,
        "build",
        lambda _spec: TSBuildResult(built=True, binary_path=str(tmp_path / "f2")),
    )
    attempt, _ = run_fix(crash, crash_file, target, spec, build, _StubFixer(), "report")
    assert attempt.reproduced_original is True
    assert attempt.applied is True
    assert attempt.verified is False
    assert "did not eliminate" in attempt.error


def test_run_fix_skips_runtime_crash(tmp_path: Path) -> None:
    target = _target()
    grammar = tmp_path / "g"
    (grammar / "src").mkdir(parents=True)
    (grammar / "src" / "parser.c").write_text("// parser")
    spec = runtime.BuildSpec(
        target=target,
        runtime_dir=tmp_path / "rt",
        grammar_dir=grammar,
        work_dir=tmp_path / "work",
    )
    build = TSBuildResult(built=True)
    crash = TSCrash(in_scanner=False, implicated_file="lib/src/subtree.c")
    attempt, new_build = run_fix(
        crash, tmp_path / "c", target, spec, build, _StubFixer(), "report"
    )
    assert attempt.attempted is False
    assert "runtime" in attempt.error
