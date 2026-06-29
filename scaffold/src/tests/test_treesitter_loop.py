"""Tests for the fuzz→fix loop control flow + JSONL emission (toolchain mocked)."""

from __future__ import annotations

import json
from pathlib import Path

from parser_security_eval.treesitter import fixer as fixer_mod
from parser_security_eval.treesitter import loop as loop_mod
from parser_security_eval.treesitter import runtime
from parser_security_eval.treesitter.models import (
    GrammarTarget,
    Tier,
    TSBuildResult,
    TSFixAttempt,
    TSFuzzResult,
)

HEAP_OVERFLOW = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60
    #0 0x1 in scan /g/src/scanner.c:10:3
    #1 0x2 in LLVMFuzzerTestOneInput /w/harness.c:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /g/src/scanner.c:10:3 in scan
"""


def _target() -> GrammarTarget:
    return GrammarTarget(
        name="demo",
        repo_url="https://example/demo",
        tier=Tier.less_popular,
        language="Demo",
    )


def test_loop_fuzzer_triggers_fix_and_writes_jsonl(tmp_path: Path, monkeypatch) -> None:
    cache = tmp_path / "cache"
    out_dir = tmp_path / "out"

    monkeypatch.setattr(loop_mod, "configure_telemetry", lambda *a, **k: False)
    monkeypatch.setattr(runtime, "ensure_runtime", lambda c: tmp_path / "rt")
    monkeypatch.setattr(runtime, "ensure_grammar", lambda t, c: tmp_path / "grammar")
    monkeypatch.setattr(runtime, "gather_seeds", lambda *a, **k: 0)
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec: TSBuildResult(
            built=True,
            binary_path=str(tmp_path / "fuzz"),
            scanner_file=str(tmp_path / "scanner.c"),
        ),
    )
    monkeypatch.setattr(runtime, "reproduce", lambda *a, **k: (1, HEAP_OVERFLOW))

    calls = {"n": 0}

    def fake_run(self: runtime.LibFuzzerRunner, duration: int):  # noqa: ANN202
        calls["n"] += 1
        if calls["n"] == 1:
            self.crashes_dir.mkdir(parents=True, exist_ok=True)
            cf = self.crashes_dir / "crash-abc"
            cf.write_bytes(b"boom")
            return TSFuzzResult(duration_seconds=duration, crashes_found=1), [cf]
        return TSFuzzResult(duration_seconds=duration, crashes_found=0), []

    monkeypatch.setattr(runtime.LibFuzzerRunner, "run", fake_run)

    fix_calls = {"n": 0}

    def fake_run_fix(crash, crash_file, target, spec, build_result, fixer, report):  # noqa: ANN001, ANN202, PLR0913
        fix_calls["n"] += 1
        return (
            TSFixAttempt(
                attempted=True, applied=True, rebuilt=True, verified=True, model="stub"
            ),
            build_result,
        )

    monkeypatch.setattr(fixer_mod, "run_fix", fake_run_fix)
    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)

    result = loop_mod.run_loop(
        _target(),
        iterations=2,
        fuzz_seconds=1,
        cache_dir=cache,
        out_dir=out_dir,
        fixer=object(),  # never used; run_fix is stubbed
        seed_corpus=False,
    )

    # The fuzzer found a crash in window 0 → fix triggered exactly once.
    assert fix_calls["n"] == 1
    assert result.crashes_found == 1
    assert result.fixes_verified == 1
    assert len(result.iterations) == 2
    assert result.iterations[0].crash is not None
    assert result.iterations[0].fix is not None and result.iterations[0].fix.verified
    assert result.iterations[1].crash is None

    # JSONL: one line per iteration, each a valid object.
    jsonl = Path(result.jsonl_path or "")
    lines = jsonl.read_text().strip().splitlines()
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    assert rec0["crash"]["bug_class"] == "heap-buffer-overflow"
    assert rec0["fix"]["verified"] is True


def test_loop_records_build_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(loop_mod, "configure_telemetry", lambda *a, **k: False)
    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(runtime, "ensure_runtime", lambda c: tmp_path / "rt")
    monkeypatch.setattr(runtime, "ensure_grammar", lambda t, c: tmp_path / "grammar")
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec: TSBuildResult(
            built=False, compile_errors="boom: undefined symbol"
        ),
    )

    result = loop_mod.run_loop(
        _target(),
        iterations=3,
        fuzz_seconds=1,
        cache_dir=tmp_path,
        out_dir=tmp_path / "o",
    )
    assert result.build_error
    assert result.crashes_found == 0
    assert len(result.iterations) == 1
    assert result.iterations[0].built is False
