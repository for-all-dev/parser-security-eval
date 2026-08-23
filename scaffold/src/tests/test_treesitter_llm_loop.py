"""Tests for the LLM-in-loop treatment arm (author mocked, toolchain stubbed)."""

from __future__ import annotations

import types
from pathlib import Path

from parser_security_eval.treesitter import harness_author as ha_mod
from parser_security_eval.treesitter import llm_loop, runtime
from parser_security_eval.treesitter.harness_author import (
    HarnessOutput,
    HarnessProposal,
    LLMHarnessAuthor,
)
from parser_security_eval.treesitter.models import (
    GrammarTarget,
    Tier,
    TSBuildResult,
    TSFuzzResult,
)


def _target() -> GrammarTarget:
    return GrammarTarget(
        name="toml",
        repo_url="https://example/x",
        tier=Tier.less_popular,
        language="TOML",
    )


# --------------------------------------------------------------------------- #
# coverage parsing
# --------------------------------------------------------------------------- #
def test_cov_regex_takes_max() -> None:
    log = "#1 NEW cov: 12 ft: 3\n#2 NEW cov: 45 ft: 9\n#3 pulse cov: 30 ft: 9\n"
    vals = [int(x) for x in runtime._COV_RE.findall(log)]
    assert max(vals) == 45


def test_runner_parses_coverage(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "fuzz"
    binary.write_text("#!/bin/true\n")
    corpus = tmp_path / "corpus"
    crashes = tmp_path / "crashes"
    log = (
        "#1 INITED cov: 5 ft: 5\n"
        "#1024 NEW cov: 321 ft: 800 corp: 45/1234b\n"
        "stat::number_of_executed_units: 100000\n"
        "stat::average_exec_per_sec: 5000\n"
    )
    monkeypatch.setattr(
        runtime,
        "_run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=log, stderr=""),
    )
    runner = runtime.LibFuzzerRunner(
        binary=binary, corpus_dir=corpus, crashes_dir=crashes
    )
    res, new_crashes = runner.run(1)
    assert res.coverage_pcs == 321
    assert res.total_executions == 100000
    assert new_crashes == []


# --------------------------------------------------------------------------- #
# build() harness_override path
# --------------------------------------------------------------------------- #
def test_build_writes_harness_override(tmp_path: Path, monkeypatch) -> None:
    grammar = tmp_path / "g"
    src = grammar / "src"
    src.mkdir(parents=True)
    (src / "parser.c").write_text("// parser\n")
    spec = runtime.BuildSpec(
        target=_target(),
        runtime_dir=tmp_path / "rt",
        grammar_dir=grammar,
        work_dir=tmp_path / "work",
    )
    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    # Every compile/link invocation "succeeds".
    monkeypatch.setattr(
        runtime,
        "_run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    override = "/* custom */\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}\n"
    res = runtime.build(spec, harness_override=override)
    assert res.built is True
    assert (spec.work_dir / "harness.c").read_text() == override


def test_build_default_uses_template(tmp_path: Path, monkeypatch) -> None:
    grammar = tmp_path / "g"
    src = grammar / "src"
    src.mkdir(parents=True)
    (src / "parser.c").write_text(
        "const TSLanguage *tree_sitter_toml(void){return 0;}\n"
    )
    spec = runtime.BuildSpec(
        target=_target(),
        runtime_dir=tmp_path / "rt",
        grammar_dir=grammar,
        work_dir=tmp_path / "work",
    )
    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(
        runtime,
        "_run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    runtime.build(spec)
    written = (spec.work_dir / "harness.c").read_text()
    assert "LLVMFuzzerTestOneInput" in written
    assert "tree_sitter_toml" in written  # template rendered with the detected symbol


# --------------------------------------------------------------------------- #
# LLMHarnessAuthor (Agent mocked)
# --------------------------------------------------------------------------- #
def test_llm_harness_author_returns_proposal(monkeypatch) -> None:
    out = HarnessOutput(
        rationale="drive the heredoc scanner state",
        harness_c="int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}",
        seeds_hex=["4142", "zz-not-hex", "00ff"],
    )
    result = types.SimpleNamespace(
        output=out,
        usage=types.SimpleNamespace(input_tokens=7, output_tokens=8),
    )

    class _FakeAgent:
        def __init__(self, *a, **k) -> None:  # noqa: ANN002, ANN003
            pass

        def run_sync(self, _user):  # noqa: ANN001, ANN202
            return result

    monkeypatch.setattr(ha_mod, "Agent", _FakeAgent)
    prop = LLMHarnessAuthor(model="anthropic:claude-test").propose(
        _target(), "tree_sitter_toml", "// scanner", "// reference"
    )
    assert isinstance(prop, HarnessProposal)
    assert prop.harness_c.endswith("\n")
    assert prop.rationale == "drive the heredoc scanner state"
    assert prop.seeds == [b"AB", b"\x00\xff"]  # malformed hex dropped
    assert prop.input_tokens == 7
    assert prop.output_tokens == 8


# --------------------------------------------------------------------------- #
# run_llm_loop (stubbed author + runner + toolchain)
# --------------------------------------------------------------------------- #
class _StubAuthor:
    name = "stub-author"

    def __init__(self) -> None:
        self.feedbacks: list[str] = []

    def propose(
        self,
        target,
        symbol,
        scanner_source,
        reference_harness,
        *,
        previous_harness="",
        feedback="",
        has_scanner=True,
    ):  # noqa: ANN001, ANN201, PLR0913
        self.feedbacks.append(feedback)
        return HarnessProposal(
            harness_c="int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}\n",
            rationale="stub harness",
            seeds=[b"seed"],
        )


class _FakeRunner:
    """Stand-in for LibFuzzerRunner: coverage grows each window, no crashes."""

    _cov = [100, 250, 400, 400, 400]

    def __init__(self, *a, **k) -> None:  # noqa: ANN002, ANN003
        self.binary = Path("fuzz")
        self._i = 0

    def run(self, duration_seconds):  # noqa: ANN001, ANN202
        cov = self._cov[min(self._i, len(self._cov) - 1)]
        self._i += 1
        return (
            TSFuzzResult(
                duration_seconds=duration_seconds,
                coverage_pcs=cov,
                total_executions=1000 * (self._i),
                crashes_found=0,
            ),
            [],
        )


def _stub_toolchain(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(llm_loop, "configure_telemetry", lambda: None)
    monkeypatch.setattr(runtime, "check_toolchain", lambda **k: None)
    monkeypatch.setattr(
        runtime, "ensure_runtime", lambda cache_dir=None: tmp_path / "rt"
    )
    monkeypatch.setattr(
        runtime, "ensure_grammar", lambda target, cache_dir=None: tmp_path / "g"
    )
    monkeypatch.setattr(runtime, "gather_seeds", lambda *a, **k: 0)
    (tmp_path / "g" / "src").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec, harness_override=None: TSBuildResult(
            built=True,
            binary_path=str(tmp_path / "fuzz"),
            symbol="tree_sitter_toml",
            had_scanner=True,
            scanner_file=None,
        ),
    )
    monkeypatch.setattr(llm_loop, "LibFuzzerRunner", _FakeRunner)


def test_run_llm_loop_iterates_and_feeds_back(tmp_path: Path, monkeypatch) -> None:
    _stub_toolchain(monkeypatch, tmp_path)
    author = _StubAuthor()
    out_dir = tmp_path / "out"
    result = llm_loop.run_llm_loop(
        _target(),
        window_seconds=1,
        max_iterations=3,
        cache_dir=tmp_path / "cache",
        out_dir=out_dir,
        author=author,
    )
    assert len(result.iterations) == 3
    assert all(it.built for it in result.iterations)
    # coverage recorded and rising across the first windows
    covs = [it.fuzz.coverage_pcs for it in result.iterations if it.fuzz]
    assert covs == [100, 250, 400]
    # JSONL streamed
    jsonl = out_dir / "toml.jsonl"
    assert jsonl.exists()
    assert len(jsonl.read_text().strip().splitlines()) == 3
    # the author saw coverage feedback after each window (off-by-one: the Nth
    # propose call carries window N-1's outcome).
    assert author.feedbacks[0] == ""  # first call has no feedback
    assert "Coverage" in author.feedbacks[1]
    assert "+100" in author.feedbacks[1]  # window 0: 100 - 0
    assert "+150" in author.feedbacks[2]  # window 1: 250 - 100


def test_run_llm_loop_records_bootstrap_build_failure(
    tmp_path: Path, monkeypatch
) -> None:
    _stub_toolchain(monkeypatch, tmp_path)
    monkeypatch.setattr(
        runtime,
        "build",
        lambda spec, harness_override=None: TSBuildResult(
            built=False, compile_errors="boom: no parser.c"
        ),
    )
    result = llm_loop.run_llm_loop(
        _target(),
        window_seconds=1,
        max_iterations=3,
        cache_dir=tmp_path / "cache",
        out_dir=tmp_path / "out",
        author=_StubAuthor(),
    )
    assert result.build_error
    assert len(result.iterations) == 1
    assert result.iterations[0].built is False


def test_run_llm_loop_compile_retry_then_gives_up(tmp_path: Path, monkeypatch) -> None:
    _stub_toolchain(monkeypatch, tmp_path)
    calls = {"n": 0}

    def flaky_build(spec, harness_override=None):  # noqa: ANN001, ANN202
        # bootstrap (override None) succeeds; every override build fails to compile.
        if harness_override is None:
            calls["n"] += 1
            return TSBuildResult(
                built=True,
                binary_path=str(tmp_path / "fuzz"),
                symbol="tree_sitter_toml",
                had_scanner=True,
            )
        return TSBuildResult(built=False, compile_errors="undefined reference")

    monkeypatch.setattr(runtime, "build", flaky_build)
    author = _StubAuthor()
    result = llm_loop.run_llm_loop(
        _target(),
        window_seconds=1,
        max_iterations=1,
        max_compile_retries=2,
        cache_dir=tmp_path / "cache",
        out_dir=tmp_path / "out",
        author=author,
    )
    assert len(result.iterations) == 1
    assert result.iterations[0].built is False
    assert "not compiled" in result.iterations[0].notes
    # author was asked twice (2 compile retries), the 2nd with compile feedback
    assert len(author.feedbacks) == 2
    assert "DID NOT COMPILE" in author.feedbacks[1]
