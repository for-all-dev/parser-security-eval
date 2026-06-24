"""Pydantic data models for the tree-sitter fuzz→fix loop.

Mirrors the conventions in :mod:`parser_security_eval.models.fuzzing`
(``Field(default_factory=...)`` for collections, computed ``@property`` helpers).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class Tier(str, Enum):
    """Popularity tier of the grammar's language."""

    popular = "popular"
    less_popular = "less-popular"


class BugClass(str, Enum):
    """Sanitizer / libFuzzer crash classification."""

    heap_buffer_overflow = "heap-buffer-overflow"
    stack_buffer_overflow = "stack-buffer-overflow"
    global_buffer_overflow = "global-buffer-overflow"
    stack_overflow = "stack-overflow"
    heap_use_after_free = "heap-use-after-free"
    segv = "SEGV"
    memory_leak = "memory-leak"
    oom = "out-of-memory"
    timeout = "timeout"
    unknown = "unknown"


class GrammarTarget(BaseModel):
    """A tree-sitter grammar to fuzz."""

    name: str  # registry key, e.g. "toml"
    repo_url: str
    tier: Tier
    language: str  # human-readable language name, e.g. "TOML"
    symbol: str | None = None  # tree_sitter_<x>; auto-detected from parser.c if None
    commit: str | None = None  # optional commit pin (e.g. a known-buggy revision)
    subpath: str = ""  # subdir holding src/parser.c (e.g. "tree-sitter-markdown")


class TSBuildResult(BaseModel):
    """Outcome of compiling a grammar into a libFuzzer binary."""

    built: bool = False
    binary_path: str | None = None
    symbol: str = ""
    src_dir: str = ""
    had_scanner: bool = False
    scanner_file: str | None = None  # path to scanner.c / scanner.cc if present
    generated: bool = False  # whether `tree-sitter generate` was run
    compile_errors: str = ""


class TSFuzzResult(BaseModel):
    """Parsed result of one libFuzzer run (one fuzz window)."""

    duration_seconds: int
    execs_per_sec: float | None = None
    corpus_size: int | None = None
    total_executions: int | None = None
    crashes_found: int = 0
    timed_out: bool = False
    oom_killed: bool = False
    raw_log_tail: str = ""


class TSCrash(BaseModel):
    """A triaged crash, deduplicated by stack hash."""

    bug_class: BugClass = BugClass.unknown
    stack_hash: str = ""  # sha256 of top-N stack frames
    asan_summary: str = ""  # one-line SUMMARY from the sanitizer
    top_frames: list[str] = Field(default_factory=list)
    crash_input_b64: str = ""  # base64 of the triggering input
    crash_file: str | None = None
    implicated_file: str | None = None  # scanner.c / parser.c / runtime
    in_scanner: bool = False  # crash is in a hand-written external scanner


class TSFixAttempt(BaseModel):
    """The fixer's attempt to eliminate a crash."""

    attempted: bool = False
    model: str = ""
    target_file: str | None = None  # the source file the fixer rewrote
    patch: str = ""  # unified diff (old → new) for the record
    rationale: str = ""
    applied: bool = False
    regenerated: bool = False  # `tree-sitter generate` re-run after grammar.js edit
    rebuilt: bool = False
    # verified == reproduced_original AND the patched build never crashed on replay.
    reproduced_original: bool = False  # the bug reproduced on the pre-fix build
    verify_attempts: int = 0  # replays used to confirm repro / clearance (flaky-safe)
    verified: bool = False  # crashing input no longer reproduces after the fix
    error: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


class TSLoopIteration(BaseModel):
    """One fuzz→(triage→fix) iteration; serialized as one JSONL line."""

    iteration: int
    grammar: str
    repo_url: str
    tier: Tier
    language: str
    built: bool
    fuzz: TSFuzzResult | None = None
    crash: TSCrash | None = None
    fix: TSFixAttempt | None = None
    started_at: datetime = Field(default_factory=_utcnow)
    notes: str = ""

    def to_jsonl(self) -> str:
        """Render this iteration as a single JSON line (no trailing newline)."""
        return self.model_dump_json()


class TSLoopResult(BaseModel):
    """Aggregate result of a full loop over one grammar."""

    grammar: str
    tier: Tier
    language: str
    iterations: list[TSLoopIteration] = Field(default_factory=list)
    jsonl_path: str | None = None
    build_error: str = ""

    @property
    def crashes_found(self) -> int:
        return sum(1 for it in self.iterations if it.crash is not None)

    @property
    def unique_stack_hashes(self) -> list[str]:
        seen: list[str] = []
        for it in self.iterations:
            if it.crash and it.crash.stack_hash and it.crash.stack_hash not in seen:
                seen.append(it.crash.stack_hash)
        return seen

    @property
    def fixes_verified(self) -> int:
        return sum(
            1 for it in self.iterations if it.fix is not None and it.fix.verified
        )
