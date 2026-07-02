"""The "fix the parser error" step.

Defines a :class:`Fixer` protocol (so a key-less environment can swap in a
heuristic later) and an :class:`LLMFixer` backed by the Anthropic SDK — the same
``anthropic`` dependency the rest of the repo already uses. ``run_fix`` ties the
proposal to the toolchain: write the patch, regenerate if needed, rebuild, and
replay the crashing input to verify the crash is gone.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import logfire
from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

from parser_security_eval import prompts
from parser_security_eval.treesitter import runtime
from parser_security_eval.treesitter.models import (
    GrammarTarget,
    TSBuildResult,
    TSCrash,
    TSFixAttempt,
)

# Model-agnostic: a pydantic-ai "provider:model" string. Swap the provider freely
# (e.g. "openai:gpt-4o", "google-gla:gemini-2.5-pro"); keys are read from the env.
DEFAULT_FIX_MODEL = "anthropic:claude-opus-4-8"
# Replays used to confirm a crash reproduces (pre-fix) and is gone (post-fix).
# >1 because some scanner crashes are flaky (e.g. heap-layout-dependent SEGVs).
VERIFY_ATTEMPTS = 20

_CRASH_MARKERS = (
    "ERROR:",
    "SUMMARY:",
    "AddressSanitizer",
    "byte(s) leaked",
    "runtime error:",
)


class FixOutput(BaseModel):
    """Structured fixer result — enforced by pydantic-ai (no text parsing)."""

    rationale: str = Field(
        description="One sentence: the root cause and the guard you added."
    )
    file_contents: str = Field(
        description="The COMPLETE corrected contents of the file — the full file, "
        "not a diff or a snippet."
    )


@dataclass
class FixProposal:
    """A fixer's proposed replacement for the implicated source file."""

    new_content: str
    rationale: str
    input_tokens: int = 0
    output_tokens: int = 0


class Fixer(Protocol):
    """Proposes a corrected version of the crash's implicated source file."""

    name: str

    def propose(
        self,
        crash: TSCrash,
        target: GrammarTarget,
        source: str,
        implicated_file: str,
        asan_report: str,
        lang_hint: str,
    ) -> FixProposal: ...


def _lang_hint(path: Path) -> str:
    return {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".js": "javascript",
    }.get(path.suffix, "")


def _crash_input_repr(crash: TSCrash) -> str:
    import base64

    try:
        raw = base64.b64decode(crash.crash_input_b64)
    except ValueError, TypeError:
        return "(unavailable)"
    snippet = raw[:512]
    return f"{snippet!r}" + (" …(truncated)" if len(raw) > 512 else "")


class LLMFixer:
    """Model-agnostic fixer via pydantic-ai.

    ``model`` is a ``provider:model`` string (e.g. ``anthropic:claude-opus-4-8``,
    ``openai:gpt-4o``); the provider's API key is read from the environment. The fix
    comes back as a validated :class:`FixOutput` (structured output), so there is no
    text/regex parsing of the model's reply.
    """

    def __init__(self, model: str = DEFAULT_FIX_MODEL, max_tokens: int = 32768) -> None:
        self.model = model
        self.name = model
        self.max_tokens = max_tokens

    def propose(
        self,
        crash: TSCrash,
        target: GrammarTarget,
        source: str,
        implicated_file: str,
        asan_report: str,
        lang_hint: str,
    ) -> FixProposal:
        system = prompts.load("treesitter.fix_system")
        user = prompts.load(
            "treesitter.fix_user",
            language=target.language,
            grammar=target.name,
            bug_class=crash.bug_class.value,
            asan_summary=crash.asan_summary,
            implicated_file=implicated_file,
            top_frames="\n".join(crash.top_frames) or "(none)",
            crash_input_repr=_crash_input_repr(crash),
            asan_report=asan_report[:6000],
            source=source,
            lang_hint=lang_hint,
        )
        agent = Agent(
            self.model,
            output_type=FixOutput,
            system_prompt=system,
            model_settings=ModelSettings(max_tokens=self.max_tokens),
        )
        # Log the FULL prompt + solution as named attributes (not interpolated into
        # the span message, which Logfire caps). pydantic-ai's auto-instrumentation
        # also captures the messages but renders a truncated preview; these explicit
        # attributes carry the complete challenge and the complete fix.
        with logfire.span(
            "repair agent {grammar} ({bug_class})",
            grammar=target.name,
            bug_class=crash.bug_class.value,
            model=self.model,
            implicated_file=implicated_file,
        ):
            logfire.info(
                "repair prompt {grammar}",
                grammar=target.name,
                system_prompt=system,
                user_prompt=user,  # the full challenge: report + source + crash input
                source_chars=len(source),
                user_prompt_chars=len(user),
            )
            result = agent.run_sync(user)
            out = cast("FixOutput", result.output)
            content = out.file_contents.strip("\n")
            logfire.info(
                "repair solution {grammar}: {rationale}",
                grammar=target.name,
                rationale=out.rationale.strip(),
                solution=out.file_contents,  # the agent's full corrected file
                solution_chars=len(out.file_contents),
                input_tokens=result.usage.input_tokens or 0,
                output_tokens=result.usage.output_tokens or 0,
            )
        return FixProposal(
            new_content=(content + "\n") if content.strip() else "",
            rationale=out.rationale.strip(),
            input_tokens=result.usage.input_tokens or 0,
            output_tokens=result.usage.output_tokens or 0,
        )


def _is_crash(rc: int, output: str) -> bool:
    """Heuristic: did this replay crash (nonzero exit or a sanitizer marker)?"""
    return rc != 0 or any(m in output for m in _CRASH_MARKERS)


def _crashes_on_replay(binary: Path, crash_file: Path, attempts: int) -> bool:
    """True if the binary crashes on at least one of *attempts* replays (flaky-safe)."""
    for _ in range(attempts):
        rc, out = runtime.reproduce(binary, crash_file)
        if _is_crash(rc, out):
            return True
    return False


def _clean_on_replay(binary: Path, crash_file: Path, attempts: int) -> bool:
    """True only if the binary never crashes across *attempts* replays."""
    for _ in range(attempts):
        rc, out = runtime.reproduce(binary, crash_file)
        if _is_crash(rc, out):
            return False
    return True


def select_fix_target(
    crash: TSCrash, build_result: TSBuildResult, src_dir: Path
) -> Path | None:
    """Choose the source file the fixer should rewrite.

    Prefers the external scanner (hand-written, cleanly patchable) whenever one is
    implicated — including serialization-buffer overflows that abort in the runtime
    after the scanner frame returns. Falls back to ``grammar.js`` (a
    regenerate-then-rebuild fix) for crashes in the generated parser. Returns
    ``None`` when the crash is in the tree-sitter runtime itself.
    """
    scanner = Path(build_result.scanner_file) if build_result.scanner_file else None
    blob = (crash.asan_summary + " " + " ".join(crash.top_frames)).lower()
    scanner_implicated = crash.in_scanner or "external_scanner" in blob
    if scanner is not None and scanner_implicated:
        return scanner

    impl = (crash.implicated_file or "").lower()
    grammar_js = src_dir.parent / "grammar.js"
    # A crash in the grammar's *generated* parser.c (not the runtime's lib/src) is
    # a grammar-definition bug → patch grammar.js and regenerate.
    if "parser.c" in impl and "lib/src" not in impl and grammar_js.exists():
        return grammar_js
    return None


def run_fix(
    crash: TSCrash,
    crash_file: Path,
    target: GrammarTarget,
    spec: runtime.BuildSpec,
    build_result: TSBuildResult,
    fixer: Fixer,
    asan_report: str,
) -> tuple[TSFixAttempt, TSBuildResult]:
    """Propose+apply a fix, rebuild, and verify the crash no longer reproduces.

    Returns the :class:`TSFixAttempt` and the (possibly rebuilt) build result.
    """
    attempt = TSFixAttempt(attempted=True, model=getattr(fixer, "name", "unknown"))
    fix_path = select_fix_target(crash, build_result, spec.src_dir)
    if fix_path is None or not fix_path.exists():
        attempt.attempted = False
        attempt.error = (
            "crash is in the tree-sitter runtime, not a grammar-level source file"
            if fix_path is None
            else f"implicated file not found: {fix_path}"
        )
        return attempt, build_result

    attempt.target_file = str(fix_path)

    # Soundness: confirm the bug actually reproduces on the PRE-fix build before
    # claiming any fix "verified" — otherwise a flaky/non-reproducible artifact
    # plus a clean post-fix replay is a false positive (the foam SEGV taught us this).
    attempt.verify_attempts = VERIFY_ATTEMPTS
    orig_binary = Path(build_result.binary_path or "")
    attempt.reproduced_original = _crashes_on_replay(
        orig_binary, crash_file, VERIFY_ATTEMPTS
    )
    if not attempt.reproduced_original:
        attempt.error = (
            f"crash did not reproduce on the original build in {VERIFY_ATTEMPTS} "
            "replays (flaky/stateful artifact) — skipping fix to avoid a false positive"
        )
        return attempt, build_result

    original = fix_path.read_text(encoding="utf-8", errors="replace")
    lang_hint = _lang_hint(fix_path)

    try:
        proposal = fixer.propose(
            crash, target, original, fix_path.name, asan_report, lang_hint
        )
    except Exception as exc:  # noqa: BLE001 — surface fixer errors into the record
        attempt.error = f"fixer.propose failed: {exc}"
        return attempt, build_result

    attempt.input_tokens = proposal.input_tokens
    attempt.output_tokens = proposal.output_tokens
    attempt.rationale = proposal.rationale
    if not proposal.new_content.strip():
        attempt.error = "fixer returned no file content"
        return attempt, build_result

    attempt.patch = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            proposal.new_content.splitlines(keepends=True),
            fromfile=f"a/{fix_path.name}",
            tofile=f"b/{fix_path.name}",
        )
    )

    # Apply (keep a backup so a failed fix can be rolled back).
    backup = fix_path.with_suffix(fix_path.suffix + ".orig")
    if not backup.exists():
        backup.write_text(original, encoding="utf-8")
    fix_path.write_text(proposal.new_content, encoding="utf-8")
    attempt.applied = True

    # grammar.js edits require regeneration before rebuild.
    if fix_path.name == "grammar.js":
        ok, _ = runtime.generate_parser(spec.src_dir)
        attempt.regenerated = ok
        if not ok:
            attempt.error = "tree-sitter generate failed after grammar.js edit"
            return attempt, build_result

    new_build = runtime.build(spec)
    attempt.rebuilt = new_build.built
    if not new_build.built:
        attempt.error = f"rebuild failed:\n{new_build.compile_errors[-1500:]}"
        return attempt, build_result

    # Verified only if the patched build never crashes across the replay budget
    # (reproduced_original is already True here).
    attempt.verified = _clean_on_replay(
        Path(new_build.binary_path or ""), crash_file, VERIFY_ATTEMPTS
    )
    if not attempt.verified:
        attempt.error = (
            "patch did not eliminate the crash (still reproduces after rebuild)"
        )
    return attempt, new_build
