"""Crash triage for the tree-sitter loop.

Parses AddressSanitizer / libFuzzer output into a :class:`TSCrash`, classifies the
bug, extracts the top stack frames, and derives a SHA-256 stack hash for
deduplication (the same idea as
:func:`parser_security_eval.triage.casr.CASRTriager._stack_hash_dedup`).
"""

from __future__ import annotations

import base64
import hashlib
import re

from parser_security_eval.treesitter.models import BugClass, TSCrash

MAX_STACK_FRAMES = 5  # top-N frames used for the stack hash (matches fuzzing task)

# Symbolized:   "    #0 0x55ad in ts_lex /src/scanner.c:42:10"
# Unsymbolized: "    #0 0x55ad (/path/fuzz+0x12ab)"
_FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+(.+?)\s*$", re.MULTILINE)
# Drop the trailing ":col" so equivalent crashes hash identically.
_COL_RE = re.compile(r":(\d+):(\d+)$")

# Frame normalization for a PORTABLE stack hash — one that matches across two
# independent sweeps (different machines, home dirs, and tree-sitter runtime
# commits). Without this, the hash is a SHA-256 over raw frame strings that embed
# run-specific noise, so the same bug hashes differently in each run and a
# cross-run overlap comparison collapses to zero. Three noise sources are removed:
#   1. binary load offsets ("fuzz+0x1d0343")            -> re-linked each build
#   2. absolute paths ("/home/<user>/.cache/.../x.c")   -> differ by machine/user
#   3. tree-sitter *runtime* line numbers               -> drift between runtime
#      (frames under ".../tree-sitter/lib/...")            commits cloned per run
# Scanner/grammar line numbers ARE kept, so distinct crash sites stay distinct.
_HEX_OFF_RE = re.compile(r"\+?0x[0-9a-fA-F]+")
_PATH_RE = re.compile(r"(?:[^\s():]*/)?([^\s():/]+?)(:\d+)?(?=[\s()]|$)")
_RUNTIME_MARKER = "tree-sitter/lib/"

_ASAN_CLASS_RE = re.compile(r"AddressSanitizer:\s+([a-z0-9-]+)")
_UBSAN_RE = re.compile(r"runtime error:|UndefinedBehaviorSanitizer")
_LIBFUZZER_RE = re.compile(r"libFuzzer:\s+(timeout|out-of-memory|deadly signal)")
_SUMMARY_RE = re.compile(r"^SUMMARY:\s*(.+?)\s*$", re.MULTILINE)

_ASAN_TO_CLASS: dict[str, BugClass] = {
    "heap-buffer-overflow": BugClass.heap_buffer_overflow,
    "stack-buffer-overflow": BugClass.stack_buffer_overflow,
    "global-buffer-overflow": BugClass.global_buffer_overflow,
    "stack-overflow": BugClass.stack_overflow,
    "heap-use-after-free": BugClass.heap_use_after_free,
    "dynamic-stack-buffer-overflow": BugClass.stack_buffer_overflow,
    "SEGV": BugClass.segv,
    "segv": BugClass.segv,
}

_SCANNER_NAMES = ("scanner.c", "scanner.cc", "scanner.cpp", "scanner.cxx")


def extract_frames(report: str) -> list[str]:
    """Return normalized ``func file:line`` strings for every stack frame."""
    frames: list[str] = []
    for raw in _FRAME_RE.findall(report):
        frame = raw.strip()
        # Normalize symbolized frames ("in func file:line") by dropping "in ".
        if frame.startswith("in "):
            frame = frame[3:]
        frames.append(_COL_RE.sub(r":\1", frame))
    return frames


def classify(report: str) -> BugClass:
    """Map a sanitizer/libFuzzer report to a :class:`BugClass`."""
    m = _LIBFUZZER_RE.search(report)
    if m:
        kind = m.group(1)
        if kind == "timeout":
            return BugClass.timeout
        if kind == "out-of-memory":
            return BugClass.oom
        return BugClass.segv  # "deadly signal"
    # Leak detection must precede the generic ASan-class regex: ASan's leak summary
    # reads "AddressSanitizer: N byte(s) leaked", which the class regex would
    # otherwise capture as the (numeric) "class" and drop to unknown.
    if (
        "byte(s) leaked" in report
        or "LeakSanitizer" in report
        or "detected memory leaks" in report
    ):
        return BugClass.memory_leak
    m = _ASAN_CLASS_RE.search(report)
    if m:
        return _ASAN_TO_CLASS.get(m.group(1), BugClass.unknown)
    if "SEGV" in report or "SIGSEGV" in report:
        return BugClass.segv
    if _UBSAN_RE.search(report):
        return BugClass.unknown
    return BugClass.unknown


def normalize_frame(frame: str) -> str:
    """Reduce a stack frame to a portable ``func basename[:line]`` form.

    See ``_HEX_OFF_RE`` above for why. Runtime frames keep only the basename;
    scanner/grammar frames keep their line number.
    """
    frame = frame.strip()
    func, _, rest = frame.partition(" ")
    is_runtime = _RUNTIME_MARKER in rest
    rest = _HEX_OFF_RE.sub("", rest)

    def _repl(m: re.Match[str]) -> str:
        base = m.group(1)
        line = m.group(2) or ""
        return base if is_runtime else base + line

    rest = _PATH_RE.sub(_repl, rest).strip(" ()")
    return f"{func} {rest}".strip()


def stack_hash(frames: list[str]) -> str:
    """Portable SHA-256 over the top-N normalized frames.

    Normalization (see :func:`normalize_frame`) makes the hash stable across
    independent sweeps, so a hybrid-vs-baseline overlap comparison is meaningful.
    """
    top = [normalize_frame(f) for f in frames[:MAX_STACK_FRAMES]]
    return hashlib.sha256("\n".join(top).encode("utf-8", "replace")).hexdigest()


def summary_line(report: str) -> str:
    """Return the sanitizer ``SUMMARY:`` line, or a best-effort first error line."""
    m = _SUMMARY_RE.search(report)
    if m:
        return m.group(1)
    for pat in (_LIBFUZZER_RE, _ASAN_CLASS_RE):
        m = pat.search(report)
        if m:
            # Return the whole line containing the match.
            line_start = report.rfind("\n", 0, m.start()) + 1
            line_end = report.find("\n", m.end())
            return report[line_start : line_end if line_end != -1 else None].strip()
    return ""


def involves_external_scanner(frames: list[str], report: str = "") -> bool:
    """True if a hand-written external scanner is implicated.

    Catches both direct scanner frames and the runtime's
    ``ts_parser__external_scanner_*`` wrappers — the latter matters for
    serialization-buffer overflows, where the scanner's ``serialize`` frame has
    already returned by the time the runtime aborts.
    """
    blob = (" ".join(frames) + " " + report).lower()
    if "external_scanner" in blob:
        return True
    return any(name in blob for name in _SCANNER_NAMES)


def implicate(frames: list[str], report: str = "") -> tuple[str | None, bool]:
    """Pick the source file most likely responsible for the crash.

    Prefers a hand-written external scanner (``scanner.c``/``.cc``) frame, then a
    generated ``parser.c`` frame, then the first frame's file. The boolean is True
    whenever an external scanner is implicated (see :func:`involves_external_scanner`).
    Returns ``(file, in_scanner)``.
    """
    in_scanner = involves_external_scanner(frames, report)
    for frame in frames:
        low = frame.lower()
        if any(name in low for name in _SCANNER_NAMES):
            return _frame_file(frame), True
    for frame in frames:
        if "parser.c" in frame.lower():
            return _frame_file(frame), in_scanner
    if frames:
        return _frame_file(frames[0]), in_scanner
    return None, in_scanner


def _frame_file(frame: str) -> str | None:
    """Extract the file path (without ``:line``) from a normalized frame."""
    m = re.search(r"\s(\S+):\d+$", frame)
    if m:
        return m.group(1)
    # Frame may be just "func /path/file" with no line number.
    parts = frame.rsplit(" ", 1)
    if len(parts) == 2 and "/" in parts[1]:
        return parts[1]
    return None


def triage(report: str, crash_bytes: bytes, crash_file: str | None = None) -> TSCrash:
    """Build a :class:`TSCrash` from a sanitizer report + the triggering input."""
    frames = extract_frames(report)
    impl_file, in_scanner = implicate(frames, report)
    bug_class = classify(report)
    # Frameless crashes (hangs, OOM, unsymbolized aborts) would all collapse to the
    # empty-string hash; fall back to a per-bug-class hash so they stay distinct.
    sh = (
        stack_hash(frames)
        if frames
        else hashlib.sha256(f"noframes:{bug_class.value}".encode()).hexdigest()
    )
    return TSCrash(
        bug_class=bug_class,
        stack_hash=sh,
        asan_summary=summary_line(report),
        top_frames=frames[:MAX_STACK_FRAMES],
        crash_input_b64=base64.b64encode(crash_bytes).decode("ascii"),
        crash_file=crash_file,
        implicated_file=impl_file,
        in_scanner=in_scanner,
    )
