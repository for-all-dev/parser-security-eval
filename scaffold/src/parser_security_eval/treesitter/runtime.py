"""Local toolchain for the tree-sitter loop: clone, build, fuzz, reproduce.

This is the nix-provided-clang analogue of
:mod:`parser_security_eval.sandbox.campaign`. It expects ``git``, ``clang`` /
``clang++`` and (only when a grammar ships no generated ``src/parser.c``)
``tree-sitter`` on ``PATH`` — i.e. it is meant to run inside the project's
``nix-shell`` (see ``scaffold/treesitter-shell.nix``).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from parser_security_eval.treesitter.models import (
    GrammarTarget,
    TSBuildResult,
    TSFuzzResult,
)

DEFAULT_CACHE = Path.home() / ".cache" / "parser-security-eval" / "treesitter"
RUNTIME_REPO = "https://github.com/tree-sitter/tree-sitter"

# Compile flags shared by every translation unit. ``fuzzer-no-link`` instruments
# each TU; the final link uses ``fuzzer`` to pull in libFuzzer's main().
_COMMON_FLAGS = [
    "-g",
    "-O1",
    "-fno-omit-frame-pointer",
    "-fsanitize=fuzzer-no-link,address",
]

_LANG_FUNC_DEF_RE = re.compile(r"\btree_sitter_([A-Za-z0-9_]+)\(void\)\s*\{")
_LANG_FUNC_DECL_RE = re.compile(r"\btree_sitter_([A-Za-z0-9_]+)\(void\)")

_HARNESS_TEMPLATE = """\
/* Auto-generated libFuzzer harness for tree-sitter grammar `{symbol}`. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <tree_sitter/api.h>

const TSLanguage *{symbol}(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
  TSParser *parser = ts_parser_new();
  if (!ts_parser_set_language(parser, {symbol}())) {{
    ts_parser_delete(parser);
    return 0;
  }}
  TSTree *tree =
      ts_parser_parse_string(parser, NULL, (const char *)data, (uint32_t)size);
  if (tree != NULL) {{
    /* Walk the tree (recursive s-expression) to exercise more parser code. */
    char *s = ts_node_string(ts_tree_root_node(tree));
    if (s != NULL) {{
      free(s);
    }}
    ts_tree_delete(tree);
  }}
  ts_parser_delete(parser);
  return 0;
}}
"""


class ToolchainError(RuntimeError):
    """Raised when a required external tool is missing or a build step fails."""


def render_harness(symbol: str) -> str:
    """Render the standard tree-sitter libFuzzer harness for *symbol*."""
    return _HARNESS_TEMPLATE.format(symbol=symbol)


def check_toolchain(*, need_generate: bool = False) -> None:
    """Verify required executables are on PATH; raise ToolchainError otherwise."""
    required = ["git", "clang", "clang++"]
    if need_generate:
        required.append("tree-sitter")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise ToolchainError(
            "Missing tools on PATH: "
            + ", ".join(missing)
            + ". Run inside `nix-shell scaffold/treesitter-shell.nix`."
        )


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — args are constructed, not shell-interpolated
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def ensure_runtime(cache_dir: Path = DEFAULT_CACHE) -> Path:
    """Clone the tree-sitter runtime (shallow) if absent; return its path."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / "tree-sitter"
    if not (dest / "lib" / "src" / "lib.c").exists():
        res = _run(["git", "clone", "--depth", "1", RUNTIME_REPO, str(dest)])
        if res.returncode != 0:
            raise ToolchainError(f"Failed to clone tree-sitter runtime:\n{res.stderr}")
    return dest


def ensure_grammar(target: GrammarTarget, cache_dir: Path = DEFAULT_CACHE) -> Path:
    """Clone *target*'s grammar repo (and checkout a pinned commit); return path."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = cache_dir / f"tree-sitter-{target.name}"
    if not dest.exists():
        clone = ["git", "clone"]
        if target.commit is None:
            clone += ["--depth", "1"]
        clone += [target.repo_url, str(dest)]
        res = _run(clone)
        if res.returncode != 0:
            raise ToolchainError(f"Failed to clone {target.repo_url}:\n{res.stderr}")
    if target.commit is not None:
        res = _run(["git", "checkout", target.commit], cwd=dest)
        if res.returncode != 0:
            raise ToolchainError(f"Failed to checkout {target.commit}:\n{res.stderr}")
    return dest


def find_src_dir(grammar_dir: Path, subpath: str = "") -> Path:
    """Locate the directory containing ``src/parser.c`` (or where it should go)."""
    if subpath:
        candidate = grammar_dir / subpath
        if (candidate / "src").exists() or (candidate / "grammar.js").exists():
            return candidate / "src" if (candidate / "src").exists() else candidate
    # Prefer an existing src/parser.c.
    parsers = sorted(grammar_dir.glob("**/src/parser.c"))
    if parsers:
        return parsers[0].parent
    # Otherwise the dir holding grammar.js (generation target).
    grammars = sorted(grammar_dir.glob("**/grammar.js"))
    if grammars:
        return grammars[0].parent / "src"
    return grammar_dir / "src"


def detect_symbol(src_dir: Path, fallback: str) -> str:
    """Read ``parser.c`` for the ``tree_sitter_<name>(void)`` language function."""
    parser_c = src_dir / "parser.c"
    if parser_c.exists():
        text = parser_c.read_text(encoding="utf-8", errors="replace")
        m = _LANG_FUNC_DEF_RE.search(text)
        if m:
            return f"tree_sitter_{m.group(1)}"
        m = _LANG_FUNC_DECL_RE.search(text)
        if m:
            return f"tree_sitter_{m.group(1)}"
    return fallback


def _find_scanner(src_dir: Path) -> Path | None:
    for name in ("scanner.c", "scanner.cc", "scanner.cpp", "scanner.cxx"):
        p = src_dir / name
        if p.exists():
            return p
    return None


def gather_seeds(grammar_dir: Path, corpus_dir: Path, limit: int = 400) -> int:
    """Seed *corpus_dir* from the grammar's own test/example files + literals."""
    corpus_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    patterns = ("test", "examples", "grammars", "queries")
    for path in grammar_dir.rglob("*"):
        if count >= limit:
            break
        if not path.is_file():
            continue
        parts = {p.lower() for p in path.parts}
        if not (parts & set(patterns)):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not data or len(data) > 65536:
            continue
        (corpus_dir / f"seed{count}").write_bytes(data)
        count += 1
    # A few adversarial literals so fuzzing always has something to mutate.
    for i, lit in enumerate(
        (b"{}", b"\xff\xfe\x00bad", b"          x", b"[[[[]]]]", b"\x00")
    ):
        (corpus_dir / f"lit{i}").write_bytes(lit)
        count += 1
    return count


def generate_parser(src_or_grammar_dir: Path) -> tuple[bool, str]:
    """Run ``tree-sitter generate`` in the grammar.js directory; return (ok, log)."""
    # tree-sitter generate must run where grammar.js lives.
    gdir = src_or_grammar_dir
    if gdir.name == "src":
        gdir = gdir.parent
    if not (gdir / "grammar.js").exists():
        return False, f"no grammar.js in {gdir}"
    res = _run(["tree-sitter", "generate"], cwd=gdir, timeout=300)
    return res.returncode == 0, (res.stdout + res.stderr)[-4000:]


@dataclass
class BuildSpec:
    """Inputs needed to (re)compile a grammar's fuzz binary."""

    target: GrammarTarget
    runtime_dir: Path
    grammar_dir: Path
    work_dir: Path

    @property
    def src_dir(self) -> Path:
        return find_src_dir(self.grammar_dir, self.target.subpath)

    @property
    def binary_path(self) -> Path:
        return self.work_dir / f"fuzz_{self.target.name}"


def build(spec: BuildSpec) -> TSBuildResult:
    """Compile the grammar + runtime + harness into a libFuzzer binary."""
    check_toolchain()
    spec.work_dir.mkdir(parents=True, exist_ok=True)
    src_dir = spec.src_dir
    generated = False

    if not (src_dir / "parser.c").exists():
        check_toolchain(need_generate=True)
        ok, log = generate_parser(src_dir)
        generated = ok
        if not ok or not (src_dir / "parser.c").exists():
            return TSBuildResult(
                built=False, generated=ok, compile_errors=f"generate failed:\n{log}"
            )

    symbol = spec.target.symbol or detect_symbol(
        src_dir, f"tree_sitter_{spec.target.name}"
    )
    scanner = _find_scanner(src_dir)

    harness_c = spec.work_dir / "harness.c"
    harness_c.write_text(render_harness(symbol), encoding="utf-8")

    includes = [
        f"-I{spec.runtime_dir / 'lib' / 'include'}",
        f"-I{spec.runtime_dir / 'lib' / 'src'}",
        # Some grammars vendor their own <tree_sitter/parser.h> next to scanner.c
        # and include it with angle brackets, so the grammar src dir must be on
        # the search path too.
        f"-I{src_dir}",
    ]

    # (source, compiler) translation units → object files.
    units: list[tuple[Path, str]] = [
        (harness_c, "clang"),
        (spec.runtime_dir / "lib" / "src" / "lib.c", "clang"),
        (src_dir / "parser.c", "clang"),
    ]
    if scanner is not None:
        cc = "clang++" if scanner.suffix in (".cc", ".cpp", ".cxx") else "clang"
        units.append((scanner, cc))

    objects: list[str] = []
    for source, cc in units:
        obj = spec.work_dir / (source.stem + "__" + source.suffix.lstrip(".") + ".o")
        res = _run([cc, "-c", *_COMMON_FLAGS, *includes, str(source), "-o", str(obj)])
        if res.returncode != 0:
            return TSBuildResult(
                built=False,
                symbol=symbol,
                src_dir=str(src_dir),
                had_scanner=scanner is not None,
                scanner_file=str(scanner) if scanner else None,
                generated=generated,
                compile_errors=f"compiling {source.name}:\n{res.stderr[-4000:]}",
            )
        objects.append(str(obj))

    link = [
        "clang++",
        "-fsanitize=fuzzer,address",
        *objects,
        "-o",
        str(spec.binary_path),
    ]
    res = _run(link)
    if res.returncode != 0:
        return TSBuildResult(
            built=False,
            symbol=symbol,
            src_dir=str(src_dir),
            had_scanner=scanner is not None,
            scanner_file=str(scanner) if scanner else None,
            generated=generated,
            compile_errors=f"linking:\n{res.stderr[-4000:]}",
        )

    return TSBuildResult(
        built=True,
        binary_path=str(spec.binary_path),
        symbol=symbol,
        src_dir=str(src_dir),
        had_scanner=scanner is not None,
        scanner_file=str(scanner) if scanner else None,
        generated=generated,
    )


# libFuzzer final-stats lines, e.g. "stat::number_of_executed_units: 249359".
_STAT_RE = {
    "executions": re.compile(r"stat::number_of_executed_units:\s*(\d+)"),
    "execs_per_sec": re.compile(r"stat::average_exec_per_sec:\s*(\d+)"),
}
_CRASH_PREFIXES = ("crash-", "oom-", "timeout-", "leak-")


@dataclass
class LibFuzzerRunner:
    """Runs a compiled tree-sitter fuzz binary and collects crashes."""

    binary: Path
    corpus_dir: Path
    crashes_dir: Path
    max_len: int = 65536
    rss_limit_mb: int = 2048
    per_input_timeout: int = 20
    extra_flags: list[str] = field(default_factory=list)

    def run(self, duration_seconds: int) -> tuple[TSFuzzResult, list[Path]]:
        """Fuzz for *duration_seconds*; return (result, new crash files)."""
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        before = self._crash_files()

        cmd = [
            str(self.binary),
            str(self.corpus_dir),
            f"-artifact_prefix={self.crashes_dir}/",
            f"-max_total_time={duration_seconds}",
            f"-max_len={self.max_len}",
            f"-rss_limit_mb={self.rss_limit_mb}",
            f"-timeout={self.per_input_timeout}",
            "-print_final_stats=1",
            *self.extra_flags,
        ]
        safety = duration_seconds + 60
        run_timed_out = False
        try:
            res = _run(cmd, timeout=safety)
            rc, log = res.returncode, res.stdout + "\n" + res.stderr
        except subprocess.TimeoutExpired as exc:
            run_timed_out = True
            rc = -1
            log = (
                (exc.stdout or b"").decode("utf-8", "replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )

        after = self._crash_files()
        new_crashes = [p for p in after if p not in before]

        result = TSFuzzResult(
            duration_seconds=duration_seconds,
            crashes_found=len(new_crashes),
            raw_log_tail=log[-4000:],
            corpus_size=sum(1 for _ in self.corpus_dir.iterdir()),
        )
        m = _STAT_RE["executions"].search(log)
        if m:
            result.total_executions = int(m.group(1))
        m = _STAT_RE["execs_per_sec"].search(log)
        if m:
            result.execs_per_sec = float(m.group(1))

        result.oom_killed = rc == 137 or "out-of-memory" in log
        result.timed_out = run_timed_out or "libFuzzer: timeout" in log
        return result, new_crashes

    def _crash_files(self) -> set[Path]:
        if not self.crashes_dir.exists():
            return set()
        return {
            p
            for p in self.crashes_dir.iterdir()
            if p.is_file() and p.name.startswith(_CRASH_PREFIXES)
        }


def reproduce(binary: Path, crash_file: Path, timeout: int = 60) -> tuple[int, str]:
    """Replay a single crashing input; return (returncode, combined output).

    A *timeout/hang* input would hang the replay too, so a TimeoutExpired is
    caught and reported as a libFuzzer timeout rather than propagating (which would
    otherwise abort a whole campaign).
    """
    try:
        res = _run([str(binary), str(crash_file)], timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1, (
            f"ERROR: libFuzzer: timeout\nReplay of {crash_file.name} exceeded "
            f"{timeout}s — the input hangs the parser (pathological parse time)."
        )
    return res.returncode, res.stdout + "\n" + res.stderr
