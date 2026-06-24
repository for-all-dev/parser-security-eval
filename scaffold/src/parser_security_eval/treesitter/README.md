# tree-sitter fuzz → fix → JSONL loop

A local-toolchain analogue of the Docker/OSS-Fuzz live-fuzzing pipeline in
`tasks/fuzzing.py`, applied to **tree-sitter grammars**. The loop is *driven by the
fuzzer*: build a grammar into a libFuzzer binary, fuzz it, and when it crashes,
that crash triggers an LLM fixer that patches the implicated source (an external
`scanner.c`/`.cc`, or `grammar.js`), rebuild, replay the crashing input to verify,
append a JSONL record, and keep fuzzing the patched parser for the next bug.

## Toolchain (nix, not Docker)

Needs `clang` (libFuzzer + ASan), `llvm` (symbolizer), the `tree-sitter` CLI,
`nodejs` and `git` — all provided by `scaffold/treesitter-shell.nix`. `uv` is taken
from the ambient PATH (`~/.local/bin`), which `nix-shell` preserves. The LLM fixer
uses the `anthropic` SDK and reads `ANTHROPIC_API_KEY` from the environment.

## Run

```bash
nix-shell scaffold/treesitter-shell.nix --run '
  export ANTHROPIC_API_KEY=...
  cd scaffold
  uv run parser-security-eval treesitter list
  uv run parser-security-eval treesitter fuzz toml --iterations 3 --duration 120
  uv run parser-security-eval treesitter sweep --tier less-popular
'
```

`--commit <sha>` pins a grammar to a revision — e.g. a known-buggy commit, to
replay a real historical bug. JSONL is streamed to `scaffold/results/treesitter/<grammar>.jsonl`
(gitignored), one record per iteration.

## Reproducible demo bugs (real, historical, fuzzer-found)

| Grammar | Buggy parent commit | Bug | Fix commit |
|---|---|---|---|
| ruby (popular) | `ab6dca77` | heredoc serialization buffer overflow | `ad907a6` |
| hcl / terraform dialect (less-popular) | `e936d3fe` | serialize buffer size-check undercount | `e2d416a` |

```bash
# popular, real crash → Opus patches scanner.c → verified
uv run parser-security-eval treesitter fuzz ruby --commit ab6dca77a8184abc94af6e3e82538741b5078d63 -i 2 -t 60
```
(The hcl/terraform bug lives in the `dialects/terraform` subpath; drive it via
`run_loop` with `GrammarTarget(subpath="dialects/terraform", commit="e936d3fe…")`.)

## Layout

- `models.py` — pydantic records (`GrammarTarget`, `TSCrash`, `TSFixAttempt`, `TSLoopIteration`, …)
- `registry.py` — popular + less-popular grammar registry
- `runtime.py` — clone / generate / compile / `LibFuzzerRunner` / reproduce
- `triage.py` — ASan/libFuzzer parsing → bug class + stack-hash dedup + implicated file
- `fixer.py` — `Fixer` protocol + `LLMFixer` (Anthropic) + apply/regenerate/rebuild/verify
- `loop.py` — the fuzzer-driven orchestration loop + registry sweep
- `cli.py` — `treesitter list | fuzz | sweep`
