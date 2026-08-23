# Homelab ablation run: LLM-in-loop fuzzing vs plain libFuzzer (tree-sitter)

Purpose: the one clean test of the funded hypothesis — **does an LLM that writes
and refines the fuzz harness with coverage feedback find more/faster than a plain
fuzzer on the same targets?** This is the "treatment" arm; the control already
exists at `scaffold/results/treesitter-baseline` (plain libFuzzer, fixed harness
template, no LLM in the discovery loop).

Runs on the homelab (Opus 5). This machine only built and smoke-verified it.

## Prerequisites

- **nix** installed. The toolchain (clang w/ libFuzzer+ASan, llvm-symbolizer,
  tree-sitter CLI, nodejs, git) comes from `scaffold/treesitter-shell.nix`.
  Verified on 2026-08-23: nixpkgs clang 21.1.2 builds+runs `-fsanitize=fuzzer,address`
  and coverage (`cov:`) parses — no extra sanitizer setup needed.
- **`uv`** on PATH (`~/.local/bin`); the nix-shell preserves ambient PATH.
- **`ANTHROPIC_API_KEY`** in the environment, with Opus-5 access and headroom for
  ~40–60M tokens (mostly cache reads; ~1M tokens per capable-model agent-run).
- Outbound HTTPS to the Anthropic API and to GitHub (grammar clones).
- Disk for the tree-sitter runtime + grammar clones + corpora/crashes under
  `~/.cache/parser-security-eval/treesitter/`.

## Setup on the homelab

```bash
git pull                       # get the uplift-ablation branch
cd scaffold && uv sync         # if the venv isn't present
```

## Run (treatment arm)

```bash
nix-shell scaffold/treesitter-shell.nix --run 'cd scaffold && uv run parser-security-eval treesitter llm-fuzz \
  -g nushell-nu,gren,foam,typst,sql \
  -m anthropic:claude-opus-5 \
  --window 300 --max-iterations 5 --reps 3 \
  --out-dir results/treesitter-llm'
```

- `-g`: the five grammars where the original survey found memory-safety crashes
  (nushell-nu global-buffer-overflow, gren heap-buffer-overflow, foam SEGV,
  typst SEGV, sql leaks). Good first pass: can the LLM arm recover known bugs?
- `--window 300 --max-iterations 5`: up to 5 harness iterations × 300s = 1500s of
  fuzzing per grammar-rep, with an LLM harness rewrite between windows.
- `--reps 3`: variance (the prior work had reps=1 everywhere — no error bars).

Outputs stream to `results/treesitter-llm/<grammar>.jsonl` (same `TSLoopIteration`
schema as the control, so `baseline-compare` works unchanged).

## Compare against the control

```bash
uv run parser-security-eval treesitter baseline-compare \
  --hybrid results/treesitter-llm --baseline results/treesitter-baseline
```

## IMPORTANT methodology note — match the fuzz budget

The existing control ran ~300s per grammar for most of the 118. The treatment
above fuzzes up to 1500s per grammar (5×300). **That is not equal fuzz-seconds**,
so a raw crash tally would confound "LLM helped" with "fuzzed 5× longer" — the
exact trap the first tree-sitter round fell into.

For a clean discovery-uplift claim, do ONE of:

1. **Equal-budget control (preferred):** re-run plain libFuzzer on just these five
   grammars at the same total budget (1500s each) and compare against that, not
   the old 300s baseline. Use `treesitter baseline` with a matched duration.
2. **Coverage-normalized read:** compare `coverage_pcs` trajectories and
   crashes-per-fuzz-second, not absolute crash counts.

The real uplift signal to look for: (a) treatment reaches **higher coverage** than
the fixed-template control at equal fuzz-seconds, and/or (b) treatment finds
crashes the equal-budget control does not. If neither holds, that is a genuine
(and now cleanly-measured) negative result — unlike the prior rounds.

Optional stronger test: add a few grammars where the control found **nothing**, to
probe the "too hard for vanilla fuzzing, tractable with LLM harnesses" niche.

## What was changed to make this measurable

The single-agent OSS-Fuzz loop (`tasks/fuzzing.py`) previously discarded all
coverage feedback to the model. That channel is now live (coverage + zero-coverage
diagnostic surfaced to the agent); the tree-sitter treatment arm was built with the
feedback loop closed from the start. See memory `uplift-ablation-direction`.
