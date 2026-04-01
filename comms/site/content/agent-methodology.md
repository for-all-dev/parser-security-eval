---
title: Methodology
order: 3
---

# Agent Architecture

Each fuzzing run uses a single agent executing a fixed refinement loop:

1. **Reads the target source** to understand the public API surface and primary parsing entry points.
2. **Generates a LibFuzzer harness** — a small C/C++ file that exercises the parser with mutated inputs.
3. **Compiles the harness** in the Docker sandbox. If compilation fails, the agent diagnoses the error and rewrites.
4. **Runs the fuzzer** for a configurable window, then reviews coverage feedback and updates the harness for the next cycle.

This loop repeats until the time budget is exhausted or a crash is found.

## Literature Context

The cyclic harness-refinement approach is motivated by recent work showing LLM-in-the-loop fuzzing substantially outperforms static baselines:

- **PBFuzz** (arXiv:2512.04611): 25.6× speedup over AFL++ within 30-minute budgets
- **HGFuzzer** (arXiv:2505.03425): 24.8× speedup; 11/17 vulnerabilities triggered within the first minute
- **RandLuzz** (arXiv:2507.22065): 2.1–4.8× speedup from LLM-synthesized seeds

Our current results show agents successfully generating and compiling harnesses across all four targets, but finding zero crashes within the tested time budgets — the gap between harness quality and autonomous crash discovery is the active research question driving the next phase.
