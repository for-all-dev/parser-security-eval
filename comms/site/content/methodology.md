---
title: Methodology
order: 2
---

# Methodology

## Agent Architecture

Each run uses a single agent (no swarm) that:

1. **Reads the target library source** to understand the public API surface.
2. **Generates a LibFuzzer harness** using the LLM, targeting the parser's primary entry points.
3. **Compiles and runs the harness** in a Docker sandbox mirroring the OSS-Fuzz environment.
4. In **30-min cycle mode**: after each 30-minute fuzzing window, the agent reviews coverage feedback and coverage gaps, then rewrites or mutates the harness for the next window.
5. In **continuous mode**: the agent generates a harness once and runs it for the full two hours.

## Fuzzing Engine

The default engine is **libFuzzer** (LLVM's in-process coverage-guided fuzzer), with AFL++ comparison runs for a subset of configurations. The sandbox uses the OSS-Fuzz project layout to ensure results are comparable to historical OSS-Fuzz campaigns.

## Statistical Design

- **3+ replicates** per configuration (different random seeds)
- Reported values are means ± standard deviation across replicates
- Minimum two-hour wall-clock budget per run
- CPU time reported as wall-clock × CPU count

## Literature Motivation

The 30-min cycle condition is directly motivated by:

- **PBFuzz** (arXiv:2512.04611): 25.6× speedup over AFL++ with CmpLog within 30-minute budgets
- **HGFuzzer** (arXiv:2505.03425): 24.8× speedup, 11/17 vulnerabilities triggered within the first minute
- **RandLuzz** (arXiv:2507.22065): 2.1–4.8× speedup from LLM-synthesized seeds

All three papers find that short cycles with LLM reflection dramatically outperform longer continuous runs. This experiment directly tests and quantifies that finding for our specific parser targets.

## Infrastructure

Runs execute inside isolated Docker containers with:

- Ubuntu 22.04 base
- LLVM/Clang toolchain matching the OSS-Fuzz environment
- Network-isolated from the host (harness generation happens before container launch)
- CPU and memory limits enforced per-container
