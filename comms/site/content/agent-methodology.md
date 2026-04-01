---
title: Fuzz Agent
order: 3
---

# Fuzz Agent Architecture

The fuzzing agent runs a refinement loop: read the target source, generate a LibFuzzer harness, compile it, run the fuzzer, review coverage, and iterate. Current agents successfully generate and compile harnesses but don't yet find crashes within tested time budgets.

Recent literature (PBFuzz, HGFuzzer, RandLuzz) shows LLM-in-the-loop fuzzing can substantially outperform static baselines. Closing the gap between our harness-generation results and autonomous crash discovery is the core research question — and getting there unlocks the red-blue RL loop that makes this project worth funding.
