---
title: Overview
order: 1
---

# Baseline: Vulns per CPU-Hour

This experiment establishes the baseline crash discovery rate for AI-assisted fuzzing on Tier 1 parser targets, directly addressing our core research question:

> **What is the incidence of vulnerabilities per unit walltime of fuzzing in targeted parsers?**

We run single-agent live fuzzing across four widely-deployed C parsers, comparing multiple frontier language models against each other and against non-AI baselines. The key comparison is whether short LLM reflection cycles (30-minute windows) outperform a continuous two-hour run—a hypothesis strongly supported by recent literature (PBFuzz, HGFuzzer, RandLuzz).

## Targets

| Library | Domain | OSS-Fuzz ID |
|---------|--------|-------------|
| **libpng** | PNG image parsing | libpng |
| **libjpeg-turbo** | JPEG image decoding | libjpeg_turbo |
| **libxml2** | XML/HTML parsing | libxml2 |
| **zlib** | Deflate compression | zlib |

These targets represent high-value, widely-deployed parsers with known historical vulnerabilities, making them ideal baselines.

## Conditions

- **30-min cycles**: Agent runs in 30-minute fuzzing windows, with an LLM synthesis step between each cycle to reflect on coverage gaps and update the harness. This is the architecture recommended by the literature.
- **2-hr continuous**: Agent runs for a straight two hours without mid-run LLM interaction. Serves as the primary comparison point.
- **OSS-Fuzz baseline**: Existing OSS-Fuzz harness, no agent, identical time budget.
- **Random harness**: Randomly mutated harness, lower baseline.

## What We Measure

- **Unique crashes found** vs. wall time
- **Coverage (%)** vs. wall time
- **Crashes per CPU-hour** (primary headline metric)
- **Harness quality**: how many compilation attempts did the agent need?
- **Time to first crash**
