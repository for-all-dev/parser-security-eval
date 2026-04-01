---
title: What We Built
order: 2
---

# Eval Framework

We built an end-to-end evaluation framework on top of [Inspect-AI](https://inspect.ai-safety.org/) that tests frontier AI models on two complementary tasks:

**Patching** — Given a crash-triggering input and the vulnerable parser source, can the model produce a correct patch? A patch is scored on whether it applies cleanly, compiles, eliminates the crash, and passes the existing test suite.

**Fuzzing** — Can an AI agent autonomously write a LibFuzzer harness, compile it against the target, and discover crashes — without human guidance?

## Benchmark

The patching task is grounded in **ARVO** (Automated Reproduction of Vulnerabilities from OSS-Fuzz) — a dataset of 209 real-world CVE patches from the OSS-Fuzz corpus, each paired with a crash-triggering input and the exact vulnerable source snapshot. This gives ground-truth pass/fail scoring against historical bugs that actually shipped in production software.

## Targets

| Library | What it parses |
|---------|----------------|
| **libpng** | PNG images |
| **libjpeg-turbo** | JPEG images |
| **libxml2** | XML and HTML |
| **zlib** | Deflate / gzip compression |

These four libraries are foundational to the internet — embedded in browsers, servers, mobile OS frameworks, and embedded systems. They have a decades-long history of memory-safety CVEs.

## Infrastructure

Each eval run executes inside an isolated Docker container with the OSS-Fuzz LLVM/Clang toolchain. The framework supports multi-model sweeps, configurable time budgets, and structured result export — making it straightforward to expand coverage to more models, more targets, and longer fuzzing campaigns as compute budget grows.
