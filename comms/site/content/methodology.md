---
title: What We Built
order: 2
---

# Eval Framework

We built an evaluation framework on [Inspect-AI](https://inspect.ai-safety.org/) that tests frontier models on two tasks against real C parser targets (libpng, libjpeg-turbo, libxml2, zlib):

**Patching** — Given a crash input and vulnerable source, produce a patch that compiles and eliminates the crash. Scored against 209 real CVEs from the [ARVO](https://github.com/AetherSeal/arvo) dataset (a shortlist from 4 targets; ARVO has 5,001 patchable vulnerabilities across ~150 parser projects).

**Fuzzing** — Autonomously write a LibFuzzer harness, compile it, and discover crashes without human guidance. This is the harder task and the active research frontier.

Each run executes in an isolated Docker container with the OSS-Fuzz toolchain.
