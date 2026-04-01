---
title: Why This Matters
order: 1
---

# The Problem

Every program that processes untrusted input is a potential exploit surface. Parsers are especially dangerous: they're written in C/C++ for performance, they run in attack-reachable paths by definition, and they have a decades-long track record of memory-safety bugs. libpng, libjpeg-turbo, libxml2, and zlib are foundational to the modern internet — and they consistently appear in CVE databases year after year.

AI-assisted code generation is making this worse by default. More code, written faster, means more attack surface. Models that can generate plausible-looking C don't automatically generate *safe* C. The number of vulnerabilities introduced per line of AI-generated code is not zero, and the scale of deployment is growing rapidly.

## The Opportunity

**Secure program synthesis** — AI that can not only write code but also find and fix its own vulnerabilities — is one of the highest-leverage defensive capabilities we can develop. If frontier models become genuinely good at patching memory-safety bugs in production parsers, that skill is directly deployable: as a post-training target, as a code review tool, and eventually as a self-improving agent in a red-blue security loop.

These are defense-dominant evaluations. Unlike dangerous-capability evals, we actively *want* models to score well on these. Getting this kind of eval into posttraining — across as many models as possible — accelerates the defensive side of the AI security race.

## What the Numbers Mean

The patching results show that current frontier models are already meaningfully capable: Claude Opus 4.6 patches ~76% of vulnerabilities across four targets, with 100% success on zlib and near-70% on libpng. The model stratification is clear and consistent.

The fuzzing results show that autonomous crash discovery is an open problem — models can generate and compile harnesses but do not yet find crashes within typical time budgets. This is the research frontier, and closing it is the goal of the next phase.
