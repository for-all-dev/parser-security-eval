---
title: Why This Matters
order: 1
---

# Parser Security Eval

Parsers written in C/C++ are a perennial source of memory-safety vulnerabilities. We're building an eval that measures whether AI agents can autonomously discover and fix these bugs — with the long-term goal of creating an **RL environment for [secure program synthesis](https://www.lesswrong.com/posts/8wtrLoDPyCfMLuHkt/how-to-solve-secure-program-synthesis)**.

## Where We Are

These are early results. The patching task (can a model fix a known crash?) gives us a working scoring pipeline, but the harder and more interesting question is **autonomous crash discovery**: can an agent write fuzz harnesses that actually find new bugs? That's the open problem, and closing it is the point of this project.

## Why It Matters

A robust red-blue loop — agents that find vulnerabilities and agents that patch them, iterating against each other — is a natural RL training signal. If we can get the red-team agent working well enough to reliably surface crashes, the whole pipeline becomes a **post-training environment** for teaching models to write secure code. That's the real prize: defense-dominant capability that scales with compute.
