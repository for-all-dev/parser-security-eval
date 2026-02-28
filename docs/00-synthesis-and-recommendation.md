# Synthesis: Recommended Approach

## The Four Directions

| Doc | Direction | Build Time | Novel? | Risk |
|-----|-----------|-----------|--------|------|
| 02 | OSS-Fuzz Native Eval | Low | Medium | Low |
| 03 | Adversarial RL Environment | High | High | High |
| 04 | Curated Parser Benchmark | Low | Low | Low |
| 05 | Agent Swarm Fuzzing | Medium | Medium | Medium |

These aren't mutually exclusive — they're phases of the same system.

## Recommended Phased Approach

### Phase 1: Curated Benchmark + OSS-Fuzz Harness (Weeks 1-4)

**Combine Directions C + A.** Build a curated parser vulnerability benchmark sourced from ARVO/oss-fuzz, with Inspect-AI task definitions for patching and harness writing.

Deliverables:
- ~100-200 curated parser vulnerabilities with ground truth
- Inspect-AI tasks: vulnerability patching, harness generation, crash triage
- Docker-based sandboxes using oss-fuzz project layouts
- Fuzzer-agnostic: support libFuzzer and AFL++ via oss-fuzz's engine abstraction
- Baseline results for 2-3 frontier models
- Answer: "how good are current models at patching parser bugs?" (compare to AutoPatchBench's ~30%)

Why start here:
- Fastest path to publishable results
- ARVO dataset + oss-fuzz do most of the heavy lifting
- Validates the toolchain before investing in live fuzzing
- The curated set becomes the eval/training curriculum for later phases

### Phase 2: Live Fuzzing + Swarm (Weeks 5-8)

**Combine Directions A + D.** Add live fuzzing campaigns where agent swarms write harnesses and compete.

Deliverables:
- Agent swarm orchestration (N agents, independent sandboxes)
- Live fuzzing with configurable engine (libFuzzer, AFL++, Honggfuzz)
- Crash triage pipeline (CASR or equivalent)
- Scoring: per-agent and swarm-aggregate metrics
- Answer: "what is the incidence of vulns per unit walltime of fuzzing in targeted parsers?"
- Answer: "does agent diversity improve bug discovery?" (plot bugs vs N_agents)

Why next:
- Phase 1 toolchain handles build/run/triage
- Just need orchestration layer + live campaign support
- Directly addresses the core research question from CLAUDE.md

### Phase 3: Adversarial Loop + RL (Weeks 9+)

**Direction B.** Close the red-blue loop. Red team finds bugs → blue team patches → red team tries again on patched version.

Deliverables:
- Multi-round adversarial loop (prompt-only first, RL later)
- PettingZoo-compatible environment API
- Reward signal: coverage + crash severity + patch correctness
- Self-play experiments (single model as both red and blue)
- If RL: PPO training with Ray distributed rollouts

Why last:
- Highest risk, highest reward
- Requires Phases 1+2 to be solid
- Can start with prompt-only (RvB pattern) before investing in RL training

## Key Architectural Decisions

### Fuzzer Agnosticism

The system treats fuzzers as interchangeable engines with a common interface:

```
Input:  harness source + target library + seed corpus + dictionary
Output: crash artifacts + coverage data + execution stats
```

This maps directly to how oss-fuzz works — `build.sh` produces `/out/<target>`, and the engine (libFuzzer, AFL++, Honggfuzz) is selected at build time via `$LIB_FUZZING_ENGINE`.

Red team agents can:
- Write harnesses (any engine — the oss-fuzz `LLVMFuzzerTestOneInput` API is engine-agnostic)
- Choose which engine to use (or the orchestrator assigns one for diversity)
- Optionally write engine-specific configuration (AFL++ dictionaries, libFuzzer flags)

For advanced agents, LibAFL remains an option as a "write your own fuzzer from scratch" mode — but it's not the default path.

### What We Measure

The project answers three questions at increasing ambition:

1. **How good are models at parser security tasks?** (Phase 1 — static benchmark)
   - Patching success rate, CWE classification accuracy, harness coverage

2. **How effective are AI agent swarms at finding parser bugs?** (Phase 2 — live fuzzing)
   - Vulns per CPU-hour, coverage velocity, marginal value of additional agents

3. **Can adversarial training produce better parser security agents?** (Phase 3 — RL)
   - Co-evolutionary improvement curves, transfer to unseen parsers

### Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Orchestrator | Python + Inspect-AI | Already scaffolded, eval framework built-in |
| CLI | Typer | Already in deps |
| Data models | Pydantic | Already in deps |
| Containers | Docker + compose | oss-fuzz compatibility |
| Fuzz engines | libFuzzer, AFL++, Honggfuzz | oss-fuzz standard engines |
| Crash triage | CASR | Multi-engine support, structured JSON output |
| Eval framework | Inspect-AI | Purpose-built for AI evals |
| RL API (Phase 3) | PettingZoo + Gymnasium | Standard multi-agent RL APIs |
| Distributed training | Ray (Phase 3) | Standard for RL workloads |

## Open Questions

1. **Parser definition scope**: How broadly do we define "parser"? Just binary/text format decoders? Or also protocol implementations, query languages, config file parsers?

2. **Language scope**: C/C++ only (where memory safety bugs live)? Or also Rust/Go (where the bug classes are different — logic errors, panics, resource exhaustion)?

3. **Planted vs. real bugs**: Phase 1 uses real historical bugs. Should Phase 2 also include parser targets with intentionally planted bugs (LAVA-M style) for controlled experiments?

4. **Agent API surface**: How much shell access do agents get? Full bash (SWE-bench style)? Or a restricted action space (specific tools only)?

5. **Compute budget**: How much fuzzing time per eval run? 5 minutes (fast iteration)? 1 hour (realistic)? 24 hours (thorough)?
