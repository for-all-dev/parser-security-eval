# Direction D: Agent Swarm Fuzzing

## Summary

Instead of a single red-team agent, deploy a **swarm of diverse agents** — each independently writes its own fuzz harness and fuzzing strategy from scratch. The swarm discovers more bugs through diversity than any single agent could. This directly addresses the CLAUDE.md note: *"each agent can greenfield its own libafl crate?"* — generalized to any fuzzer.

## Why This Direction

- **Diversity beats optimization**: Fuzzing research consistently shows that running diverse fuzzers in parallel finds more bugs than running one optimized fuzzer for longer (see: Google FuzzBench results, EnFuzz ensemble paper)
- **LLMs are good at generating diverse solutions**: Different prompts, temperatures, and models produce meaningfully different harnesses
- **Natural parallelism**: Each agent runs independently, easy to scale horizontally
- **Directly measures agent capability**: How many distinct crash-inducing inputs can N agents find in T time?

## Architecture

```
┌──────────────────────────────────────────┐
│            Swarm Orchestrator             │
│  - spawns agents                         │
│  - collects + deduplicates crashes       │
│  - tracks global coverage                │
│  - scores individual agents              │
└─────┬────────┬────────┬────────┬─────────┘
      │        │        │        │
  ┌───v──┐ ┌──v───┐ ┌──v───┐ ┌──v───┐
  │Agent 1│ │Agent 2│ │Agent 3│ │Agent N│
  │       │ │       │ │       │ │       │
  │Writes │ │Writes │ │Writes │ │Writes │
  │own    │ │own    │ │own    │ │own    │
  │harness│ │harness│ │harness│ │harness│
  └───┬───┘ └──┬───┘ └──┬───┘ └──┬───┘
      │        │        │        │
  ┌───v──┐ ┌──v───┐ ┌──v───┐ ┌──v───┐
  │Fuzzer │ │Fuzzer │ │Fuzzer │ │Fuzzer │
  │Sandbox│ │Sandbox│ │Sandbox│ │Sandbox│
  └───────┘ └──────┘ └──────┘ └──────┘
```

Each agent gets:
- Fresh copy of the parser source code
- Choice of fuzzer engine (or assigned one for diversity)
- Its own isolated sandbox (Docker container)
- A time/compute budget
- No communication with other agents (independent exploration)

## Diversity Strategies

### Strategy 1: Different Fuzz Engines
- Agent 1 uses libFuzzer
- Agent 2 uses AFL++ with MOpt mutation schedule
- Agent 3 uses Honggfuzz
- Agent 4 uses AFL++ with CMPLOG
- Each engine has different strengths → more total coverage

### Strategy 2: Different Harness Approaches
Prompt each agent differently:
- Agent 1: "Focus on the main parsing entry point"
- Agent 2: "Focus on error handling paths"
- Agent 3: "Focus on edge cases in format-specific features"
- Agent 4: "Focus on streaming/incremental parsing APIs"
- Agent 5: "Fuzz the internal helper functions directly"

### Strategy 3: Different LLM Models/Temperatures
- Agent 1: Claude Opus, temp 0.3 (precise, conservative)
- Agent 2: Claude Sonnet, temp 0.8 (creative, diverse)
- Agent 3: GPT-4o, temp 0.5 (different model = different biases)
- Agent 4: DeepSeek-R1, temp 0.6 (strong at code)

### Strategy 4: Grammar vs. Mutation
- Some agents write structure-aware fuzz harnesses (grammar-based)
- Some agents write dumb byte-level harnesses with good seeds
- Some agents focus on dictionary construction (format-specific tokens)
- Coverage overlap between grammar-based and mutation-based is typically low

## Scoring: Individual + Swarm

### Individual Agent Score
```python
score_individual = (
    unique_crashes_found * severity_weight
    + marginal_coverage_contribution  # coverage not found by any other agent
    + first_to_find_bonus             # found a bug before others
)
```

### Swarm Aggregate Score
```python
score_swarm = (
    total_unique_crashes
    + total_unique_coverage
    + coverage_diversity_bonus        # how non-overlapping are agent coverages?
)
```

### Key Metric: Marginal Value of Additional Agents
Plot: `bugs_found(N_agents)` vs `N_agents`. Is the curve sublinear (diminishing returns), linear (great!), or superlinear (synergy)?

This directly answers the CLAUDE.md question: *"what is the incidence of vulns per unit walltime of fuzzing in targeted parsers?"*

## Swarm + Blue Team Integration

After the swarm phase, all crashes are deduplicated and fed to a blue team agent (or blue team swarm):

```
Phase 1: Red Swarm (parallel)
  → N agents each fuzz independently
  → Collect all crashes, deduplicate

Phase 2: Triage (automated)
  → CASR / crash clustering
  → Severity classification
  → Generate structured reports

Phase 3: Blue Team (sequential or parallel)
  → For each unique bug: agent patches, verifies
  → OR: blue team swarm, each agent tackles different bugs

Phase 4: Verification
  → Re-run ALL red team inputs on patched binary
  → Check for regressions
  → Score
```

## Connection to Ensemble Fuzzing Literature

**EnFuzz** (USENIX Security 2019):
- Showed that ensemble fuzzing (running multiple fuzzers with shared seeds) outperforms any individual fuzzer
- Key insight: seed synchronization between fuzzers helps, but even independent runs with dedup at the end is effective
- Our swarm is the AI-agent version of this

**CollabFuzz** (RAID 2021):
- Collaborative fuzzing with strategic seed sharing between heterogeneous fuzzers
- Could extend our swarm: agents share interesting inputs mid-campaign

**FuzzBench** (Google):
- Standardized fuzzer comparison shows no single fuzzer dominates all targets
- Reinforces the diversity argument

## Compose-Based Orchestration

```yaml
# docker-compose.yml
services:
  orchestrator:
    build: ./orchestrator
    volumes:
      - crashes:/shared/crashes
      - coverage:/shared/coverage
    environment:
      - NUM_AGENTS=8
      - TARGET=libpng
      - FUZZ_DURATION=600  # 10 min per agent

  agent:
    build: ./agent-sandbox
    deploy:
      replicas: 8
    volumes:
      - crashes:/shared/crashes  # write crashes here
    environment:
      - TARGET=libpng
      - AGENT_ID={{.Task.Slot}}
    # Each replica gets a unique AGENT_ID via swarm slot

  triage:
    build: ./triage
    depends_on:
      orchestrator:
        condition: service_completed_successfully
    volumes:
      - crashes:/shared/crashes
```

## Advantages
- Directly measures what we care about: how good are AI agents at finding parser bugs?
- Natural parallelism → fast wall-clock time
- Diversity is a feature, not a bug
- Easy to add new agent types / models
- Maps cleanly to the "incidence of vulns per unit walltime" question
- Each agent can truly greenfield its own approach (including choice of fuzzer)

## Risks
- Expensive: N agents × T time × compute per agent
- Deduplication across agents is non-trivial (different harnesses = different crash formats)
- Hard to attribute bugs to specific agent strategies (which diversity dimension mattered?)
- No adversarial pressure on blue team (blue team just patches what red team found)
- Coordination overhead if adding seed sharing
