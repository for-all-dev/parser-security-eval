# Direction B: Adversarial RL Post-Training for Parser Security

## Summary

Use LM post-training RL (GRPO/PPO over token-level completions) to train models that are better at attacking and defending parsers. Red team and blue team are not "agents in a gym" — they're LM completions with different system prompts and tool access, orchestrated by scaffolding (like claude-code subagents). The reward signal comes from fuzzing outcomes.

## Why This Direction

- **Self-play is the endgame**: SSR (Self-Play SWE-RL) showed a single model playing both injector and solver, trained via PPO over completions, beats human-data baselines by 10+ points on SWE-bench
- **Adversarial pressure produces robustness**: Red team finds increasingly subtle bugs → blue team produces increasingly robust patches → parsers get genuinely more secure
- **Reward signal is natural**: crashes = red team reward, crash elimination = blue team reward. No need for synthetic labels.
- **Novel contribution**: No existing RL post-training pipeline uses fuzzer output as reward signal for code security

## How LM Post-Training RL Works Here

This is **not** gym-style RL with discrete observations and actions. The paradigm is:

1. **The model generates a completion** (a fuzz harness, a patch, a series of bash commands)
2. **The completion is executed** in a sandboxed environment (Docker container with fuzzer + parser)
3. **An outcome is observed** (crashes found? patch successful? tests pass?)
4. **The outcome becomes a reward** for that completion
5. **The model's weights are updated** via GRPO/PPO to make high-reward completions more likely

This is the same paradigm as DeepSeek-R1 (reward from math correctness), SWE-RL (reward from test pass/fail), and OpenAI's code-contest training. The "environment" is just the sandbox that executes the model's output and computes a scalar reward.

### Multi-Agent = Scaffolding, Not PettingZoo

Red and blue teams are orchestrated by **scaffolding** — the same way claude-code spawns subagents:

```python
# This is scaffolding, not a gym environment
async def adversarial_episode(target: str, model: str):
    sandbox = await create_sandbox(target)

    # Red team: LM completion with red-team system prompt + tools
    red_result = await run_agent(
        model=model,
        system_prompt=RED_TEAM_PROMPT,
        tools=[write_file, run_bash, run_fuzzer],
        sandbox=sandbox,
        max_turns=20,
    )

    crashes = await triage_crashes(sandbox)

    # Blue team: LM completion with blue-team system prompt + tools
    blue_result = await run_agent(
        model=model,
        system_prompt=BLUE_TEAM_PROMPT,
        tools=[read_file, edit_file, run_bash, rebuild, verify_fix],
        sandbox=sandbox,
        context=crashes,  # crash reports as input
        max_turns=20,
    )

    # Compute rewards from outcomes
    red_reward = compute_red_reward(crashes)
    blue_reward = compute_blue_reward(sandbox, crashes)

    return red_result, blue_result, red_reward, blue_reward
```

The agents are just LM completions with different prompts. The "multi-agent" aspect is a scaffolding/orchestration concern — who runs when, what context they see, what tools they have access to.

## Reward Formulation

### Red Team Reward (per episode)

The model generates a fuzz harness + configuration. The reward is computed after executing it:

```python
def red_reward(crashes, coverage_before, coverage_after):
    coverage_bonus = 0.1 * (coverage_after.edges - coverage_before.edges)
    crash_bonus = sum(severity_score(c) for c in new_unique_crashes(crashes))
    return coverage_bonus + crash_bonus
```

### Blue Team Reward (per episode)

The model generates patches. The reward is computed after rebuilding and verifying:

```python
def blue_reward(patches, test_results):
    fix_bonus = 3.0 * sum(1 for p in patches if p.crash_eliminated)
    regression_penalty = -1.0 * sum(1 for p in patches if p.tests_regressed)
    minimality_bonus = 0.1 * sum(1 for p in patches if p.diff_lines < 10)
    return fix_bonus + regression_penalty + minimality_bonus
```

### Episode Structure

```
Episode:
  1. Reset: fresh parser target (may have planted or real bugs)
  2. Red team turn (bounded: N actions or T seconds):
     - Write harness, configure fuzzer, run campaign
     - Collect crashes
  3. Crash triage (automated):
     - Deduplicate, classify severity, generate reports
  4. Blue team turn (bounded: M actions or T seconds):
     - For each crash: read report, patch source, verify
  5. Verification (automated):
     - Re-run all triggering inputs on patched binary
     - Run test suite for regressions
  6. Score:
     - Red: unique crashes × severity
     - Blue: patches accepted / total crashes
  7. Optional: repeat from step 2 on the patched version (multi-round)
```

### Reward Design (Detail)

```python
# Red team reward
def red_reward(crashes, coverage_before, coverage_after):
    coverage_bonus = 0.1 * (coverage_after.edges - coverage_before.edges)
    crash_bonus = sum(severity_score(c) for c in new_unique_crashes(crashes))
    return coverage_bonus + crash_bonus

# Blue team reward
def blue_reward(patches, test_results):
    fix_bonus = 3.0 * sum(1 for p in patches if p.crash_eliminated)
    regression_penalty = -1.0 * sum(1 for p in patches if p.tests_regressed)
    minimality_bonus = 0.1 * sum(1 for p in patches if p.diff_lines < 10)
    return fix_bonus + regression_penalty + minimality_bonus

# Severity scoring (ASAN error type → approximate CVSS)
SEVERITY = {
    "heap-buffer-overflow": 3.0,    # often exploitable
    "heap-use-after-free": 3.0,     # often exploitable
    "stack-buffer-overflow": 2.5,   # exploitable but harder
    "global-buffer-overflow": 2.0,
    "heap-double-free": 2.0,
    "stack-use-after-return": 1.5,
    "use-of-uninitialized-value": 1.0,
    "integer-overflow": 1.0,        # UBSAN
    "null-dereference": 0.5,        # usually just DoS
    "assertion-failure": 0.3,
    "timeout": 0.1,
    "oom": 0.1,
}
```

## Training Pipeline

### Phase 1: Prompt-Only (No Training)

Use the RvB pattern — LLM agents with carefully designed system prompts, no weight updates. This validates:
- The scaffolding and sandbox work end-to-end
- The reward signal is informative and discriminative
- Episode turnaround is fast enough

This is just Inspect-AI evals with prompt engineering. The "RL" comes later.

### Phase 2: RL Post-Training (Single Role)

Train two separate models (or LoRA adapters):
- **Red model**: GRPO/PPO, reward = crashes found per episode
- **Blue model**: GRPO/PPO, reward = patches verified per episode
- Training data: rollouts across many parser targets
- Infrastructure: standard LM post-training pipeline (vLLM/SGLang for inference, DeepSpeed/FSDP for training)

This is the DeepSWE/R2E-Gym paradigm applied to parser security. The model generates a full completion (harness or patch), it gets executed, and the outcome is a scalar reward.

### Phase 3: Self-Play

SSR pattern — single base model, two LoRA adapters (red + blue), trained alternately:
1. Red adapter generates harness → fuzz → collect crashes → reward red
2. Blue adapter patches crashes → verify → reward blue
3. Repeat on patched codebase — red must find *new* bugs
4. Alternate training: freeze blue, train red on harder targets; freeze red, train blue on harder crashes

The key insight from SSR: self-play eliminates the need for curated vulnerability datasets. The model generates its own training signal.

## Speed Considerations

RL training requires thousands of episodes. Key bottleneck: **target build time**.

| Approach | Reset Time | Storage | Suitability |
|----------|-----------|---------|-------------|
| Docker per episode | ~90s | High | Eval only |
| Mount namespace + chroot (SWE-MiniSandbox) | ~25s | Low | RL-viable |
| Pre-compiled target + copy | ~5s | Medium | Best for RL |
| In-process fuzzing (no rebuild) | ~1s | Minimal | Red-team only |

**Recommendation**: Pre-compile the target binary with sanitizers. For red-team episodes (harness writing), no rebuild needed — just compile the new harness and link against the existing target. For blue-team episodes, incremental rebuild (only recompile changed files).

## What the Agent Actually Does

The agent is an LM generating text. Its "actions" are:
- **Generating code**: fuzz harnesses (C/C++), patches (diffs), build scripts
- **Generating bash commands**: running the fuzzer, checking coverage, verifying fixes
- **Reasoning in chain-of-thought**: deciding what to fuzz, analyzing crash reports

These are all just tokens in a completion. The scaffolding parses tool calls from the completion (like claude-code does), executes them in the sandbox, and feeds results back as the next turn. The full multi-turn trajectory is the "rollout" for RL.

The reward is computed from the final state of the sandbox after the agent finishes its turns — not from individual actions.

## Advantages
- Novel research contribution (no existing RL post-training pipeline for parser security)
- Self-play eliminates need for curated vulnerability datasets
- Adversarial dynamics produce genuinely more robust parsers
- Natural curriculum: easy targets first, harder targets as agents improve
- Same paradigm as proven systems (DeepSeek-R1, SWE-RL, OpenAI code-contest)

## Risks
- RL post-training is expensive (compute + engineering time)
- Fuzzing non-determinism makes reward signal noisy (need multiple rollouts per target to reduce variance)
- Sandbox turnaround time matters — each RL step requires executing the completion
- Need significant number of diverse parser targets for generalization
- Red-team completions can be very long (writing a full fuzz harness from scratch)
