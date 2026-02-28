# Direction B: Adversarial RL Environment

## Summary

Build a PettingZoo-compatible multi-agent RL environment where a red team agent and blue team agent co-evolve. The red team writes/tunes fuzz harnesses and mutation strategies; the blue team patches vulnerabilities. The fuzzer is the physics engine of this game world.

## Why This Direction

- **Self-play is the endgame**: SSR (Self-Play SWE-RL) showed a single model playing both injector and solver, trained via PPO, beats human-data baselines by 10+ points on SWE-bench
- **Adversarial pressure produces robustness**: Red team finds increasingly subtle bugs → blue team produces increasingly robust patches → parsers get genuinely more secure
- **Reward signal is natural**: crashes = red team reward, crash elimination = blue team reward. No need for synthetic labels.
- **Novel contribution**: No existing RL environment uses fuzzer output as reward signal for code security agents

## Game Formulation

### Two-Player Asymmetric Game

**Red Team** (attacker):
- **State**: parser source code, current coverage map, crash history
- **Actions**: write/modify fuzz harness, configure mutator, add seeds, run fuzzing campaign
- **Reward**: +severity_score per new unique crash, +coverage_delta for new edges

**Blue Team** (defender):
- **State**: parser source code, crash report (ASAN output + stack trace + triggering input), test suite
- **Actions**: read code, search, edit files, rebuild, verify fix
- **Reward**: +3 per crash successfully patched (crash gone + tests pass), -1 per regression introduced

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

## Environment API (PettingZoo-Compatible)

```python
class ParserSecurityEnv(pettingzoo.ParallelEnv):
    """Multi-agent parser security environment."""

    metadata = {"name": "parser_security_v0"}
    possible_agents = ["red_team", "blue_team"]

    def reset(self, target: str, seed: int = None):
        """Reset with a fresh parser target."""
        self._setup_sandbox(target)
        self._build_target(sanitizers=["address", "undefined"])
        observations = {
            "red_team": self._red_observation(),   # source + API surface
            "blue_team": None,                      # blue waits for crashes
        }
        return observations, {}

    def step(self, actions: dict[str, Action]):
        """Execute agent actions."""
        # Actions are bash commands executed in sandbox
        # Returns: observations, rewards, terminations, truncations, infos
        ...

    def _red_observation(self):
        return {
            "source_files": self._list_source(),
            "coverage_map": self._get_coverage(),
            "crash_history": self._get_crashes(),
            "available_engines": ["libfuzzer", "afl++", "honggfuzz"],
        }

    def _blue_observation(self, crash_reports):
        return {
            "crash_reports": crash_reports,  # ASAN output + stack trace
            "source_files": self._list_source(),
            "test_suite": self._get_tests(),
        }
```

## Training Architecture

### Phase 1: Prompt-Only (No Training)

Use the RvB pattern — LLM agents with carefully designed prompts, no gradient updates. This validates:
- The game loop works end-to-end
- The reward signal is informative
- The environment resets fast enough

### Phase 2: RL Fine-Tuning

Use the DeepSWE/R2E-Gym pattern:
- Sparse binary reward per episode (PPO)
- Train on many parser targets simultaneously
- Ray for distributed rollouts across targets

### Phase 3: Self-Play

Use the SSR pattern:
- Single model plays both red and blue roles (differentiated by system prompt)
- PPO with self-play curriculum
- Model discovers increasingly subtle bugs and increasingly robust patches

## Speed Considerations

RL training requires thousands of episodes. Key bottleneck: **target build time**.

| Approach | Reset Time | Storage | Suitability |
|----------|-----------|---------|-------------|
| Docker per episode | ~90s | High | Eval only |
| Mount namespace + chroot (SWE-MiniSandbox) | ~25s | Low | RL-viable |
| Pre-compiled target + copy | ~5s | Medium | Best for RL |
| In-process fuzzing (no rebuild) | ~1s | Minimal | Red-team only |

**Recommendation**: Pre-compile the target binary with sanitizers. For red-team episodes (harness writing), no rebuild needed — just compile the new harness and link against the existing target. For blue-team episodes, incremental rebuild (only recompile changed files).

## Fuzzer Abstraction Layer

Since we're fuzzer-agnostic, define a common interface:

```python
class FuzzerEngine(Protocol):
    def build_harness(self, harness_source: str, target_lib: Path) -> Path:
        """Compile fuzz harness, return binary path."""
        ...

    def run(self, binary: Path, corpus: Path, duration: int,
            crashes_dir: Path) -> FuzzResult:
        """Run fuzzing campaign, return results."""
        ...

    def get_coverage(self, binary: Path, corpus: Path) -> CoverageReport:
        """Generate coverage report from corpus replay."""
        ...

@dataclass
class FuzzResult:
    crashes: list[CrashInfo]
    coverage: CoverageReport
    execs_per_sec: float
    total_execs: int

class LibFuzzerEngine(FuzzerEngine): ...
class AFLPlusPlusEngine(FuzzerEngine): ...
class HonggfuzzEngine(FuzzerEngine): ...
```

## Advantages
- Novel research contribution (no existing RL env for parser security)
- Self-play eliminates need for curated vulnerability datasets
- Adversarial dynamics produce genuinely more robust parsers
- Natural curriculum: easy targets first, harder targets as agents improve

## Risks
- RL training is expensive (compute + engineering time)
- Fuzzing non-determinism makes reward signal noisy
- Environment reset time may bottleneck training
- Red-team agent action space is very large (writing arbitrary C code)
- Need significant number of diverse parser targets for generalization
