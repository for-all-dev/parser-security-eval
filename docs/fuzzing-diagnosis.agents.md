# Fuzzing Score Diagnosis — Issue #110

## Date: 2026-03-29

## Problem

All 12 fuzzing-baseline runs scored `_live_fuzzing_scorer: mean=0.0` with
`total_time: 0.0` in results.json. Initial hypothesis was that the agent
couldn't find crashes, but investigation revealed **two infrastructure bugs**.

## Root Causes

### Bug 1: `_session_state` not surviving message limit (9/12 runs)

The solver stashes `session_state` into `state.metadata["_session_state"]` at
the end of the `solve()` function (line ~738). But when the agent hits the
120-message limit, Inspect-AI's `generate()` raises a `LimitExceededError`.
This exception propagates up through the solver, **skipping the metadata
stash**. Inspect-AI then catches the exception in its own `task_run_sample()`
and passes the pre-solver state (without `_session_state`) to the scorer.

**Evidence:** All 9 non-libpng runs have 120 messages (the limit), real
execution times (11min–98min), and the agent was actively compiling harnesses
and running fuzzing — but the scorer reports "No session state found."

**Fix:** Wrap `generate()` in `try/except BaseException` to stash
`_session_state` before re-raising. Also use `state.store` (Inspect-AI's
recommended solver→scorer communication mechanism) in addition to
`state.metadata`.

### Bug 2: Build failure early return without session state (3/12 runs — libpng)

When `sandbox.build_target()` fails, the solver returns early at line 708
without stashing `_session_state`. These runs only have 3 messages and
15–50 seconds of execution.

**Fix:** Call `_stash_session_state(state)` on the early return path too.

### Bug 3: `total_time` always 0.0

The `extract_run_result()` function in `experiments/state.py` checks for
`log.stats.eval_time`, but `EvalStats` in Inspect-AI 0.3.184 doesn't have
that attribute. It only has `started_at` and `completed_at`.

**Fix:** Fall back to computing duration from `completed_at - started_at`.

## What the Agent Actually Did

Looking at the eval logs for the 9 runs that hit message limit:

- **libjpeg-turbo:** Agent wrote harnesses, compiled (with repairs), ran fuzzing.
  Lots of compile errors around include paths. Eventually got harnesses
  compiling. Found 0 unique crashes but did run fuzzing campaigns.

- **libxml2:** Similar pattern — initial `#include <libxml/parser.h>` failures,
  then fixed. Ran fuzzing, found some "slow-unit" crashes (timeouts/
  algorithmic complexity). Agent was actively iterating at message limit.

- **zlib:** Agent wrote harnesses, compiled, fuzzed. No crashes in short runs.

- **libpng:** Build failed in sandbox — never got to harness writing.

## Key Learnings

1. **Inspect-AI's `state.metadata` is fragile for solver→scorer data** when
   limits/exceptions are involved. Use `state.store` instead — it's designed
   for this and persists through the Store context var.

2. **The agent IS doing real work.** The fuzzing runs are not trivially broken.
   Zero crashes in short windows (60–300s) against hardened parsers is a
   plausible result, but we need the scorer fix to confirm with real scores.

3. **libpng build failure** needs separate investigation — likely a Docker
   image or dependency issue in the sandbox.

## Next Steps

- [ ] Small test run to validate the fix (single target, short duration)
- [ ] If fix works, rerun full experiment grid
- [ ] Investigate libpng build failure separately
- [ ] Consider whether `compile_score` and `coverage_score` components of the
      scorer are capturing useful signal even when crash_score is 0
