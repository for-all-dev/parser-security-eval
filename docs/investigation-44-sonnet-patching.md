# Investigation: claude-sonnet-4-6 Unexpectedly Poor at Vulnerability Patching Eval

**Issue:** #44
**Date investigated:** 2026-03-01
**Eval log examined:** `scaffold/logs/2026-02-28T20-38-26+00-00_vulnerability-patching_N5gqpyZSzmDtrbZvWadEMq.eval`
**Result under investigation:** mean score = 0.032 (1/31 samples > 0.0, none at 1.0)

---

## Executive Summary

The extremely poor performance of claude-sonnet-4-6 on the patching eval was **not a model capability issue**. Three independent scaffolding bugs conspired to make every sample score 0.0 (or 0.5 at best), regardless of the model's actual patch quality. The model was actively using the tool loop, producing reasonable diffs, and iterating — but the environment was broken underneath it.

All three bugs were fixed in commits `156a6e4` and `bec9e5b` (2026-02-28), shortly after the eval run completed.

---

## Data Overview

| Metric | Value |
|--------|-------|
| Total samples | 31 |
| Scored 0.0 with "No unified diff found" | 29 |
| Scored 0.5 (applies + compiles, crash not eliminated) | 2 |
| Scored 1.0 (crash eliminated) | 0 |
| Mean score | 0.032 |
| Samples that hit the 30-message limit | 29/31 |
| Samples where last message is a tool result | 29/31 |

---

## Failure Mode A: Wrong Fuzz Binary Name in metadata.yaml (19 samples)

**Affected samples:** 19 out of 31 (all libxml2 samples plus some others targeting the same binary)

**Root cause:** `targets/libxml2/metadata.yaml` listed the fuzz target as `xml_read_memory_fuzzer`, but the OSS-fuzz container actually builds the binary as `libxml2_xml_read_memory_fuzzer` (with the project name prefix). The `_resolve_fuzz_binary()` function in `patching.py` uses this metadata to construct the binary path passed to `run_crash_input`.

Every call to `run_crash_input` returned:
```
CRASH DETECTED (exit 127):
bash: /out/xml_read_memory_fuzzer: No such file or directory
```

**Behavioral impact:** The model correctly applied patches and compiled successfully, then called `run_crash_input` and got back what appeared to be a crash. Unable to confirm whether the crash was eliminated, the model retried — applying more patches, compiling again, running again — burning through its 30-message budget in a retry loop without ever writing a conclusive final diff block.

The same binary name bug also caused `patch_scorer` to report `crash_eliminated=False` for the two samples that *did* produce final diffs (ARVO-42478580, ARVO-42486883), scoring them 0.5 instead of their true value.

**Fix:** `targets/libxml2/metadata.yaml` was corrected to list `libxml2_xml_read_memory_fuzzer` as the primary fuzz target (commit `bec9e5b`).

---

## Failure Mode B: Source Window Truncated to Wrong Section of File (11 samples)

**Affected samples:** 11 out of 31 (the non-exit-127, non-libjpeg-turbo failures)

**Root cause:** `_truncate_source()` windowed large source files to 400 lines centered on a "crash anchor" line. The anchor was found by `_extract_crash_line()`, which only searched the ASAN stack trace for `filename:NNN` patterns.

For the common case where the **crash surface** and the **fix site** are in different files (e.g., the ASAN trace shows `error.c:201` but the fix must be applied to `buf.c`), `_extract_crash_line` returned `None`. The fallback was `lines 1–400`, even when the relevant function was at line 2805.

Example: ARVO-42470114 shows the crash in `error.c` and `parser.c`, but the root cause allocation is in `buf.c:137` (explicit in the "Uninitialized value was created" second stack trace). The model was shown SAX2.c lines 1–400. The model correctly identified `buf.c:137` from reading the crash report, but when it tried to write a diff for `buf.c`, it guessed wrong line numbers because it couldn't see the actual content.

Result: 73% of all `try_patch` calls across the run were rejected (228/309), and most of the successful applications were trivially at line 1 (comment insertions to probe the file structure), not at the actual vulnerable location.

**Fix:** `_extract_crash_line` was given a Strategy 2 fallback that parses function names from ASAN frames and scans the source file for the first matching C function definition. `max_lines` was also bumped from 400 to 600. (commit `bec9e5b`)

---

## Failure Mode C: Scorer Only Read `state.output.completion` (29 samples)

**Affected samples:** 29 out of 31 (all that hit the 30-message limit)

**Root cause:** This was the **proximate cause** of 29 samples scoring 0.0 with "No unified diff found in model output." The scorer (pre-fix) called `_extract_diff(state.output.completion)`. When the Inspect-AI message limit fired mid-tool-loop (which happened to 29/31 samples), the last message in the conversation was a tool result, not an assistant message. `state.output.completion` was set to the text of the last *assistant turn before the limit* — which was often the text preceding a `compile_target()` call, not a diff block.

Crucially, **the diffs existed** in the conversation. Every one of the 29 limit-hit samples had valid `--- a/... +++ b/...` diffs as arguments to `try_patch` tool calls. The scorer just wasn't looking there.

Manual re-running of the extraction logic against the logs confirms: Pass 2 (walking assistant messages in reverse for `try_patch` arguments) finds a valid diff string for all 29 of these samples.

**Fix:** `_extract_diff_from_state()` was introduced with a three-pass fallback strategy:
1. Text content of assistant messages (reversed)
2. `try_patch` tool call `diff` arguments (reversed) — the key new pass
3. `state.output.completion` as last resort
(commits `156a6e4` and `bec9e5b`)

---

## Failure Mode D: libjpeg-turbo Source Directory Missing (1 sample)

**Affected sample:** ARVO-42489817

**Root cause:** For this sample, `try_patch` failed on every attempt with:
```
Patch REJECTED (exit 1):
bash: line 0: cd: /src/libjpeg-turbo: No such file or directory
```

The source directory inside the container used a different name from what `patching.py` was constructing (which uses the `target` metadata field directly). Meanwhile, `run_crash_input` paradoxically reported "CRASH ELIMINATED" on each call — suggesting the crash input may not actually trigger a crash in the baseline binary in this container image. The model was correctly confused: it observed "crash eliminated" but its patches were rejected, leaving it in an inconsistent state.

This is a separate container/dataset configuration issue specific to the libjpeg-turbo target. The model's behavior (noting the contradiction and eventually giving up on applying the patch) was reasonable given the broken environment.

---

## Hypothesis Checklist

| Hypothesis | Finding |
|---|---|
| Tool calling hygiene: does the model use tools correctly? | **Not an issue.** The model calls `try_patch → compile_target → run_crash_input` in the right order and iterates correctly. 309 tool calls were made across 31 samples. |
| Diff format: does it produce malformed diffs? | **Partial contributor.** Some early diffs were malformed (67 "malformed patch" rejections). Most failures were hunk-line-mismatch (130 "Hunk FAILED") due to wrong source window, not format errors. |
| Loop termination: does it terminate early? | **Driven by environment.** The model terminates when it believes the environment is stuck (repeated `exit 127`). It doesn't give up on fixable problems. |
| Context window usage: does it lose track? | **Not a clear issue.** The model consistently remembered earlier tool results and adapted its strategy (e.g., trying different line numbers after rejections). |
| Diff extraction: does `_extract_diff_from_state` fail? | **Yes, but this was a code bug.** The pre-fix scorer didn't have `_extract_diff_from_state` at all — it used `_extract_diff(state.output.completion)` only. |
| Model vs task: is sonnet 4.6 actually worse at C vuln reasoning? | **No evidence for this.** The two samples that worked (got 0.5) show correct root cause analysis and reasonable patches. The 19 that burned out on exit 127 would likely have produced diffs too. |

---

## Evidence from Log Transcripts

**ARVO-42478580 (scored 0.5 — one of the best-performing samples):**

The model correctly identified a heap-use-after-free in `xmlTextReaderFreeDoc`, produced a well-reasoned explanation, and submitted a structurally correct diff that reorders operations to fix the UAF. It applied and compiled. The crash_eliminated=False verdict came from the scorer running the binary as `/out/xml_read_memory_fuzzer` (wrong name) — the same bug. The actual patch quality was high.

**ARVO-42489817 (libjpeg-turbo, crash "eliminated" 4 times but 0.0 score):**

The model observed CRASH ELIMINATED from `run_crash_input` four times in a row — without any working patch — and correctly noted the environment was inconsistent: "Interesting — the crash is eliminated without my patch." It tried multiple path variations for the source directory, couldn't resolve the container misconfiguration, and eventually ran out of budget. The model's reasoning was sound; the infrastructure was broken.

**ARVO-42470727 (source window issue):**

The model was shown SAX2.c lines 1–400 but the fix needed to go in `buf.c`. It read the crash report (which mentioned `buf.c:137`), correctly targeted `buf.c`, and spent 13 `try_patch` calls probing with different line offsets (lines 105, 110, 115, 120, 125, 130, 132, 134, 137, 140...) — a binary search strategy — since it couldn't see the actual file content. The strategy was correct; the source was inaccessible.

---

## Assessment: Model vs Scaffolding vs Prompt

**This is a scaffolding issue, not a model issue.**

- Failure Mode A (19 samples): wrong binary name in `metadata.yaml` — data/config bug
- Failure Mode B (11 samples): wrong source window — code bug in `_extract_crash_line`
- Failure Mode C (29 samples): scorer couldn't find diffs in conversation history — code bug in scorer
- Failure Mode D (1 sample): container path mismatch — deployment/config bug

The model's core behavior — reading the crash report, identifying the vulnerable function, generating plausible diffs, iterating on rejections — was reasonable and often correct. The eval was measuring scaffolding reliability, not model capability.

---

## Proposed Fixes (Implemented in bec9e5b and 156a6e4)

The following fixes have already been merged:

1. **Binary name**: corrected `targets/libxml2/metadata.yaml` fuzz_targets entry.
2. **Source window**: `_extract_crash_line` Strategy 2 — parse function names from ASAN frames, scan source for matching C function definitions; `max_lines` 400→600.
3. **Scorer extraction**: `_extract_diff_from_state` three-pass strategy, with Pass 2 recovering the last `try_patch` argument if no fenced diff block is found in assistant message text.

### Additional Recommendations (Not Yet Implemented)

4. **Detect `exit 127` in `run_crash_input` and surface it clearly**: Instead of returning "CRASH DETECTED (exit NNN)", detect `exit 127` specifically and return something like "ERROR: binary not found at `/out/...`. Check metadata.yaml fuzz_targets." This would prevent the model from interpreting a missing binary as a persistent crash, saving message budget.

5. **Validate binary path at sandbox startup**: Before the tool loop begins, check that the fuzz binary exists in the container (e.g., `ls /out/<binary>`) and fail fast with a clear error rather than silently failing on every `run_crash_input` call.

6. **Add a `read_file` tool**: The model's most common workaround for wrong source windows was to insert dummy diffs at line 1 to probe content (a "what's actually there" strategy). Providing a `read_file(path, start_line, end_line)` tool would let the model directly read the file it needs to patch, eliminating both the source-window mismatch problem and the context-guessing behavior.

7. **Increase message_limit**: 30 messages is tight for a workflow that needs: try_patch + compile + run (3 messages) × N iterations. With the binary-name bug causing 3 failed attempts before giving up, 30 messages runs out fast. Consider 60 messages.

8. **Re-run the eval with the fixed scaffolding** to get a real baseline for model capability.
