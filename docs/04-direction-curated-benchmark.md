# Direction C: Curated Parser Security Benchmark

## Summary

Build a static benchmark of parser vulnerabilities with known ground truth — similar to AutoPatchBench but parser-focused, with richer metadata, multiple difficulty categories, and support for both discovery and patching evaluation.

## Why This Direction

- **Fastest to ship**: No live fuzzing infrastructure needed for v1
- **Reproducible**: Deterministic scoring, easy to compare models
- **Complements existing benchmarks**: AutoPatchBench has 136 vulns but is not parser-focused; Magma has parser targets but no AI agent interface; ARVO has 5000+ vulns but no eval harness
- **Foundation for the RL environment**: The curated set becomes the training/eval curriculum

## Data Sources

### Primary: ARVO Dataset
[github.com/n132/ARVO](https://github.com/n132/ARVO) — 5,001 patches, 5,651 vulnerabilities with:
- Triggering inputs (the actual crash-inducing data)
- Canonical patches (human-written fixes)
- Reproducible Docker builds
- ASAN/UBSAN crash reports

Filter ARVO for parser-related projects. Initial estimate: ~2000 parser-related vulns.

### Secondary: oss-fuzz Bug Tracker
[bugs.chromium.org/p/oss-fuzz](https://bugs.chromium.org/p/oss-fuzz/issues/list) — public after 90-day disclosure. Includes:
- Crash type and sanitizer
- Reproducer input
- Regressed/fixed commit ranges

### Tertiary: Historical CVEs
NVD/CVE database filtered for parser-related CWEs:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-125: Out-of-bounds Read
- CWE-787: Out-of-bounds Write
- CWE-416: Use After Free
- CWE-190: Integer Overflow
- CWE-476: NULL Pointer Dereference

## Benchmark Structure

```
benchmark/
  metadata.json                    # global index
  targets/
    libpng/
      vulns/
        CVE-2019-7317/
          metadata.yaml            # CWE, severity, difficulty, affected versions
          crash_input.bin          # triggering input
          crash_report.txt         # ASAN output + stack trace
          vulnerable_source/       # snapshot of vulnerable code (or git ref)
          reference_patch.diff     # canonical human fix
          test_suite/              # functional tests to check for regressions
        oss-fuzz-12345/
          ...
    libxml2/
      ...
```

### metadata.yaml per vulnerability
```yaml
id: CVE-2019-7317
target: libpng
cwe: CWE-416  # Use After Free
severity: HIGH  # CVSS 5.3
difficulty: medium
affected_function: png_image_free
affected_file: png.c
lines_changed_in_fix: 3
sanitizer: address
crash_type: heap-use-after-free
root_cause: "png_image_free called twice when error occurs during png_image_finish_read"
tags: [double-free, error-handling, image-parser]
```

## Eval Tasks

### Task 1: Vulnerability Detection (Given Source Only)
- **Input**: Parser source code (vulnerable version), no crash info
- **Question**: "Identify security vulnerabilities in this parser"
- **Metric**: Precision/recall vs. known CVEs
- **Difficulty categories**:
  - Easy: single-function bugs with obvious patterns
  - Medium: cross-function bugs requiring data flow analysis
  - Hard: subtle logic errors, race conditions, integer overflows

### Task 2: Crash Root Cause Analysis
- **Input**: Crash report (ASAN output + stack trace + triggering input) + source code
- **Question**: "What is the root cause? Classify the CWE."
- **Metric**: CWE classification accuracy, root cause description quality

### Task 3: Vulnerability Patching
- **Input**: Crash report + source code
- **Question**: "Generate a minimal patch that fixes this vulnerability"
- **Metric**:
  - Does the patch compile?
  - Does the crash input no longer trigger a crash?
  - Do existing tests still pass?
  - Diff size vs. reference patch
- **Baseline**: AutoPatchBench reports ~30% success for best models

### Task 4: Harness Writing
- **Input**: Parser source code + API documentation
- **Question**: "Write a fuzz harness for this parser"
- **Metric**: Coverage achieved in 5-minute fuzzing run, bugs found
- **Baseline**: oss-fuzz-gen results (29% coverage improvement over human harnesses)

### Task 5: Patch Review
- **Input**: Vulnerability + proposed patch (correct or incorrect)
- **Question**: "Does this patch correctly fix the vulnerability?"
- **Metric**: Accuracy at distinguishing good patches from bad ones
- **Data**: Generate wrong patches via LLM, mix with correct ones

## Difficulty Calibration

Use multiple signals to rate difficulty:
1. **Lines changed in canonical fix**: 1-3 lines = easy, 4-10 = medium, 10+ = hard
2. **Number of files changed**: 1 = easier, 2+ = harder
3. **CWE complexity**: NULL deref = easy, use-after-free = medium, type confusion = hard
4. **Historical solve rate**: If available from AutoPatchBench or similar

## Integration with Inspect-AI

```python
from inspect_ai import Task, task
from inspect_ai.dataset import json_dataset
from inspect_ai.scorer import model_graded_fact
from inspect_ai.solver import generate, system_message

@task
def parser_vuln_patching():
    return Task(
        dataset=json_dataset("benchmark/metadata.json"),
        solver=[
            system_message(BLUE_TEAM_PROMPT),
            provide_crash_report(),
            provide_source_code(),
            generate(),  # agent generates patch
        ],
        scorer=[
            patch_compiles(),
            crash_eliminated(),
            tests_pass(),
            diff_minimality(),
        ],
        sandbox="docker",  # each eval runs in isolated container
    )
```

## Comparison to Existing Benchmarks

| Benchmark | # Vulns | Parser Focus? | Live Fuzzing? | Patching? | Discovery? |
|-----------|---------|--------------|---------------|-----------|------------|
| AutoPatchBench | 136 | No (general C/C++) | No | Yes | No |
| Magma | ~100 | Partial | Yes (fuzzer benchmark) | No | No |
| ARVO | 5,001 | Partial | No | Yes (has patches) | No |
| CVE-Bench | 509 | No | No | Yes | No |
| **Ours** | ~500 (v1) | **Yes** | **Yes (Phase 2)** | **Yes** | **Yes** |

## Advantages
- Fast to build (data already exists in ARVO/oss-fuzz, need curation + tooling)
- Reproducible and deterministic
- Easy to compare models
- Foundation for RL training curriculum
- Publishable as a standalone benchmark

## Risks
- Curation is labor-intensive (filtering ARVO, verifying reproducibility)
- Static benchmarks get saturated / contaminated over time
- Doesn't capture the dynamic red-team capability (harness writing, mutation strategy)
- Parser definition is fuzzy — need clear inclusion criteria
