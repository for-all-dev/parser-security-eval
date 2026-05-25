# Direction A: OSS-Fuzz Native Eval

## Summary

Build the eval as a thin orchestration layer on top of oss-fuzz's existing infrastructure. Each parser target is literally an oss-fuzz project. Agents interact via the same interfaces that human developers use: writing fuzz harnesses, running `helper.py`, reading crash reports.

## Why This Direction

- **1000+ existing targets**: oss-fuzz already integrates libpng, libxml2, openssl, curl, etc. We don't have to write any target packaging from scratch.
- **Battle-tested build/run infra**: Dockerfiles, sanitizer configs, corpus management all proven at scale.
- **oss-fuzz-gen as starting point**: Google already has an LLM-in-the-loop system for harness generation. We extend it with patching and adversarial dynamics.
- **Minimal new infrastructure**: The eval mostly orchestrates existing tools.

## Architecture

```
┌─────────────────────────────────────┐
│        Eval Orchestrator (Python)    │
│  - Inspect-AI tasks                 │
│  - agent ↔ sandbox communication    │
│  - scoring + metrics                │
└─────────┬──────────────┬────────────┘
          │              │
   ┌──────v──────┐ ┌────v────────────┐
   │ Red Agent    │ │ Blue Agent       │
   │ (harness    │ │ (reads crash     │
   │  generation │ │  reports, patches │
   │  + tuning)  │ │  source code)    │
   └──────┬──────┘ └────┬────────────┘
          │              │
   ┌──────v──────────────v────────────┐
   │     Docker Sandbox (per target)   │
   │                                   │
   │  oss-fuzz project layout:         │
   │  - Dockerfile + build.sh          │
   │  - /src/<project> (parser source) │
   │  - /out/ (fuzz targets + corpora) │
   │                                   │
   │  Fuzz engines available:          │
   │  - libFuzzer (default)            │
   │  - AFL++ (alternative)            │
   │  - Honggfuzz (alternative)        │
   │                                   │
   │  Sanitizers:                      │
   │  - ASAN, UBSAN, MSAN             │
   │                                   │
   │  Infra tools:                     │
   │  - python3 infra/helper.py        │
   │  - coverage reports               │
   │  - crash triage (casr / clusterfuzz) │
   └───────────────────────────────────┘
```

## Agent Action Space

### Red Team Agent
```
write_harness(code)          → write a fuzz_target.cc to /src/
modify_build_sh(code)        → adjust build.sh for new harness
add_seed(binary_data)        → add to seed corpus
add_dictionary(entries)      → add tokens to dictionary file
run_fuzz(engine, duration)   → `helper.py run_fuzzer --engine <e> --duration <d>`
get_coverage()               → `helper.py coverage` → HTML/JSON report
list_crashes()               → ls /out/crashes/
```

### Blue Team Agent
```
read_crash(crash_id)         → ASAN output + stack trace + triggering input
read_source(file, lines)     → parser source code
search_code(query)           → grep/ripgrep in source tree
edit_file(path, diff)        → apply patch
rebuild()                    → re-run build.sh with sanitizers
run_tests()                  → execute existing test suite
verify_fix(crash_id)         → re-run triggering input, confirm no crash
```

## Target Selection Strategy

Start with parsers that have:
1. **Rich CVE history** — more known bugs = better ground truth
2. **Existing oss-fuzz integration** — no setup work needed
3. **Variety of formats** — binary, text, protocol

### Category 1 (Start Here)
| Target | Format Type | OSS-Fuzz? | Historical CVEs |
|--------|------------|-----------|-----------------|
| libpng | Binary image | Yes | 50+ |
| libjpeg-turbo | Binary image | Yes | 30+ |
| libxml2 | Text markup | Yes | 100+ |
| openssl | Crypto/TLS | Yes | 200+ |
| zlib / libzip | Archive | Yes | 20+ |

### Category 2 (Expand)
| Target | Format Type | OSS-Fuzz? |
|--------|------------|-----------|
| curl | Protocol | Yes |
| protobuf | Serialization | Yes |
| harfbuzz | Font | Yes |
| libpcap | Network capture | Yes |
| sqlite | Query language | Yes |

### Category 3 (Stretch)
- Custom parsers written specifically for the eval (with planted bugs)
- Rust/Go parsers (memory-safe languages — different attack surface)

## Eval Task Types

### Task Type 1: Harness Generation (Red Team)
- **Input**: Parser source code + API docs
- **Goal**: Write a fuzz harness that achieves maximum coverage
- **Metric**: Branch coverage %, unique crashes found in N minutes of fuzzing
- **Baseline**: Existing human-written oss-fuzz harnesses

### Task Type 2: Crash Triage (Analysis)
- **Input**: ASAN crash report + triggering input + source code
- **Goal**: Identify root cause, classify vulnerability type (CWE), assess severity
- **Metric**: Accuracy vs. ground-truth CVE classification

### Task Type 3: Vulnerability Patching (Blue Team)
- **Input**: Crash report + stack trace + triggering input + source code
- **Goal**: Generate minimal patch that eliminates the crash
- **Metric**: Patch success (crash gone + tests pass + no regressions)
- **Baseline**: AutoPatchBench results (best models ~30% on full set)

### Task Type 4: Adversarial Loop (Red + Blue)
- **Setup**: Parser with no known bugs (or bugs hidden from agents)
- **Red team**: finds crashes via fuzzing
- **Blue team**: patches them
- **Red team**: tries to find new crashes in patched version
- **Metric**: Rounds until no new crashes found, total bugs found/fixed

## Integration with Inspect-AI

The scaffold already depends on `inspect-ai`. Each task type becomes an Inspect task:

```python
@task
def harness_generation(target: str, engine: str = "libfuzzer"):
    return Task(
        dataset=parser_targets(target),
        solver=[
            red_team_agent(),  # generates harness
            run_fuzzer(engine=engine, duration="5m"),
        ],
        scorer=coverage_and_crashes(),
    )

@task
def vulnerability_patching(target: str, crash_set: str):
    return Task(
        dataset=crash_reports(target, crash_set),
        solver=[
            blue_team_agent(),  # reads crash, patches source
            rebuild_and_verify(),
        ],
        scorer=patch_correctness(),
    )
```

## Advantages
- Minimal new infrastructure — leverage oss-fuzz's proven patterns
- Huge existing target library (1000+ projects)
- Directly comparable to oss-fuzz-gen and AutoPatchBench baselines
- Natural upgrade path to RL (swap Inspect scorer for reward function)

## Risks
- oss-fuzz build environments are complex and fragile
- Build times can be long (minutes per target rebuild)
- libFuzzer/AFL++ are less programmatically controllable than LibAFL
- Some oss-fuzz projects have flaky builds
