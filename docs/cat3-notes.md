# Category 3 Handoff Notes

Notes from the agent that bootstrapped Category 3 targets (#121, #123).

## Target selection

88 Category 3 targets are bootstrapped. Good candidates for the smoke test (high sample counts, well-known projects):

- **curl** (well-maintained, standard C)
- **harfbuzz** (C++, solid oss-fuzz integration)
- **ffmpeg** (large project, many fuzz targets)
- **openssl** / **boringssl** (crypto parsers)
- **libtiff**, **libraw**, **openjpeg** (image parsers, similar to Cat 1/2)
- **sqlite3** (very mature fuzzing)

## Two kinds of build.sh

83 of the 88 targets have a normal `build.sh` copied directly from oss-fuzz (`build_sh_source: static` in metadata.yaml). These should work like Cat 1/2 targets.

5 targets have `build_sh_source: dockerfile` in their metadata — their real build.sh is created inside the Docker image at build time (copied from the cloned source repo). The `build.sh` file in `targets/` is a **stub that exits with an error** if run directly. These 5 are: **karchive, kimageformats, libconfig, poppler, valijson**. For the smoke test, I'd **avoid these 5** unless you want to debug the Docker build flow — stick with the 83 "static" targets.

## Docker builds

`category3 validate` confirmed all 88 targets pass layout validation (Dockerfile, build.sh, metadata.yaml present). However, none have been Docker-built yet. The `validate --build` flag runs a plain `docker build` which tests Dockerfile syntax but not the full oss-fuzz compile step. The real test is `build-target`.

Expect some Docker builds to fail — oss-fuzz Dockerfiles are maintained upstream and may have dependencies or build steps that don't work outside Google's CI. If a target fails `build-target`, just try the next one.

## Dockerfile comment headers

oss-fuzz Dockerfiles start with a license comment block, not `FROM`. We fixed `validate_target_layout()` to handle this (PR #122), so validation should work fine. Just be aware if you see Dockerfiles that look different from Cat 1/2 — that's expected.

## Registry

The registry is at `benchmark/category3_samples.json` — 3,348 samples across 88 projects. Two projects (oniguruma, unrar) were removed because they no longer exist in oss-fuzz. The registry `project` field maps to `targets/<project>/`.

## Curate/fetch pipeline

The `curate arvo` and `fetch-artifacts` commands should work for Cat 3 the same as Cat 1/2 — the ARVO localIds in the registry point to real ARVO entries. If you're scoping to specific targets, you can filter by project name in the curated dataset.

## Smoke Test Results (Issue #126)

### Targets attempted

| Target | Docker build | Compile (`build_target`) | Ready samples | Notes |
|--------|-------------|-------------------------|---------------|-------|
| harfbuzz | OK | OK | 146 | Used for smoke test |
| sqlite3 | OK (after nullglob fix) | OK | 0 | Fossil VCS — git-based source extraction fails |
| curl | OK (after adding run_tests.sh stub) | FAIL | 34 | ossfuzz.sh needs network during compile; `--network=none` blocks it |
| openjpeg | OK | FAIL | 7 | build.sh clones test data from GitHub; `--network=none` blocks it |

### Issues found and fixed

1. **Missing `run_tests.sh`**: Many Cat 3 Dockerfiles `COPY run_tests.sh` but the bootstrap agent only copied Dockerfile + build.sh. Created stub `run_tests.sh` for curl and sqlite3. ~38 other targets also need this (grep for `run_tests` in Dockerfiles).

2. **sqlite3 glob failure**: `build.sh` does `cp $SRC/*.options ...` but no `.options` files exist. With `set -e`, this fails. Fixed with `shopt -s nullglob` (same fix as zlib from Cat 1).

3. **`--network=none` breaks compile**: `DockerSandbox.start()` uses `--network=none` for security. Targets whose `build.sh` downloads data during compile (curl, openjpeg) fail. This affects many Cat 3 targets. Potential fix: allow network during `build_target()` but keep `--network=none` for fuzzing/patching.

4. **Silent `build_target()` failures**: `build_target()` discarded stdout/stderr on failure, making diagnosis impossible. Added warning-level logging of the last 30 stderr and 10 stdout lines on failure.

5. **Parallel compile overload**: 5 simultaneous `ninja -j10` builds (50 compiler processes) exhausted CPU. Run at most 2 patching evals in parallel for harfbuzz.

### Smoke test results (5 harfbuzz samples, claude-haiku-4-5)

| Sample ID | Crash type | Severity/Difficulty | Score | Time | Tokens |
|-----------|-----------|-------------------|-------|------|--------|
| ARVO-42505165 | Global-buffer-overflow READ 1 | medium/medium | 0.000 | 29:45 | 524K |
| ARVO-42504409 | Use-of-uninitialized-value | medium/medium | 0.500 | 44:08 | 565K |
| ARVO-42472557 | Heap-buffer-overflow READ 2 | medium/medium | 0.500 | 31:36 | 579K |
| ARVO-42472478 | Heap-double-free | high/hard | 0.500 | 21:12 | 557K |
| ARVO-42471192 | Heap-buffer-overflow WRITE 1 | high/medium | 0.000 | 12:00 | 1.1M |

**Mean score: 0.300** | **Total tokens: ~3.3M** | **Total wall time: ~2h 19m**

Pipeline completed end-to-end without crashes. Scores are comparable to Cat 1/2 results with Haiku (the 0.500 scores indicate the model proposed patches that compiled and partially fixed the vulnerability).
