# Unclear that hybrid/neurosymbolic agents where fuzzers and LLMs uplift each other works very well

Recently, [MaxvH wrote](https://www.lesswrong.com/posts/KKE6bL8LEpb6KuZWA/funding-formal-methods-for-the-cyberpocalypse) that we ought to develop an FM tool of the future:

> AI-accelerated fuzzers, which rapidly self-improve their fuzz harnesses at runtime.

Last May, Forall R&D was funded by the [GoodForever Foundation](https://www.goodforever.org/) to investigate roughly this hypothesis, before the post was written. We came back with a negative result — with a specific shape worth knowing about if you're considering funding or building in this space.

## What we built

An eval framework (Inspect-AI, docker-sandboxed OSS-Fuzz targets) where an LLM agent runs the loop MaxvH describes: analyze the target, write its own libFuzzer harness, compile it, seed it, run a fuzzing campaign, triage crashes, and refine the harness — a 4-phase loop borrowed from the PBFuzz literature, with per-target persistent memory, call-graph context, and multi-agent swarm variants. Targets were classic C parsers: libxml2, libpng, libjpeg-turbo, zlib. Benchmark ground truth came from [ARVO](https://github.com/n132/ARVO-Meta) (reproducible OSS-Fuzz bugs with crash inputs and reference patches).

## The result

Across a 36-run sweep — 3 frontier models × 4 targets × 3 campaign durations — the agents reliably produced working harnesses and ran real campaigns, and found approximately nothing. Our first sweep's zeros turned out to be pipeline bugs; we fixed those and re-ran. The second sweep's zeros were genuine.

We don't think this means the agents were bad at fuzzing. We think it means the question was malformed: **OSS-Fuzz targets are, by construction, the parsers that have already been fuzzed to fixpoint.** Google runs continuous fuzzing campaigns against them with CPU-years of compute. The bugs an LLM-written harness can reach in a 30-minute campaign were harvested years ago. An LLM uplifting the fuzzer adds no measurable value when the un-uplifted fuzzer has already exhausted the target — the corpus that makes evaluation convenient (reproducible bugs, ground-truth patches) is precisely the corpus where there's nothing left to find. Anyone proposing to demonstrate AI-fuzzer uplift on OSS-Fuzz-adjacent benchmarks should expect the same wall.

## What did show signal

Patching, not finding. Given an ARVO crash report, Claude Opus repaired ~76% of vulnerabilities across the four targets, Sonnet ~72.5%, GPT-4o-mini ~52.5% — clean model stratification. But these are exactly the numbers you'd predict without accounting for contamination: the fix commits are public and plausibly in training data, so we treat this as an eval-plumbing validation, not a capability claim.

## Where we went next

If the problem was target hardness, the fix is softer targets. We pivoted to parsers that have *not* lived under continuous fuzzing: tree-sitter grammars, whose external scanners are hand-written C, and parsers in interactive theorem provers (Isabelle, Lean).

Here the loop does close. We swept **118 tree-sitter grammars** (~24 fuzzing-hours, ~250M executions), and the fuzz→fix loop found genuine memory-safety bugs in **9 of them (10 distinct crashes) — all in hand-written `scanner.c` code**: two global-buffer-overflows (nushell-nu, fdncred-nu), a heap-buffer-overflow (gren), two SEGVs (foam, typst), and memory leaks in four more (sql, idris, liquidsoap, svelte). Claude Opus patched them crash-input-replay-verified, landing verified fixes on 18 of 31 attempts. A further 12 grammars produced only timeouts/OOMs — resource exhaustion, not memory-safety bugs, and we discount them (they collapse onto two generic libFuzzer stack signatures). So the pivot worked where OSS-Fuzz didn't: real bugs exist on un-hardened parsers, and the loop finds and fixes them.

But this immediately sharpens the ablation question, and here we have to be honest about what the LLM is doing. For tree-sitter the harness is essentially *fixed* — feed bytes to the parser — so unlike the OSS-Fuzz setup the LLM writes no harness. Its only contribution is on the **fix** side; every one of these 9 bugs is a plain libFuzzer crash. So the real test is: run vanilla libFuzzer — no LLM anywhere — against the same 118 grammars for the same per-grammar walltime, and see how many of the 9 it finds on its own.

> **⚠️ PLACEHOLDER — baseline not yet run.** The `treesitter baseline` ablation (plain libFuzzer, fork mode, same grammars + walltime, no LLM) is implemented but has not been executed. Our prior: it reproduces **most or all** of the 9, since the LLM adds nothing to discovery on a fixed harness. When it runs, this section gets the real overlap number (e.g. "vanilla libFuzzer found N/9 of the same bugs") and the sentence below is confirmed or corrected.

If that prior holds, it *sharpens* the negative result rather than rescuing the hypothesis: on un-hardened targets the discovery value comes from *fuzzing at all*, not from the AI. What the LLM demonstrably does — and what a pure fuzzer cannot — is the fix side: it patches the crashes it's handed. The open quantity is vulns-and-fixes per dollar of the hybrid versus buying more CPU for vanilla fuzzing plus a cheap patch step, and we do not yet have evidence the hybrid wins on discovery anywhere.

## Takeaway

"AI-accelerated fuzzers that self-improve their harnesses at runtime" is a natural idea, and we'd guess versions of it get funded more than once. Our data says: on hardened targets the AI adds nothing because the fuzzer alone already sufficed years ago, and on soft targets — where we did find real bugs — the fuzzer alone plausibly finds the same ones (baseline pending). The niche where LLM *discovery* uplift pays — targets too hard for vanilla fuzzing but tractable with LLM-guided harnesses — is where the hypothesis has to live, and we have not yet observed it. The one place the LLM clearly earns its keep is patching the crashes, which is a different and more defensible claim than the one we set out to test.
