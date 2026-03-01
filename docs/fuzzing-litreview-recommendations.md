# Fuzzing + LLM Hybrid Architecture: Literature Review and Recommendations

Prepared for Phase 2 swarm fuzzing design (issues #49, #52, #53, #54).
Sources: 13 papers from `docs/prior_literature/` plus corresponding arXiv entries.

---

## Paper Summaries

### 1. PBFuzz: Agentic Directed Fuzzing for PoV Generation (2025)
**arXiv:** 2512.04611
PBFuzz frames Proof-of-Vulnerability (PoV) generation as a two-constraint satisfaction problem (reachability + triggering) and solves it with an agentic loop that mimics human security analysts: iterative code study, hypothesis formation, test encoding, and debugging feedback. It uses persistent memory to avoid hypothesis drift and property-based testing (PBT) to preserve input structure while solving constraints. PBFuzz triggered 57 vulnerabilities (17 unique to it), achieving a 25.6x speedup over AFL++ with CmpLog within a 30-minute budget at $1.83 USD per vulnerability.

**Most actionable:** The decomposition of vulnerability triggering into reachability constraints and triggering constraints is the right abstraction for directing an agent. PBT as the innermost loop (not blind mutation) dramatically improves structure-preserving exploration.

---

### 2. All You Need Is A Fuzzing Brain (2025)
**arXiv:** 2509.07225
The "FuzzingBrain" Cyber Reasoning System (CRS), a DARPA AIxCC finalist (4th place), autonomously discovered 28 vulnerabilities including 6 zero-days across real-world C and Java projects, patching 14 of them. The paper provides a detailed account of the LLM-powered components: harness generation, crash triage, patch synthesis, and an iterative detect-patch pipeline. The full system is open source on GitHub.

**Most actionable:** The detect-patch pipeline architecture is directly applicable here. Key insight: vulnerability detection and patch validation are tightly coupled — you need both loops running together to close the feedback cycle.

---

### 3. Attention Distance: A Novel Metric for Directed Fuzzing with LLMs (2025)
**arXiv:** 2512.19758 — ICSE 2026
Proposes "attention distance" as a drop-in replacement for physical call-graph distance in directed grey-box fuzzing (AFLGo-style). An LLM computes attention scores between code elements to capture semantic/logical proximity rather than syntactic graph distance. Evaluated on 38 real vulnerabilities: 3.43x improvement over AFLGo, 2.89x over DAFL, 7.13x over WindRanger, all with no changes to the fuzzing engine itself — only the distance metric changes.

**Most actionable:** Distance metrics are a high-leverage point. If the eval uses directed greybox fuzzing (e.g., LibAFL with AFLGo-style targeting), swapping in LLM-derived semantic distance requires minimal integration work and delivers large speedups.

---

### 4. CKGFuzzer: LLM-Based Fuzz Driver Generation Enhanced by Code Knowledge Graph (2024)
**arXiv:** 2411.11532 — ICSE 2025
Treats fuzz driver generation as a code synthesis task where the LLM is given context from a code knowledge graph (CKG) built via interprocedural static analysis. The CKG exposes API call chains, type hierarchies, and usage patterns that the LLM uses to write more accurate drivers. The loop includes automatic compilation error repair. Results: 8.73% coverage improvement, 84.4% reduction in manual crash review effort, 11 real bugs found (9 new) across 8 open-source C libraries.

**Most actionable:** For parser fuzzing, the CKG pattern — static analysis as structured context for the LLM — is the right approach for harness generation. The incremental repair loop for compilation errors is essential to include.

---

### 5. Directed Greybox Fuzzing via Large Language Model (HGFuzzer) (2025)
**arXiv:** 2505.03425
HGFuzzer converts path constraint problems into code generation tasks: the LLM synthesizes test harnesses that already encode reachability paths and generates custom mutators for specific target functions. Result: 17/20 real-world vulnerabilities triggered, 11 within the first minute, 24.8x speedup over state-of-the-art directed fuzzers, 9 new CVEs.

**Most actionable:** The key move is treating the harness as the primary vehicle for encoding semantic path constraints, not relying on coverage guidance alone. Generate a new harness per target location rather than one universal harness.

---

### 6. Fuzz4All: Universal Fuzzing with Large Language Models (2024)
**arXiv:** 2308.04748 — ICSE 2024
Fuzz4All uses LLMs as a universal input generator via autoprompting: a meta-prompt is constructed from the target's specification/docs and refined iteratively to generate syntactically and semantically valid inputs for arbitrary languages (C, C++, Go, SMT2, Java, Python). Outperformed language-specific fuzzers on all six languages and found 98 bugs (64 confirmed new) in GCC, Clang, Z3, OpenJDK, and others.

**Most actionable:** Autoprompting — systematically constructing prompts from target documentation and updating them based on feedback — is a reusable pattern for parser fuzzing. Feed the parser's format specification into the prompt and update it based on which inputs cause interesting behavior.

---

### 7. Fuzzing: Randomness? Reasoning! — RandLuzz (2025)
**arXiv:** 2507.22065
RandLuzz identifies randomness as the main enemy of efficient directed fuzzing and uses LLMs to eliminate it in two places: (1) seed generation via function-call-chain analysis to produce inputs that are already "aimed" at the target location, and (2) mutator synthesis via LLM bug analysis to generate bug-specific mutators. Results: 2.1x–4.8x speedup on seeds, up to 2.7x on individual bugs, 8 bugs exposed within 60 seconds.

**Most actionable:** Separate the seed generation phase from the mutation phase and apply LLM reasoning to both independently. LLM-generated seeds should be targeted at specific call paths; LLM-generated mutators should encode knowledge of the bug class being hunted.

---

### 8. LLM-Assisted Model-Based Fuzzing of Protocol Implementations — ChatFuMe (2025)
**arXiv:** 2508.01750
ChatFuMe avoids direct message sequence generation (expensive, often invalid) by having the LLM instead write a random-sequence-generator *program* that encodes the protocol's state machine. This generator is refined in a loop. Applied to HMQ, PyModbus, and Moquette; discovered 12 bugs. Lower token consumption than prior LLM-based protocol fuzzers.

**Most actionable:** For format-driven parsers, generate a *generator program* rather than individual inputs. The generator encodes format semantics and can be iterated cheaply. This pattern is well-suited to binary format parsers (e.g., libxml2, libtiff, libpng).

---

### 9. LLM Guided Protocol Fuzzing — ChatAFL (NDSS 2024)
ChatAFL uses LLMs to extract machine-readable protocol knowledge from natural language specifications: message type grammars, state transition sequences, and prediction of next-message types. This knowledge feeds directly into AFLNet-style stateful fuzzing. Coverage improvements over AFLNet: 47.6% more state transitions, 29.6% more states, 5.8% more code; 9 new vulnerabilities vs. 3–4 for competing tools.

**Most actionable:** For parsers that are essentially protocol implementations (e.g., XML, HTTP, Modbus), extracting the grammar from the spec document and injecting it into the fuzzer's mutation engine is a high-signal, low-cost intervention. LLMs are very good at this extraction task.

---

### 10. Not All Paths Are Equal: MultiGo (2025)
**ACM TOSEM**
MultiGo introduces "path difficulty" — a Poisson-distribution-based metric that estimates probability of traversing a path — and uses a Contextual Multi-Armed Bandit (CMAB) model to schedule seeds across fuzzing vs. concolic execution modes, optimizing for either exploitation (reach target) or exploration (find hidden bugs on non-optimal paths). Evaluated on 136 target sites across 41 programs; outperforms AFLGo, SelectFuzz, Beacon, WindRanger, DAFL, SymCC, and SymGo. Found 14 new undisclosed vulnerabilities.

**Most actionable:** In a multi-agent swarm, different agents should play different roles (exploiter vs. explorer) and be scheduled by a bandit model. The path diversity insight — that non-optimal paths expose different bugs — argues against pure greedy target-reaching.

---

### 11. R1-Fuzz: Specializing Language Models for Textual Fuzzing via RL (2025)
**arXiv:** 2509.20384
R1-Fuzz fine-tunes a 7B-parameter LLM with reinforcement learning specifically for fuzzing input generation, using coverage-slicing-based question construction and distance-based reward calculation. The specialized small model matches or outperforms much larger models (GPT-4-class). Results: up to 75% higher code coverage, 29 new vulnerabilities found.

**Most actionable:** A fine-tuned small model specialized for a specific parser format would dramatically outperform a general-purpose LLM. RL with coverage as the reward signal is the right training objective. The cost of fine-tuning is justified by the number of fuzzing invocations in a swarm.

---

### 12. Semantic-Aware Fuzzing: LLM-Guided Reasoning-Driven Input Mutation (2025)
**arXiv:** 2509.19533
Integrates reasoning LLMs (Deepseek-r1, QwQ-32B, Llama3.3, Gemma3) into AFL++'s mutation loop via few-shot prompting, specifically targeting IoT/embedded protocol parsers. Key finding: Deepseek-r1 is the strongest open-source model for this task. Mutation quality depends more on prompt complexity and model choice than on shot count. Throughput bottleneck (LLM latency >> fuzzer throughput) is the dominant practical obstacle.

**Most actionable:** Treat LLM mutation as an async, low-frequency operation that produces high-quality seeds for the fast fuzzing engine, not as a synchronous mutation operator. Use Deepseek-r1 class models for mutation reasoning. Few-shot examples should include known crash inputs for the target parser.

---

### 13. The Lean Theorem Prover (System Description) (2015)
**CADE-25**
Lean is a theorem prover built on dependent type theory, bridging interactive and automated proving. It provides a small trusted kernel, an extensible tactic framework, and a rich API for embedding. Lean 4 is a full programming language with a metaprogramming system. This paper is the system description.

**Relevance to this repo:** The Benchify repo targets Lean for fuzzing (finding inputs that crash the Lean elaborator or type-checker). For this parser-security-eval, the key insight is that formal specification languages like Lean can serve as ground truth for input validity — a Lean spec of a parser's grammar is a oracle for whether a given input is valid, enabling better differential fuzzing.

---

## Recommendations

### Fuzz Harness Design

**R1. Write one harness per target function, not one harness per library.**
HGFuzzer and CKGFuzzer both demonstrate that harness specificity is a primary coverage driver. A harness that encodes the call path to a specific parser function (e.g., `xmlParseDocument` vs. the generic `xmlReadMemory`) enables the fuzzer to focus mutations on the inputs that actually exercise that code. For the parser-security-eval, generate a harness per CWE-relevant function identified during triage.

**R2. Use static call graph analysis to construct harness context.**
Before invoking the LLM to write a harness, run a static analysis pass (e.g., via `cflow`, `clang --analyze`, or a custom tree-sitter pass) to extract the call graph, type signatures, and error-handling patterns for the target function. Feed this as structured context to the LLM. CKGFuzzer shows this lifts coverage by ~9% and eliminates most compilation errors in generated harnesses.

**R3. Include compilation error repair in the harness generation loop.**
The harness generation agent must have a sub-loop: write harness → attempt compile → if error, send error + harness back to LLM → retry. Budget 3–5 iterations. Papers consistently show that the first draft compiles only 60–70% of the time; repair brings this to 90%+.

**R4. Encode reachability in the harness, not just in mutation.**
RandLuzz and HGFuzzer both find that seeding with inputs already positioned near the target (rather than at the entry point) dramatically reduces time-to-exposure. The harness should call the minimum necessary setup to reach the target function directly. Avoid boilerplate wrappers that re-enter the parser from scratch on every input.

**R5. Use property-based testing for structure-constrained parsers.**
PBFuzz demonstrates that property-based testing (Hypothesis-style generators) is more efficient than blind mutation for parsers with complex structural constraints. For XML, JSON, ELF, or protocol parsers, define a PBT generator for the high-level structure and use LLM to fill in the semantics. This preserves structural validity while exploring edge cases.

---

### Agentic Fuzzing Loop Design

**R6. Separate the loop into four distinct phases with explicit handoffs.**
Based on the PBFuzz and FuzzingBrain architectures, the optimal agentic loop is:

```
[Analyze]   →   [Synthesize]   →   [Fuzz]   →   [Triage]
  |                  |                |               |
  LLM reads      LLM writes      libAFL runs     LLM classifies
  source, CVEs   harness +       (10-30 min)     crashes, writes
  call graph     seed corpus                     patch hypothesis
     ↑______________________________________________|
```

These phases should be separate agent invocations with structured JSON handoffs, not a single long LLM context. Keeping context small improves reasoning quality and enables parallel execution.

**R7. Limit the agent's 30-minute fuzzing budget, then force a synthesis step.**
PBFuzz achieves its 25.6x speedup by capping fuzzing at 30 minutes and requiring the agent to re-synthesize based on crash/coverage feedback. Do not let fuzzing run for 24 hours unattended in the first iteration. Short cycles with LLM reflection converge faster than long blind fuzzing runs.

**R8. Maintain persistent per-target memory across agent restarts.**
PBFuzz identifies "hypothesis drift" — the agent forgetting what it already tried — as a major failure mode. Implement a structured per-target JSON log that records: hypotheses tried, crashes found, harness variants generated, and the coverage delta from each run. Pass this log to the LLM as the first context item in every new session.

**R9. Use the fuzzing engine's coverage feedback as the primary reward signal.**
Both R1-Fuzz and the FuzzingBrain system use coverage as the RL/feedback signal. In practice: after each fuzzing run, diff the coverage bitmap against the previous run; inputs that open new edges are "interesting" and should be prioritized for further mutation and for inclusion in the persistent corpus. This is more reliable than LLM-judged interestingness.

**R10. Run blueteam patching in the same loop iteration as redteam fuzzing.**
FuzzingBrain found that coupling vulnerability detection and patching improves both — the patch attempt often reveals why the crash happened, which informs the next round of fuzzing. Issue #49 (blueteam patcher) and issues #52–54 (fuzzing swarm) should share the same crash database and run in locked-step iterations.

---

### Diversity Strategies

**R11. Run at least three harness variants per target simultaneously.**
Fuzz4All's autoprompting and CKGFuzzer's knowledge-graph approach generate structurally different harnesses that exercise different API entry points. In a swarm, assign each worker a different harness variant. Coverage union across variants substantially exceeds any single harness.

**R12. Use different mutation strategies per agent: grammar-based, random, semantic.**
The literature suggests a portfolio approach:
- Agent A: grammar-based (Fuzz4All autoprompt or ChatAFL grammar extraction)
- Agent B: coverage-directed random (AFL++ with standard mutators)
- Agent C: LLM semantic mutation (RandLuzz-style, using Deepseek-r1)
- Agent D: directed/targeted (HGFuzzer-style, targeting specific CVE locations)

These strategies explore orthogonal regions of the input space. In the parser-security-eval swarm (issues #52–54), each container should run one strategy.

**R13. Use multiple LLM models and temperatures for harness generation.**
Semantic-aware fuzzing finds that model choice dominates over shot count. Generate harnesses with at least two models (e.g., Claude Sonnet + Deepseek-r1) and multiple temperature settings (0.2 for correctness, 0.8 for exploration). Deduplicate by compilation success and coverage achieved.

**R14. Implement multi-path exploration, not just target-reaching.**
MultiGo demonstrates that non-optimal paths to a target expose different bugs. In the swarm, designate some agents as "explorers" (maximizing path diversity, not target distance) and others as "exploiters" (minimizing distance to known-vulnerable locations). A CMAB-style scheduler can dynamically rebalance based on crash rate.

---

### Seed Corpus Management

**R15. Bootstrap the seed corpus from the target's own test suite.**
The target parser's `test/` directory contains valid inputs that exercise real parser behavior. These are far better starting seeds than random bytes. For OSS-Fuzz targets (libxml2, libtiff, etc.), download the existing OSS-Fuzz seed corpus as the starting point.

**R16. Generate LLM-assisted seeds targeting specific call paths before fuzzing starts.**
RandLuzz shows a 2.1–4.8x speedup from LLM-generated seeds over standard initial seeds. Before each fuzzing run, ask the LLM: "Generate 20 inputs that would reach `<target_function>` in `<parser_name>`. Here is the call graph: `<cg>`. Here is the format spec: `<spec>`." Use these as the initial corpus.

**R17. Apply format-aware seed minimization after each crash find.**
Standard crash minimizers (e.g., `afl-tmin`) operate at the byte level and destroy semantic structure. For structured formats (XML, ELF, PNG), implement a format-aware minimizer: use the LLM to reduce the crashing input while preserving the semantic property that causes the crash. This makes crash triage dramatically easier.

**R18. Maintain a "hall of fame" corpus across all fuzzing campaigns.**
Across multiple runs and multiple parser targets, maintain a global corpus of high-coverage inputs. This is analogous to OSS-Fuzz's shared corpus infrastructure. When a new harness is generated, initialize it from the hall-of-fame corpus rather than from scratch.

---

### Crash Triage and Deduplication

**R19. Deduplicate crashes by stack trace prefix, not by input similarity.**
Two inputs that trigger the same stack frame are likely the same bug. Hash the top 3–5 frames of the stack trace (or the sanitizer output) as the deduplication key. This is standard in OSS-Fuzz and dramatically reduces the manual review burden. CKGFuzzer reports 84.4% reduction in review workload from this alone.

**R20. Use LLM-based triage to assign CWE category and severity immediately.**
The existing eval already has `cwe_scorer` and `severity_scorer`. For each new crash, immediately run LLM triage to classify: (1) CWE category (buffer overflow, use-after-free, integer overflow, etc.), (2) severity (critical/high/medium/low), (3) whether it is exploitable vs. merely crashing. This prioritizes which crashes the blueteam patcher should address first.

**R21. Track "unique" crashes separately from "interesting" inputs.**
A crash is unique if its deduplication key has not been seen before. An interesting input is one that opens new coverage edges but does not crash. Maintain separate queues. The unique-crashes queue drives blueteam patching; the interesting-inputs queue drives further fuzzing. Do not conflate them.

**R22. Record the full execution trace for each unique crash.**
Use `AFL_DEBUG=1` or ASAN's verbose output to record the full address trace for each unique crash. This is the raw material the LLM needs to reason about reachability constraints when generating the next harness variant. PBFuzz's "custom program-analysis tools" are essentially structured wrappers around this trace data.

---

## Key Insights

**1. The agentic loop beats extended fuzzing time.**
Across PBFuzz (25.6x speedup), HGFuzzer (24.8x speedup), and RandLuzz (2.1–4.8x speedup), the consistent finding is that LLM-guided short cycles outperform long unsupervised fuzzing runs by a large margin. The optimal unit of work is 20–30 minutes of fuzzing followed by LLM analysis and re-synthesis, not 24-hour continuous campaigns.

**2. Harness quality is the dominant bottleneck.**
CKGFuzzer, HGFuzzer, and PBFuzz all find that the harness — how you call the parser and what inputs you feed it — determines 80%+ of the outcome. A harness that exercises the right entry points with structure-preserving inputs will find bugs that a generic harness misses entirely regardless of how long it runs. For the parser-security-eval, harness generation quality should be the primary engineering investment.

**3. LLMs should operate on structured intermediate representations, not raw source.**
The best-performing systems (CKGFuzzer with code knowledge graphs, ChatAFL with extracted grammar schemas, HGFuzzer with call chains) all convert source code into a structured representation before passing it to the LLM. Raw source is noisy and context-inefficient. Build a pre-processing step that extracts: call graph subgraph for the target function, type signatures, format specification excerpt, and known-related CVE descriptions.

**4. Semantic distance outperforms syntactic distance for directing fuzzing.**
The attention distance paper demonstrates that LLM-computed semantic proximity between code elements is a strictly better metric than call-graph-hop-count. For a directed fuzzing approach, the effort to instrument the fuzzer with LLM-derived distances pays for itself quickly (~3–7x speedup with no other changes).

**5. Small specialized models outperform large general models for specific tasks.**
R1-Fuzz's RL-specialized 7B model rivals GPT-4-class models for its specific task. Semantic-aware fuzzing finds that model choice matters more than shot count. For this project's swarm (issues #52–54), consider maintaining a library of task-specific prompts tuned for each parser format rather than relying on zero-shot general prompting.

**6. The detect-patch-detect cycle is synergistic.**
FuzzingBrain's detect-and-patch architecture, where patching attempts feed back into the next fuzzing iteration, outperforms purely detection-focused systems. For this project, the blueteam patcher (issue #49) should not run in isolation — its patch attempts should update the target binary, and the fuzzer should verify the patch by re-testing the crashing input plus fuzzing the patched binary for regressions.

**7. Throughput vs. quality tradeoff in LLM mutation.**
Semantic-aware fuzzing identifies LLM latency as the primary obstacle to integrating LLMs directly into the mutation loop. The practical resolution is the same across multiple papers: use LLMs to generate high-quality seeds and mutators *before* the fuzzing run, then run the fast native fuzzer autonomously. Async LLM calls during fuzzing should be low-frequency (e.g., every 5 minutes of fuzzing, not per-execution).

**8. Protocol/format grammar extraction is free value.**
ChatAFL demonstrates that LLMs can extract machine-readable grammars from natural language specifications with high accuracy. For every parser target added to this eval, an LLM should extract the input format grammar from the RFC, man page, or source-level comments and inject it into the fuzzer's dictionary and generator. This is a low-effort, high-payoff step that the existing OSS-Fuzz integrations often skip.

---

## Applicability to This Project (parser-security-eval)

The eval currently targets libxml2 (see `targets/libxml2/metadata.yaml`). The swarm design in issues #49, #52–54 should implement the following architecture, drawing on the above:

```
Phase 1 — Setup (per target, one-time):
  - Extract call graph for target parser (tree-sitter or clang static analysis)
  - Extract input format grammar from spec/docs (LLM extraction)
  - Generate 3 harness variants per key entry-point (CKGFuzzer pattern)
  - Generate initial seed corpus targeting key entry-points (RandLuzz pattern)

Phase 2 — Swarm (per target, 30-min cycles):
  - 4 parallel agents with different mutation strategies (portfolio)
  - Each agent: fuzz (libAFL) → collect interesting inputs → deduplicate crashes
  - Crash triage: stack-hash dedup → CWE/severity classification (existing scorers)

Phase 3 — Synthesis (after each cycle):
  - LLM reflects on coverage delta and crash queue
  - Updates persistent memory with hypotheses tried
  - Generates next harness/seed variant based on uncovered edges
  - Blueteam patcher attempts patch for highest-severity unique crashes

Phase 4 — Verification:
  - Re-fuzz patched binary with original crashing input
  - Score patch quality (existing _patch_scorer)
  - Update hall-of-fame corpus with inputs that expose post-patch regressions
```

This architecture is consistent with the CLAUDE.md vision (generator/blueteam agents, LibAFL integration, OSS-Fuzz compatibility) and directly implements the highest-impact findings from the literature reviewed above.
