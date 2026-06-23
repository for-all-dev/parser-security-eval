# Statement of Work

We should have like the RL version of oss-fuzz or ARVO. 

Parsers are among the most exploited components in software   they process untrusted input by definition, and memory-safety bugs in C/C++ parsers (libxml2, libpng, libjpeg, zlib, etc.) account for a persistent share of CVEs. We've built the scaffolding for an end-to-end evaluation framework that measures how well frontier AI models can both discover parser vulnerabilities via fuzzing and patch them given crash reports. The system is built on Inspect-AI with docker-sandboxed oss-fuzz targets, a benchmark of 209/5k real-world vulnerabilities (with ground-truth patches from ARVO), and experiment infrastructure for multi-model sweeps. Our preliminary results on patching already show meaningful signal: Claude Opus patches 85% of libjpeg-turbo vulnerabilities and 70% of libpng bugs, with clear model stratification (Sonnet trails by ~10 points, GPT-5.4-mini by ~20). We've validated the full pipeline curation, build, evaluation, and scoring across 4 parser targets and 3 frontier models.

What's left is executing the remaining two phases: live adversarial fuzzing (where AI agents write their own fuzz harnesses and compete to find bugs in real time) and closing the red-blue loop (where a red-team agent finds crashes, a blue-team agent patches them, and the cycle repeats on the patched code). The infrastructure for both is designed but not yet built out we need funding to scale compute for fuzzing campaigns, expand target coverage to the full oss-fuzz corpus, run statistically powered sweeps across more models and configurations, and ultimately build toward an RL training signal where models improve at parser security through self-play. This is the 80/20 moment: the eval framework, benchmark dataset, and scoring pipeline are proven; what remains is the compute and engineering to turn it into a full adversarial training environment for secure program synthesis.

## Milestones

### [x] June 18th ish

Sample our 80/20 more widely from the oss-fuzz and ARVO spaces. Then, refine the prototype to not rely as heavily on oss-fuzz and ARVO. Understand what the expected token expenditures are to find (in expectation) novel vulns.

### [ ] July 18th ish

~~Drop-in claude plug-in for writing parsers that are stresstested as they’re written is drafted, a preliminary version is available MIT licensed.~~

~~The hypothesis is that a fuzz-uplifted AI can find vulns in pre-existing parser repos (like libpng and zlib). By now, we’ll have a ton of signal about if this hypothesis is true or false. If it seems true, then we’ll be faced with questions of responsible disclosure while not DOSing maintainers with AI generated patches. If it seems false, we’ll focus more on the stresstested-as-written parser development toolchain.~~

**Revised (2026-06-23):** Attack tree-sitter and parsers in real-world ITP projects rather than oss-fuzz/ARVO targets. Targets: Isabelle’s parser (Scala, via Java fuzzer) and Lean’s parser. Goal: meaningful vulns-per-token signal on un-hardened targets, laying groundwork for an ARVO-for-ITP contribution. By July 18th we should know whether fuzz-uplifted AI can find vulns in this new target class.

### [ ] August 18th ish

Approximately conference tier writeup (not necessarily submitted or worried about specific peer review), with accompanying website. The repo is MIT licensed. Our parser stresstesting dev toolchain is MIT licensed and possibly accumulating gh stars. 

A north star, but not make-or-break KPI, would be if we caught wind of a contributor to one of the major parsing libraries using our stresstesting-in-devloop toolchain. 

---

## Changelog

### 2026-06-23 — Milestone 1 check-in

**Milestone 1 (June 18th) marked complete.**

**What we learned:**
- The core hypothesis — that uplifting agents with fuzzers increases vulns per token — is not looking promising on oss-fuzz/ARVO. We couldn't elicit a good baseline vulns/token on these data sources. In hindsight this makes sense: oss-fuzz targets are selected for being the most hardened repos already.
- Patching signal is what you'd predict if you didn't factor in contamination. Updated numbers: Opus ~76%, Sonnet ~72.5%, GPT-4o-mini ~52.5% across ARVO CVEs.
- The decision not to refine the prototype away from oss-fuzz/ARVO (because we thought there was richness of data within it) turned out to be the wrong call — it was the wrong kind of richness.

**Pivot for Milestone 2:**
- Departing from oss-fuzz and ARVO as the primary target surface. The Claude drop-in plugin angle is shelved for now.
- New direction: tree-sitter and parsers in real-world ITP (interactive theorem prover) projects. Specific targets:
  - Isabelle's parser (Scala — Matthew notes it is pretty bad), attacked via a Java fuzzer
  - Lean's parser (aping Kiran's work)
- Pitch framing: contribute to an "ARVO-for-ITP" in the parser security case.
- Rationale: the externalized upsides of hardening tree-sitter would be good for the world; these targets are not already maximally hardened the way oss-fuzz corpus targets are.
