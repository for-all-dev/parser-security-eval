# Prior Art and References

Detailed references supporting the plan documents. Organized by topic.

## AI + Fuzzing Systems

| System | Year | Approach | Key Result | Reference |
|--------|------|----------|------------|-----------|
| FuzzGPT | 2023 | In-context learning for edge case generation | 76 bugs in PyTorch/TF, 11 high-priority | [Semantic Scholar](https://www.semanticscholar.org/paper/470754e17de89081f63dde4719922fe9b63251d5) |
| ChatAFL | 2024 | LLM-guided protocol fuzzing | Outperformed AFLNet, NSFuzz | NDSS 2024 |
| TitanFuzz | 2023 | CodeGen-based masked mutation | DL library API fuzzing | ISSTA 2023 |
| WhiteFox | 2024 | LLM analyzes compiler optimization source | First white-box compiler fuzzer | [OOPSLA 2024](https://yangchenyuan.github.io/files/OOPSLA24-WhiteFox.pdf) |
| Fuzz4All | 2024 | GPT-4/StarCoder as universal input generator | Multi-language fuzzing | [fuzz4all.github.io](https://fuzz4all.github.io/) |
| LLM4Fuzz | 2024 | LLM-guided smart contract fuzzing | 5 DeFi vulns in 600 contracts | [arXiv:2401.11108](https://arxiv.org/abs/2401.11108) |
| BertRLFuzzer | 2024 | BERT RL agent + multi-armed bandit | 17 web vulns, 54% faster | [AAAI 2024](https://ojs.aaai.org/index.php/AAAI/article/view/30455) |
| CovRL | 2024 | RL + LLM mutator with TF-IDF coverage reward | 58 JS engine bugs, 15 CVEs | [arXiv:2402.12222](https://arxiv.org/abs/2402.12222) |
| oss-fuzz-gen | 2024 | LLM generates fuzz targets for oss-fuzz | 272 projects improved, 26 new bugs incl CVE-2024-9143 | [GitHub](https://github.com/google/oss-fuzz-gen) |

## Benchmarks and Datasets

| Benchmark | Size | Focus | Live Fuzzing? | Reference |
|-----------|------|-------|---------------|-----------|
| AutoPatchBench | 136 vulns | C/C++ fuzzing vulns | No | [Meta Engineering Blog](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/) |
| ARVO | 5,001 patches, 5,651 vulns | OSS-Fuzz reproductions | No | [GitHub](https://github.com/n132/ARVO), [arXiv:2408.02153](https://arxiv.org/abs/2408.02153) |
| Magma | ~100 bugs in 7 targets | Ground-truth fuzzing benchmark | Yes | [hexhive.epfl.ch/magma](https://hexhive.epfl.ch/magma/), [arXiv:2009.01120](https://arxiv.org/abs/2009.01120) |
| CVE-Bench (repair) | 509 CVEs | Multi-language CVE patching | No | [NAACL 2025](https://aclanthology.org/2025.naacl-long.212/) |
| CVE-Bench (exploit) | 40 CVEs | Web app exploitation | No | [arXiv:2503.17332](https://arxiv.org/abs/2503.17332) |
| LAVA-M | Synthetic bugs | Coreutils | No | Classic fuzzing benchmark |
| Cybench | 40 CTF tasks | Multi-domain security | No | [arXiv:2408.08926](https://arxiv.org/abs/2408.08926) |
| SWE-bench | 2,294 issues | General Python bugs | No | [swebench.com](https://www.swebench.com) |
| FuzzBench | 22+ targets | Fuzzer comparison | Yes | [Google FuzzBench](https://google.github.io/fuzzbench/) |

## Competitions

| Competition | Approach | Key Result | Reference |
|-------------|----------|------------|-----------|
| DARPA AIxCC | 53 challenges, autonomous CRS | 54 vulns found, 43 patched (winner) | [darpa.mil](https://www.darpa.mil/news/2025/aixcc-results), [SoK arXiv:2602.07666](https://arxiv.org/abs/2602.07666) |
| Team Atlanta (ATLANTIS) | Ensemble fuzzing + LLM patching on K8s | Won $4M, 392.76 pts | [arXiv:2509.14589](https://arxiv.org/abs/2509.14589), [GitHub](https://github.com/Team-Atlanta/aixcc-afc-atlantis) |

## LM Post-Training RL for Code

| System | Domain | Key Insight | Reference |
|--------|--------|-------------|-----------|
| DeepSeek-R1 | Math/code reasoning | GRPO over completions, reward from correctness | [arXiv:2501.12948](https://arxiv.org/abs/2501.12948) |
| SWE-RL | Code repair | RL post-training on SWE-bench, sparse reward from test pass/fail | [arXiv:2502.18449](https://arxiv.org/abs/2502.18449) |
| Self-Play SWE-RL (SSR) | Bug injection + repair self-play | +10.4 on SWE-bench with single model, PPO self-play | [arXiv:2512.18552](https://arxiv.org/abs/2512.18552) |
| DeepSWE / R2E-Gym | Code repair | Sparse binary reward + PPO, 23%→42% | [Together AI blog](https://www.together.ai/blog/deepswe), [arXiv:2504.07164](https://arxiv.org/abs/2504.07164) |

## Agent Scaffolding / Environments

| System | Domain | Key Insight | Reference |
|--------|--------|-------------|-----------|
| RvB | Red vs Blue CVE hardening | Training-free adversarial scaffolding, TDSR metric | [arXiv:2601.19726](https://arxiv.org/abs/2601.19726) |
| SWE-MiniSandbox | Fast sandboxing for RL rollouts | Mount namespace + chroot, 25% reset time vs Docker | [arXiv:2602.11210](https://arxiv.org/abs/2602.11210) |
| SWE-bench | Code repair eval | Agent executes bash in sandbox, binary test reward | [swebench.com](https://www.swebench.com) |
| Cybench | CTF security eval | LM agents with bash tools in Kali containers | [arXiv:2408.08926](https://arxiv.org/abs/2408.08926) |

## Fuzzing Infrastructure

| Tool | Purpose | Reference |
|------|---------|-----------|
| oss-fuzz | Continuous fuzzing for OSS | [github.com/google/oss-fuzz](https://github.com/google/oss-fuzz) |
| ClusterFuzz | Distributed fuzzing infra | [google.github.io/clusterfuzz](https://google.github.io/clusterfuzz/) |
| ClusterFuzzLite | CI-integrated fuzzing | [google.github.io/clusterfuzzlite](https://google.github.io/clusterfuzzlite/) |
| libFuzzer | In-process coverage-guided fuzzer | [llvm.org/docs/LibFuzzer](https://llvm.org/docs/LibFuzzer.html) |
| AFL++ | Fork of AFL, feature-rich | [github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) |
| LibAFL | Rust composable fuzzing framework | [github.com/AFLplusplus/LibAFL](https://github.com/AFLplusplus/LibAFL) |
| Honggfuzz | Google's feedback-driven fuzzer | [github.com/google/honggfuzz](https://github.com/google/honggfuzz) |
| Centipede | Google's newer fuzzing engine | [github.com/google/centipede](https://github.com/google/fuzztest/tree/main/centipede) |
| CASR | Rust crash triage toolchain | [github.com/ispras/casr](https://github.com/ispras/casr) |
| Nautilus | Grammar-based coverage-guided fuzzer | Integrated in LibAFL |
| Fuzz Introspector | LLVM-based fuzzing analysis | [fuzz-introspector.com](https://fuzz-introspector.com) |

## Ensemble / Collaborative Fuzzing

| Paper | Key Insight | Reference |
|-------|-------------|-----------|
| EnFuzz | Ensemble fuzzing outperforms any single fuzzer | USENIX Security 2019 |
| CollabFuzz | Strategic seed sharing between heterogeneous fuzzers | RAID 2021 |
| CUPID | Coverage-guided protocol fuzzing via collaborative composition | Usenix Security 2022 |

## Crash Triage and Analysis

| Tool | Approach | Reference |
|------|----------|-----------|
| CASR | ASAN/UBSAN parsing, severity classification, clustering | [GitHub](https://github.com/ispras/casr) |
| GPTrace | LLM embeddings + HDBSCAN for crash dedup | [arXiv:2512.01609](https://arxiv.org/pdf/2512.01609) |
| Igor | Root-cause clustering (beyond stack trace similarity) | [CCS 2021](https://hexhive.epfl.ch/publications/files/21CCS.pdf) |

## Security Patching with LLMs

| System | Approach | Fix Rate | Reference |
|--------|----------|----------|-----------|
| CodeRover-S | Dynamic call graphs + type analysis | 63% on 2024 vulns, 5/9 merged upstream | [arXiv:2411.03346](https://arxiv.org/abs/2411.03346) |
| AutoPatchBench results | Various LLMs on 136 vulns | ~30% best case | [Meta Engineering Blog](https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/) |
| CVE-Bench results | LLM agents on 509 CVEs | Varies by model | [NAACL 2025](https://aclanthology.org/2025.naacl-long.212/) |
