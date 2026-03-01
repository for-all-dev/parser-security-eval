---
title: Analysis
order: 3
---

# Analysis

*Written analysis will be added here once experiment results are finalized.*

## Preliminary Observations

Results are shown in the charts above. Key questions to address in the final writeup:

1. **Do 30-min cycles beat continuous runs?** The literature predicts yes—this is the primary hypothesis. Look at the cycle-condition comparison chart for the headline number.

2. **Which model finds crashes fastest?** Compare time-to-first-crash across models on the same target.

3. **Which targets are hardest?** Some parsers may be resistant to AI-generated harnesses due to complex input formats or deep API structures.

4. **Harness quality gap**: How many compile attempts does each model need? A model that writes correct harnesses on the first try has a practical advantage even if its crash rate is similar.

5. **Coverage vs. crashes**: High coverage doesn't always mean more crashes. Look for configurations that achieve high crash rates despite modest coverage—these likely have semantically targeted harnesses.

## Comparison to Published Benchmarks

Once results are in, compare crashes/CPU-hour to the published baselines:

| System | Crashes/CPU-hour (reported) |
|--------|----------------------------|
| PBFuzz | ~$1.83/vulnerability at 30-min budget |
| HGFuzzer | 17/20 CVEs triggered |
| AFL++ (no LLM) | Baseline |
| This work (best) | *TBD* |
