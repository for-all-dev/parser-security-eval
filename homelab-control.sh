#!/usr/bin/env nix-shell
#! nix-shell scaffold/treesitter-shell.nix -i bash
#
# Control arm: plain libFuzzer, fixed template harness, NO LLM. Budget and window
# cadence are derived per-rep from the treatment sweep it is pointed at, so the
# two arms are equal-fuzz-seconds by construction.
#
# Run directly -- ./homelab-control.sh -- NOT `bash homelab-control.sh`.
set -euo pipefail

cd "$(dirname "$0")"

# No LLM in this arm, so no API key is strictly needed; sourced anyway to keep
# the two run scripts symmetric.
set -a
# shellcheck disable=SC1091
source .env
set +a

export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

cd scaffold
# -j 1 on purpose: the treatment fuzzed one grammar at a time on one core. Running
# the control concurrently would give each process less CPU than its treatment
# counterpart got, biasing the comparison toward the LLM arm.
uv run parser-security-eval treesitter baseline \
  --hybrid results/treesitter-llm \
  --out results/treesitter-baseline \
  -j 1
