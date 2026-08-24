#!/usr/bin/env nix-shell
#! nix-shell scaffold/treesitter-shell.nix -i bash
#
# Homelab ablation run: LLM-in-loop fuzzing vs plain libFuzzer (tree-sitter).
# See docs/homelab-ablation-run.md for prerequisites and the methodology note
# about matching the fuzz budget before comparing against the 300s control.
#
# Run it directly -- ./homelab-run.sh -- NOT `bash homelab-run.sh`, which skips
# the shebang and so never enters the nix-shell. The shebang's relative path is
# resolved against this script's directory, so any cwd works.
set -euo pipefail

cd "$(dirname "$0")"

# Monorepo-root dotenv (ANTHROPIC_API_KEY et al). `set -a` exports every var it
# defines; a plain `source` would leave them as unexported shell locals.
set -a
# shellcheck disable=SC1091
source .env
set +a

# NixOS ships no default CA path for Python's OpenSSL, so every urllib fetch
# (grammar metadata, wiki scrape) dies with CERTIFICATE_VERIFY_FAILED -- and
# survey/sources.py swallows it into an empty result rather than erroring.
export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

cd scaffold
uv run parser-security-eval treesitter llm-fuzz \
  -g nushell-nu,gren,foam,typst,sql \
  -m anthropic:claude-opus-5 \
  --window 300 --max-iterations 5 --reps 3 \
  --out-dir results/treesitter-llm
