"""Tree-sitter fuzz→fix→JSONL loop.

A local-toolchain (nix-provided clang + tree-sitter CLI) analogue of the
Docker/OSS-Fuzz live-fuzzing pipeline in :mod:`parser_security_eval.tasks.fuzzing`.

The loop is *driven by the fuzzer*: a tree-sitter grammar is compiled into a
libFuzzer binary, fuzzed until it crashes, the crash is triaged, an LLM fixer
patches the implicated source (external scanner or ``grammar.js``), the parser is
rebuilt and the crashing input replayed to verify the fix, a JSONL record is
appended, and the loop continues fuzzing the patched parser for the next bug.
"""

from __future__ import annotations
