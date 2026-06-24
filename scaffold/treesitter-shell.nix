# Toolchain for the tree-sitter fuzz→fix loop (parser_security_eval.treesitter).
#
# Provides clang (with libFuzzer + ASan), llvm (llvm-symbolizer, so ASan stack
# traces are symbolized → accurate crash dedup + implicated-file detection), the
# tree-sitter CLI, nodejs (for `tree-sitter generate`) and git. `uv` is
# intentionally NOT pinned here — it is picked up from ~/.local/bin on the ambient
# PATH, which nix-shell preserves.
#
# Usage:
#   nix-shell scaffold/treesitter-shell.nix --run \
#     'cd scaffold && ANTHROPIC_API_KEY=... uv run parser-security-eval treesitter fuzz toml'
#
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = [
    pkgs.clang
    pkgs.llvm
    pkgs.tree-sitter
    pkgs.nodejs
    pkgs.git
  ];
}
