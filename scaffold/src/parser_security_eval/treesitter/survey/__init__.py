"""Tree-sitter grammar survey: build a prioritized registry for fuzzing.

Gathers, for every grammar on the tree-sitter wiki, the data needed to pick good
fuzzing-survey candidates — grammars with real-world impact (used by Zed/Emacs,
RedMonk-ranked language, moderate popularity) that are also *likely to have bugs*
(hand-written external scanner, less scrutiny) and *tractable to fix* (actively
maintained, not archived). Outputs JSONL + CSV + a ranked priority list.
"""

from __future__ import annotations
