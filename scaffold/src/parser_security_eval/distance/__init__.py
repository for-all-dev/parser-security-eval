"""Distance metrics for directed fuzzing.

Two metrics are provided:

* :mod:`callgraph_distance` — hop-count distance over the call graph (AFLGo
  baseline).
* :mod:`semantic_distance` — LLM-derived semantic/attention distance that
  captures logical proximity not visible in the call graph
  (arXiv 2512.19758, ICSE 2026).
"""
