"""Tests for tree-sitter crash triage (ASAN/libFuzzer parsing + dedup)."""

from __future__ import annotations

import base64

from parser_security_eval.treesitter import triage
from parser_security_eval.treesitter.models import BugClass

HEAP_OVERFLOW = """\
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000051
READ of size 1 at 0x602000000051 thread T0
    #0 0x4f1a2b in scan_string /home/u/tree-sitter-toml/src/scanner.c:120:14
    #1 0x4f0010 in tree_sitter_toml_external_scanner_scan /home/u/tree-sitter-toml/src/scanner.c:300:10
    #2 0x4e9999 in ts_lexer__advance /home/u/tree-sitter/lib/src/lexer.c:200
    #3 0x4d0000 in LLVMFuzzerTestOneInput /home/u/work/harness.c:14:18
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/u/tree-sitter-toml/src/scanner.c:120:14 in scan_string
"""

STACK_OVERFLOW = """\
==1==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd00000000
    #0 0x55 in ts_subtree__print_dot_graph /home/u/tree-sitter/lib/src/subtree.c:900
    #1 0x56 in ts_node_string /home/u/tree-sitter/lib/src/node.c:100
    #2 0x57 in LLVMFuzzerTestOneInput /home/u/work/harness.c:14
"""

LIBFUZZER_TIMEOUT = """\
==2== ERROR: libFuzzer: timeout after 20 seconds
    #0 0x10 in scan /home/u/tree-sitter-x/src/scanner.c:5
SUMMARY: libFuzzer: timeout
"""

PARSER_CRASH = """\
==3==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x20 in ts_parser__lex /home/u/tree-sitter-x/src/parser.c:88:3
    #1 0x21 in LLVMFuzzerTestOneInput /home/u/work/harness.c:14
SUMMARY: AddressSanitizer: SEGV
"""


def test_classify_heap_overflow() -> None:
    assert triage.classify(HEAP_OVERFLOW) is BugClass.heap_buffer_overflow


def test_classify_stack_overflow() -> None:
    assert triage.classify(STACK_OVERFLOW) is BugClass.stack_overflow


def test_classify_timeout_takes_priority() -> None:
    assert triage.classify(LIBFUZZER_TIMEOUT) is BugClass.timeout


def test_classify_segv() -> None:
    assert triage.classify(PARSER_CRASH) is BugClass.segv


LEAK = """\
==1==ERROR: AddressSanitizer: 2024 byte(s) leaked in 527 allocation(s).
    #0 0x1 in malloc
    #1 0x2 in tree_sitter_sql_external_scanner_deserialize /g/src/scanner.c:50
SUMMARY: AddressSanitizer: 2024 byte(s) leaked
"""


def test_classify_memory_leak_from_asan_wording() -> None:
    # ASan writes "AddressSanitizer: N byte(s) leaked"; must not fall to unknown.
    assert triage.classify(LEAK) is BugClass.memory_leak
    crash = triage.triage(LEAK, b"x")
    assert crash.bug_class is BugClass.memory_leak
    assert crash.in_scanner is True  # deserialize frame


def test_extract_frames_drops_column() -> None:
    frames = triage.extract_frames(HEAP_OVERFLOW)
    assert frames[0] == "scan_string /home/u/tree-sitter-toml/src/scanner.c:120"
    assert len(frames) == 4


def test_stack_hash_is_stable_and_distinct() -> None:
    a = triage.stack_hash(triage.extract_frames(HEAP_OVERFLOW))
    b = triage.stack_hash(triage.extract_frames(HEAP_OVERFLOW))
    c = triage.stack_hash(triage.extract_frames(STACK_OVERFLOW))
    assert a == b
    assert a != c
    assert len(a) == 64


def test_stack_hash_is_portable_across_runs() -> None:
    # Same bug seen in two independent sweeps: differs only in home-dir path,
    # binary load offset, and tree-sitter *runtime* line numbers (parser.c drift).
    # The portable stack hash must ignore all three and match.
    run_a = [
        "serialize (/home/mpwd/.cache/ts/_work_gren/fuzz_gren+0x1d0343)",
        "serialize /home/mpwd/.cache/ts/tree-sitter-gren/src/scanner.c:417",
        "ts_parser__lex /home/mpwd/.cache/ts/tree-sitter/lib/src/./parser.c:550",
    ]
    run_b = [
        "serialize (/home/q/.cache/ts/_baseline_gren/fuzz_gren+0x1c21df)",
        "serialize /home/q/.cache/ts/tree-sitter-gren/src/scanner.c:417",
        "ts_parser__lex /home/q/.cache/ts/tree-sitter/lib/src/./parser.c:561",
    ]
    assert triage.stack_hash(run_a) == triage.stack_hash(run_b)
    # A genuinely different crash site (different scanner line) must NOT collapse.
    run_c = list(run_b)
    run_c[1] = "serialize /home/q/.cache/ts/tree-sitter-gren/src/scanner.c:210"
    assert triage.stack_hash(run_c) != triage.stack_hash(run_b)


def test_implicate_prefers_scanner() -> None:
    file, in_scanner = triage.implicate(triage.extract_frames(HEAP_OVERFLOW))
    assert file is not None and file.endswith("scanner.c")
    assert in_scanner is True


def test_implicate_parser_not_scanner() -> None:
    file, in_scanner = triage.implicate(triage.extract_frames(PARSER_CRASH))
    assert file is not None and file.endswith("parser.c")
    assert in_scanner is False


def test_frameless_crashes_get_distinct_stable_hashes() -> None:
    t = triage.triage("ERROR: libFuzzer: timeout\n", b"x")
    o = triage.triage("ERROR: libFuzzer: out-of-memory\n", b"x")
    assert t.bug_class is BugClass.timeout
    assert o.bug_class is BugClass.oom
    # Frameless crashes must not collapse to the same (empty-string) hash.
    assert t.stack_hash and o.stack_hash
    assert t.stack_hash != o.stack_hash
    # Stable across calls (dedup-friendly).
    assert t.stack_hash == triage.triage("ERROR: libFuzzer: timeout\n", b"y").stack_hash


def test_triage_roundtrips_input_and_summary() -> None:
    crash = triage.triage(HEAP_OVERFLOW, b"\x00bad\xff", crash_file="/tmp/crash-1")
    assert crash.bug_class is BugClass.heap_buffer_overflow
    assert crash.in_scanner is True
    assert "heap-buffer-overflow" in crash.asan_summary
    assert base64.b64decode(crash.crash_input_b64) == b"\x00bad\xff"
    assert crash.crash_file == "/tmp/crash-1"
