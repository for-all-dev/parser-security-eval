"""Tests for tool_ok detection in the trajectory viewer loader."""

from __future__ import annotations

from viz.loader import _TOOL_ERROR_PREFIX_NAMES, _TOOL_SUCCESS_RE


def test_success_re_matches_known_keywords() -> None:
    assert _TOOL_SUCCESS_RE.search("patch applied successfully")
    assert _TOOL_SUCCESS_RE.search("Compilation succeeded")
    assert _TOOL_SUCCESS_RE.search("CRASH ELIMINATED - no sanitizer errors detected.")
    assert _TOOL_SUCCESS_RE.search("no crash detected")
    assert _TOOL_SUCCESS_RE.search("tests pass")


def test_success_re_does_not_match_file_content() -> None:
    """read_source_file returns file content, not a status keyword."""
    assert not _TOOL_SUCCESS_RE.search(
        "[parser.c lines 1-200 of 3456]\n#include <stdio.h>"
    )
    assert not _TOOL_SUCCESS_RE.search(
        "[libxml2/parser.c lines 50-100 of 9812]\nstatic int"
    )


def test_error_prefix_names_includes_read_source_file() -> None:
    assert "read_source_file" in _TOOL_ERROR_PREFIX_NAMES


def test_error_prefix_logic_success() -> None:
    """Simulate the tool_ok logic for a successful read_source_file call."""
    tool_result = "[parser.c lines 1-50 of 3456]\nint main() { return 0; }"
    tool_ok = not tool_result.startswith("ERROR")
    assert tool_ok is True


def test_error_prefix_logic_failure() -> None:
    """Simulate the tool_ok logic for a failed read_source_file call."""
    tool_result = "ERROR reading parser.c: No such file or directory"
    tool_ok = not tool_result.startswith("ERROR")
    assert tool_ok is False


def test_error_prefix_logic_error_in_content_is_not_failure() -> None:
    """File content that contains the word ERROR mid-string is still a success."""
    tool_result = "[error_handler.c lines 1-10 of 200]\n// ERROR codes defined here"
    tool_ok = not tool_result.startswith("ERROR")
    assert tool_ok is True
