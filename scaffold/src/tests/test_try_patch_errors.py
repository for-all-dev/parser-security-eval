"""Tests for try_patch error-message improvements (PR #99).

Tests the helper functions added to improve error diagnostics when patches fail:
- _validate_unified_diff: detects malformed diffs
- _parse_diff_targets: extracts file paths and hunk lines from diffs
- _build_rejection_context: builds detailed error context for failed patches
- _check_whitespace_mismatch: detects tab/space mismatches in context lines
"""

import asyncio
from unittest.mock import AsyncMock


from parser_security_eval.tasks.patching import (
    _build_rejection_context,
    _check_whitespace_mismatch,
    _parse_diff_targets,
    _validate_unified_diff,
)


# ---------------------------------------------------------------------------
# Valid diff fixture used across tests
# ---------------------------------------------------------------------------

VALID_DIFF = """\
--- a/parser.c
+++ b/parser.c
@@ -10,7 +10,7 @@
   int x = 0;
   int y = 1;
   int z = 2;
-  buf = malloc(len);
+  buf = malloc(len + 1);
   if (!buf) return -1;
   memcpy(buf, src, len);
   return 0;
"""


# ---------------------------------------------------------------------------
# 1. _validate_unified_diff — malformed diff detection
# ---------------------------------------------------------------------------


class TestValidateUnifiedDiff:
    def test_empty_string(self) -> None:
        result = _validate_unified_diff("")
        assert result is not None
        assert "Malformed diff" in result
        assert "missing '--- a/<file>' header" in result
        assert "missing '+++ b/<file>' header" in result
        assert "missing '@@ -N,M +N,M @@' hunk header" in result

    def test_random_text(self) -> None:
        result = _validate_unified_diff("hello world\nthis is not a diff\nfoo bar")
        assert result is not None
        assert "Malformed diff" in result

    def test_missing_hunk_header(self) -> None:
        diff_no_hunk = "--- a/file.c\n+++ b/file.c\n-old line\n+new line\n"
        result = _validate_unified_diff(diff_no_hunk)
        assert result is not None
        assert "missing '@@ -N,M +N,M @@' hunk header" in result
        # Should NOT complain about --- or +++ since they are present
        assert "missing '--- a/<file>' header" not in result
        assert "missing '+++ b/<file>' header" not in result

    def test_missing_minus_header(self) -> None:
        diff_no_minus = "+++ b/file.c\n@@ -1,3 +1,3 @@\n context\n"
        result = _validate_unified_diff(diff_no_minus)
        assert result is not None
        assert "missing '--- a/<file>' header" in result

    def test_missing_plus_header(self) -> None:
        diff_no_plus = "--- a/file.c\n@@ -1,3 +1,3 @@\n context\n"
        result = _validate_unified_diff(diff_no_plus)
        assert result is not None
        assert "missing '+++ b/<file>' header" in result

    def test_valid_diff_returns_none(self) -> None:
        result = _validate_unified_diff(VALID_DIFF)
        assert result is None


# ---------------------------------------------------------------------------
# _parse_diff_targets
# ---------------------------------------------------------------------------


class TestParseDiffTargets:
    def test_single_file(self) -> None:
        targets = _parse_diff_targets(VALID_DIFF)
        assert len(targets) == 1
        assert targets[0] == ("parser.c", 10)

    def test_strips_b_prefix(self) -> None:
        diff = "--- a/foo.c\n+++ b/src/foo.c\n@@ -5,3 +5,3 @@\n ctx\n"
        targets = _parse_diff_targets(diff)
        assert targets[0][0] == "src/foo.c"

    def test_multi_file_diff(self) -> None:
        diff = (
            "--- a/a.c\n+++ b/a.c\n@@ -1,3 +1,3 @@\n ctx\n"
            "--- a/b.c\n+++ b/b.c\n@@ -20,3 +20,3 @@\n ctx\n"
        )
        targets = _parse_diff_targets(diff)
        assert len(targets) == 2
        assert targets[0] == ("a.c", 1)
        assert targets[1] == ("b.c", 20)


# ---------------------------------------------------------------------------
# 2. _build_rejection_context — wrong file path ("does not exist")
# ---------------------------------------------------------------------------


class TestBuildRejectionContextWrongFile:
    def test_nonexistent_file_error(self) -> None:
        """Diff targets a file that does not exist in the sandbox."""
        diff = "--- a/nonexistent.c\n+++ b/nonexistent.c\n@@ -1,3 +1,3 @@\n ctx\n"
        sandbox = AsyncMock()

        # find for .rej files: none
        sandbox.exec.side_effect = [
            (0, "", ""),  # find .rej
            (1, "", ""),  # test -f (file does not exist)
            (0, "", ""),  # find for similar filenames
        ]

        result = asyncio.run(
            _build_rejection_context(sandbox, "/src/target", diff, "patch failed")
        )
        assert "does not exist" in result

    def test_suggests_similar_files(self) -> None:
        """When file doesn't exist but similar names are found, suggests them."""
        diff = "--- a/parser.c\n+++ b/parser.c\n@@ -1,3 +1,3 @@\n ctx\n"
        sandbox = AsyncMock()

        sandbox.exec.side_effect = [
            (0, "", ""),  # find .rej: none
            (1, "", ""),  # test -f: not found
            (0, "/src/target/src/parser.c", ""),  # find similar
        ]

        result = asyncio.run(
            _build_rejection_context(sandbox, "/src/target", diff, "patch failed")
        )
        assert "does not exist" in result
        assert "Did you mean" in result


# ---------------------------------------------------------------------------
# 3. Hunk line beyond EOF
# ---------------------------------------------------------------------------


class TestBuildRejectionContextHunkBeyondEOF:
    def test_hunk_beyond_eof(self) -> None:
        """Hunk references line 500 but file only has 50 lines."""
        diff = "--- a/small.c\n+++ b/small.c\n@@ -500,3 +500,3 @@\n ctx\n"
        sandbox = AsyncMock()

        sandbox.exec.side_effect = [
            (0, "", ""),  # find .rej: none
            (0, "", ""),  # test -f: exists
            (0, "50", ""),  # wc -l: 50 lines
            (0, "", ""),  # sed (context lines, empty since beyond EOF)
        ]

        result = asyncio.run(
            _build_rejection_context(sandbox, "/src/target", diff, "patch failed")
        )
        assert "only has 50 lines" in result
        assert "500" in result


# ---------------------------------------------------------------------------
# 4. _check_whitespace_mismatch
# ---------------------------------------------------------------------------


class TestCheckWhitespaceMismatch:
    def test_tabs_vs_spaces_detected(self) -> None:
        """Diff uses spaces but file uses tabs (or vice versa)."""
        diff = (
            "--- a/file.c\n"
            "+++ b/file.c\n"
            "@@ -10,5 +10,5 @@\n"
            "     int x = 0;\n"  # context line with spaces
            "-    old_line;\n"
            "+    new_line;\n"
            "     int y = 1;\n"
        )
        # Actual file uses tabs
        actual_content = "\tint x = 0;\n\tint y = 1;\n"
        parts: list[str] = []

        _check_whitespace_mismatch(diff, "file.c", 10, actual_content, parts)

        assert len(parts) > 0
        assert "Whitespace mismatch" in parts[0]
        assert "tabs vs spaces" in parts[0]

    def test_no_mismatch_when_matching(self) -> None:
        """No warning when whitespace matches exactly."""
        diff = (
            "--- a/file.c\n"
            "+++ b/file.c\n"
            "@@ -10,3 +10,3 @@\n"
            "     int x = 0;\n"
            "-    old;\n"
            "+    new;\n"
        )
        actual_content = "    int x = 0;\n    old;\n"
        parts: list[str] = []

        _check_whitespace_mismatch(diff, "file.c", 10, actual_content, parts)

        assert len(parts) == 0

    def test_empty_actual_content(self) -> None:
        """No crash when actual content is empty."""
        diff = "--- a/file.c\n+++ b/file.c\n@@ -10,3 +10,3 @@\n ctx\n"
        parts: list[str] = []
        _check_whitespace_mismatch(diff, "file.c", 10, "", parts)
        assert len(parts) == 0


# ---------------------------------------------------------------------------
# 5. .rej file contents in error output
# ---------------------------------------------------------------------------


class TestBuildRejectionContextRejFiles:
    def test_rej_file_contents_included(self) -> None:
        """When .rej files exist, their contents appear in error output."""
        diff = "--- a/parser.c\n+++ b/parser.c\n@@ -10,3 +10,3 @@\n ctx\n"
        rej_content = (
            "--- parser.c.orig\n+++ parser.c\n@@ -10,3 +10,3 @@\n"
            " original context\n-wrong line\n+replacement\n"
        )
        sandbox = AsyncMock()

        sandbox.exec.side_effect = [
            (0, "/src/target/parser.c.rej\n", ""),  # find .rej
            (0, rej_content, ""),  # cat .rej file
            (0, "", ""),  # test -f: exists
            (0, "100", ""),  # wc -l
            (0, "  int x = 0;\n  int y = 1;\n", ""),  # sed context
        ]

        result = asyncio.run(
            _build_rejection_context(sandbox, "/src/target", diff, "patch failed")
        )
        assert "Reject file contents" in result
        assert "parser.c.rej" in result
        assert "original context" in result

    def test_no_rej_files_no_section(self) -> None:
        """When no .rej files exist, no reject section appears."""
        diff = "--- a/parser.c\n+++ b/parser.c\n@@ -10,3 +10,3 @@\n ctx\n"
        sandbox = AsyncMock()

        sandbox.exec.side_effect = [
            (0, "", ""),  # find .rej: none
            (0, "", ""),  # test -f: exists
            (0, "100", ""),  # wc -l
            (0, "  int x = 0;\n", ""),  # sed context
        ]

        result = asyncio.run(
            _build_rejection_context(sandbox, "/src/target", diff, "patch failed")
        )
        assert "Reject file" not in result


# ---------------------------------------------------------------------------
# 6. read_source_file hint in error output
# ---------------------------------------------------------------------------


class TestBuildRejectionContextReadSourceHint:
    def test_read_source_file_hint(self) -> None:
        """Error message includes read_source_file hint with correct path and lines."""
        diff = "--- a/SAX2.c\n+++ b/SAX2.c\n@@ -150,3 +150,3 @@\n ctx\n"
        sandbox = AsyncMock()

        sandbox.exec.side_effect = [
            (0, "", ""),  # find .rej: none
            (0, "", ""),  # test -f: exists
            (0, "300", ""),  # wc -l
            (0, "  some code;\n", ""),  # sed context
        ]

        result = asyncio.run(
            _build_rejection_context(sandbox, "/src/target", diff, "patch failed")
        )
        assert "read_source_file" in result
        assert "SAX2.c" in result
        # Hint should suggest lines around hunk_line=150
        assert "start_line=140" in result
        assert "end_line=180" in result
