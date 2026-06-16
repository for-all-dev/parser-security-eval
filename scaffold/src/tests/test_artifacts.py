"""Tests for artifact fetching with patch_url and Docker fallbacks."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from parser_security_eval.dataset.artifacts import (
    _extract_sources_from_docker,
    _fetch_patch_from_url,
    extract_vulnerable_sources,
    fetch_reference_patches,
)

# ---------------------------------------------------------------------------
# _fetch_patch_from_url
# ---------------------------------------------------------------------------


class TestFetchPatchFromUrl:
    def test_github_commit_url_appends_diff(self) -> None:
        """GitHub commit URLs should have .diff appended."""
        diff_text = (
            "diff --git a/src/foo.c b/src/foo.c\n--- a/src/foo.c\n+++ b/src/foo.c\n"
        )
        response = MagicMock()
        response.read.return_value = diff_text.encode()
        response.__enter__ = lambda s: s
        response.__exit__ = MagicMock(return_value=False)

        with patch(
            "parser_security_eval.dataset.artifacts.urllib.request.urlopen"
        ) as mock_open:
            mock_open.return_value = response
            result = _fetch_patch_from_url("https://github.com/foo/bar/commit/abc123")

        assert result == diff_text
        # Verify .diff was appended
        call_args = mock_open.call_args[0][0]
        assert call_args.full_url == "https://github.com/foo/bar/commit/abc123.diff"

    def test_non_diff_response_returns_none(self) -> None:
        """HTML or other non-diff responses should return None."""
        html = "<html><body>Not a diff</body></html>"
        response = MagicMock()
        response.read.return_value = html.encode()
        response.__enter__ = lambda s: s
        response.__exit__ = MagicMock(return_value=False)

        with patch(
            "parser_security_eval.dataset.artifacts.urllib.request.urlopen"
        ) as mock_open:
            mock_open.return_value = response
            result = _fetch_patch_from_url("https://example.com/commit/abc")

        assert result is None

    def test_network_error_returns_none(self) -> None:
        """Network errors should be caught and return None."""
        with patch(
            "parser_security_eval.dataset.artifacts.urllib.request.urlopen",
            side_effect=OSError("Connection refused"),
        ):
            result = _fetch_patch_from_url("https://example.com/patch")

        assert result is None

    def test_empty_url_returns_none(self) -> None:
        assert _fetch_patch_from_url("") is None

    def test_non_http_url_returns_none(self) -> None:
        assert _fetch_patch_from_url("ftp://example.com/patch") is None

    def test_plain_diff_response(self) -> None:
        """Non-GitHub URLs that return a valid diff should work."""
        diff_text = "--- a/file.c\n+++ b/file.c\n@@ -1 +1 @@\n"
        response = MagicMock()
        response.read.return_value = diff_text.encode()
        response.__enter__ = lambda s: s
        response.__exit__ = MagicMock(return_value=False)

        with patch(
            "parser_security_eval.dataset.artifacts.urllib.request.urlopen"
        ) as mock_open:
            mock_open.return_value = response
            result = _fetch_patch_from_url("https://fossil-scm.org/patch/123")

        assert result == diff_text


# ---------------------------------------------------------------------------
# _extract_sources_from_docker
# ---------------------------------------------------------------------------


class TestExtractSourcesFromDocker:
    def test_successful_extraction(self, tmp_path: Path) -> None:
        """Docker extraction should pull, create, find, cp, and rm."""
        vuln_dir = tmp_path / "arvo" / "ARVO-100"
        vuln_dir.mkdir(parents=True)

        calls: list[list[str]] = []

        def mock_run(
            cmd: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if cmd[0] == "docker" and cmd[1] == "pull":
                return subprocess.CompletedProcess(cmd, 0)
            if cmd[0] == "docker" and cmd[1] == "create":
                return subprocess.CompletedProcess(cmd, 0)
            if cmd[0] == "docker" and cmd[1] == "run" and "find" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="/src/project/foo.c\n"
                )
            if cmd[0] == "docker" and cmd[1] == "cp":
                # Simulate docker cp by writing a file
                dest = cmd[-1]
                Path(dest).parent.mkdir(parents=True, exist_ok=True)
                Path(dest).write_text("int main() { return 0; }")
                return subprocess.CompletedProcess(cmd, 0)
            if cmd[0] == "docker" and cmd[1] == "rm":
                return subprocess.CompletedProcess(cmd, 0)
            return subprocess.CompletedProcess(cmd, 1)

        with patch(
            "parser_security_eval.dataset.artifacts.subprocess.run",
            side_effect=mock_run,
        ):
            result = _extract_sources_from_docker(100, ["src/foo.c"], vuln_dir)

        assert "src/foo.c" in result
        assert result["src/foo.c"] == "arvo/ARVO-100/vulnerable_src/foo.c"
        # Verify container cleanup
        rm_calls = [c for c in calls if c[0] == "docker" and c[1] == "rm"]
        assert len(rm_calls) == 1

    def test_pull_failure_returns_empty(self, tmp_path: Path) -> None:
        """Failed Docker pull should return empty dict and track failure."""
        vuln_dir = tmp_path / "arvo" / "ARVO-200"
        vuln_dir.mkdir(parents=True)
        failed: set[int] = set()

        with patch(
            "parser_security_eval.dataset.artifacts.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "docker pull"),
        ):
            result = _extract_sources_from_docker(
                200, ["src/bar.c"], vuln_dir, failed_images=failed
            )

        assert result == {}
        assert 200 in failed

    def test_skips_already_failed_images(self, tmp_path: Path) -> None:
        """Should skip images that previously failed to pull."""
        vuln_dir = tmp_path / "arvo" / "ARVO-300"
        vuln_dir.mkdir(parents=True)
        failed: set[int] = {300}

        with patch(
            "parser_security_eval.dataset.artifacts.subprocess.run",
        ) as mock_run:
            result = _extract_sources_from_docker(
                300, ["src/baz.c"], vuln_dir, failed_images=failed
            )

        assert result == {}
        mock_run.assert_not_called()

    def test_container_cleanup_on_error(self, tmp_path: Path) -> None:
        """Container should be cleaned up even if extraction fails."""
        vuln_dir = tmp_path / "arvo" / "ARVO-400"
        vuln_dir.mkdir(parents=True)
        calls: list[list[str]] = []

        def mock_run(
            cmd: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            if cmd[0] == "docker" and cmd[1] == "pull":
                return subprocess.CompletedProcess(cmd, 0)
            if cmd[0] == "docker" and cmd[1] == "create":
                return subprocess.CompletedProcess(cmd, 0)
            if cmd[0] == "docker" and cmd[1] == "run" and "find" in cmd:
                raise subprocess.TimeoutExpired(cmd, 30)
            if cmd[0] == "docker" and cmd[1] == "rm":
                return subprocess.CompletedProcess(cmd, 0)
            return subprocess.CompletedProcess(cmd, 0)

        with patch(
            "parser_security_eval.dataset.artifacts.subprocess.run",
            side_effect=mock_run,
        ):
            result = _extract_sources_from_docker(400, ["src/qux.c"], vuln_dir)

        assert result == {}
        rm_calls = [c for c in calls if c[0] == "docker" and c[1] == "rm"]
        assert len(rm_calls) == 1


# ---------------------------------------------------------------------------
# fetch_reference_patches — patch_url fallback
# ---------------------------------------------------------------------------


def _make_metadata(tmp_path: Path, records: list[dict]) -> Path:
    """Write a metadata.json and return the benchmark directory."""
    benchmark_dir = tmp_path / "benchmark"
    benchmark_dir.mkdir()
    metadata = {"records": records}
    (benchmark_dir / "metadata.json").write_text(json.dumps(metadata))
    return benchmark_dir


def _make_arvo_db(cache_dir: Path, rows: list[dict]) -> Path:
    """Create a minimal arvo.db with the given rows."""
    import sqlite3 as sqlite3_mod

    cache_dir.mkdir(parents=True, exist_ok=True)
    db_path = cache_dir / "arvo.db"
    conn = sqlite3_mod.connect(str(db_path))
    conn.execute(
        "CREATE TABLE arvo ("
        "  localId INTEGER, fix_commit TEXT, repo_addr TEXT, patch_url TEXT"
        ")"
    )
    for row in rows:
        conn.execute(
            "INSERT INTO arvo (localId, fix_commit, repo_addr, patch_url) VALUES (?, ?, ?, ?)",
            (
                row["localId"],
                row.get("fix_commit", ""),
                row.get("repo_addr", ""),
                row.get("patch_url", ""),
            ),
        )
    conn.commit()
    conn.close()
    return db_path


class TestFetchReferencePatchesFallback:
    def test_patch_url_fallback_on_clone_failure(self, tmp_path: Path) -> None:
        """When git clone fails, should fall back to patch_url."""
        records = [{"id": "ARVO-100", "target": "sqlite3"}]
        benchmark_dir = _make_metadata(tmp_path, records)
        cache_dir = tmp_path / "cache"

        diff_text = "diff --git a/src/main.c b/src/main.c\n-old\n+new\n"
        _make_arvo_db(
            cache_dir,
            [
                {
                    "localId": 100,
                    "fix_commit": "abc123",
                    "repo_addr": "https://fossil-scm.org/sqlite",
                    "patch_url": "https://github.com/sqlite/sqlite/commit/abc123",
                }
            ],
        )

        def mock_clone_or_update(repo_url: str, clone_dir: Path) -> None:
            raise subprocess.CalledProcessError(1, "git clone")

        response = MagicMock()
        response.read.return_value = diff_text.encode()
        response.__enter__ = lambda s: s
        response.__exit__ = MagicMock(return_value=False)

        with (
            patch(
                "parser_security_eval.dataset.artifacts._clone_or_update",
                side_effect=mock_clone_or_update,
            ),
            patch(
                "parser_security_eval.dataset.artifacts.urllib.request.urlopen",
                return_value=response,
            ),
        ):
            success, total = fetch_reference_patches(benchmark_dir, cache_dir)

        assert success == 1
        assert total == 1
        # Verify patch was written
        patch_path = benchmark_dir / "arvo" / "ARVO-100" / "reference_patch.diff"
        assert patch_path.exists()
        assert "diff --git" in patch_path.read_text()

        # Verify metadata was updated
        meta = json.loads((benchmark_dir / "metadata.json").read_text())
        rec = meta["records"][0]
        assert rec["reference_patch_path"] == "arvo/ARVO-100/reference_patch.diff"
        assert rec["source_extraction_method"] == "patch_url"

    def test_git_success_does_not_use_patch_url(self, tmp_path: Path) -> None:
        """When git works, patch_url should not be fetched."""
        records = [{"id": "ARVO-200", "target": "libpng"}]
        benchmark_dir = _make_metadata(tmp_path, records)
        cache_dir = tmp_path / "cache"

        _make_arvo_db(
            cache_dir,
            [
                {
                    "localId": 200,
                    "fix_commit": "def456",
                    "repo_addr": "https://github.com/glennrp/libpng.git",
                    "patch_url": "https://github.com/glennrp/libpng/commit/def456",
                }
            ],
        )

        diff_text = "diff --git a/png.c b/png.c\n-old\n+new\n"

        with (
            patch(
                "parser_security_eval.dataset.artifacts._clone_or_update",
            ),
            patch(
                "parser_security_eval.dataset.artifacts._git_diff_for_commit",
                return_value=diff_text,
            ),
            patch(
                "parser_security_eval.dataset.artifacts.urllib.request.urlopen",
            ) as mock_urlopen,
        ):
            success, total = fetch_reference_patches(benchmark_dir, cache_dir)

        assert success == 1
        mock_urlopen.assert_not_called()

        meta = json.loads((benchmark_dir / "metadata.json").read_text())
        assert meta["records"][0]["source_extraction_method"] == "git"


# ---------------------------------------------------------------------------
# extract_vulnerable_sources — Docker fallback
# ---------------------------------------------------------------------------


class TestExtractVulnerableSourcesFallback:
    def test_docker_fallback_when_git_fails(self, tmp_path: Path) -> None:
        """When git clone fails, should fall back to Docker extraction."""
        records = [
            {
                "id": "ARVO-100",
                "target": "sqlite3",
                "reference_patch_path": "arvo/ARVO-100/reference_patch.diff",
            }
        ]
        benchmark_dir = _make_metadata(tmp_path, records)
        cache_dir = tmp_path / "cache"

        # Write the reference patch
        patch_dir = benchmark_dir / "arvo" / "ARVO-100"
        patch_dir.mkdir(parents=True)
        (patch_dir / "reference_patch.diff").write_text(
            "diff --git a/src/main.c b/src/main.c\n-old\n+new\n"
        )

        _make_arvo_db(
            cache_dir,
            [
                {
                    "localId": 100,
                    "fix_commit": "abc123",
                    "repo_addr": "https://fossil-scm.org/sqlite",
                    "patch_url": "",
                }
            ],
        )

        docker_result = {"src/main.c": "arvo/ARVO-100/vulnerable_src/main.c"}

        with (
            patch(
                "parser_security_eval.dataset.artifacts._clone_or_update",
                side_effect=subprocess.CalledProcessError(1, "git clone"),
            ),
            patch(
                "parser_security_eval.dataset.artifacts._extract_sources_from_docker",
                return_value=docker_result,
            ) as mock_docker,
        ):
            success, total = extract_vulnerable_sources(benchmark_dir, cache_dir)

        assert success == 1
        mock_docker.assert_called_once()

        meta = json.loads((benchmark_dir / "metadata.json").read_text())
        rec = meta["records"][0]
        assert rec["vulnerable_source_paths"] == docker_result
        assert rec["source_extraction_method"] == "docker"

    def test_git_success_skips_docker(self, tmp_path: Path) -> None:
        """When git extraction succeeds, Docker should not be called."""
        records = [
            {
                "id": "ARVO-200",
                "target": "libpng",
                "reference_patch_path": "arvo/ARVO-200/reference_patch.diff",
            }
        ]
        benchmark_dir = _make_metadata(tmp_path, records)
        cache_dir = tmp_path / "cache"

        patch_dir = benchmark_dir / "arvo" / "ARVO-200"
        patch_dir.mkdir(parents=True)
        (patch_dir / "reference_patch.diff").write_text(
            "diff --git a/png.c b/png.c\n-old\n+new\n"
        )

        _make_arvo_db(
            cache_dir,
            [
                {
                    "localId": 200,
                    "fix_commit": "def456",
                    "repo_addr": "https://github.com/glennrp/libpng.git",
                    "patch_url": "",
                }
            ],
        )

        def mock_run(
            cmd: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            # Simulate successful git fetch
            if "fetch" in cmd:
                return subprocess.CompletedProcess(cmd, 0)
            return subprocess.CompletedProcess(cmd, 0)

        with (
            patch("parser_security_eval.dataset.artifacts._clone_or_update"),
            patch(
                "parser_security_eval.dataset.artifacts.subprocess.run",
                side_effect=mock_run,
            ),
            patch(
                "parser_security_eval.dataset.artifacts._git_show_file",
                return_value="int main() {}",
            ),
            patch(
                "parser_security_eval.dataset.artifacts._extract_sources_from_docker",
            ) as mock_docker,
        ):
            success, total = extract_vulnerable_sources(benchmark_dir, cache_dir)

        assert success == 1
        mock_docker.assert_not_called()

        meta = json.loads((benchmark_dir / "metadata.json").read_text())
        assert meta["records"][0]["source_extraction_method"] == "git"
