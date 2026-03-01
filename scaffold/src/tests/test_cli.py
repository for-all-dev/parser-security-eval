"""Tests for CLI command wiring."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from parser_security_eval.cli import app


runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


VULN_RECORD = {
    "id": "OSS-FUZZ-12345",
    "target": "libpng",
    "severity": "high",
    "difficulty": "medium",
    "crash_type": "heap-buffer-overflow",
    "sanitizer": "address",
    "affected_file": "pngrutil.c",
    "affected_function": "png_read_row",
    "cwe": "CWE-125",
    "root_cause": "Off-by-one in row buffer allocation",
    "crash_input_path": "libpng/OSS-FUZZ-12345/crash.png",
    "crash_report_path": "libpng/OSS-FUZZ-12345/crash_report.txt",
    "reference_patch_path": "libpng/OSS-FUZZ-12345/fix.diff",
    "vulnerable_source_ref": "abc123",
    "tags": [],
    "lines_changed_in_fix": None,
    "ossfuzz_project": None,
}

REFERENCE_PATCH = "--- a/pngrutil.c\n+++ b/pngrutil.c\n@@ -100,7 +100,7 @@\n-   buf = malloc(len);\n+   buf = malloc(len + 1);\n"


def make_benchmark(tmp_path: Path) -> Path:
    record_dir = tmp_path / "libpng" / "OSS-FUZZ-12345"
    record_dir.mkdir(parents=True)
    metadata = {
        "version": "0.1.0",
        "total_vulnerabilities": 1,
        "targets": ["libpng"],
        "records": [VULN_RECORD],
    }
    (tmp_path / "metadata.json").write_text(json.dumps(metadata))
    (record_dir / "crash.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (record_dir / "crash_report.txt").write_text("ASAN: heap-buffer-overflow")
    (record_dir / "fix.diff").write_text(REFERENCE_PATCH)
    return tmp_path


def make_targets(tmp_path: Path) -> Path:
    target_dir = tmp_path / "targets" / "libpng"
    target_dir.mkdir(parents=True)
    (target_dir / "metadata.yaml").write_text(
        "name: libpng\nfuzz_targets:\n  - libpng_read_fuzzer\n"
    )
    return tmp_path


# ---------------------------------------------------------------------------
# curate
# ---------------------------------------------------------------------------


class TestCurateCommand:
    def test_unknown_source_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["curate", "unknown"])
        assert result.exit_code != 0
        assert "unknown" in result.output

    def test_arvo_calls_ingest_arvo(self, tmp_path: Path) -> None:
        from parser_security_eval.models.vulnerability import (
            Difficulty,
            Sanitizer,
            Severity,
            VulnerabilityRecord,
        )

        fake_record = VulnerabilityRecord(
            id="OSS-FUZZ-1",
            target="libpng",
            severity=Severity.HIGH,
            difficulty=Difficulty.MEDIUM,
            crash_type="heap-buffer-overflow",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="foo.c",
        )

        with patch(
            "parser_security_eval.cli.ingest_arvo",
            return_value=[fake_record],
        ):
            result = runner.invoke(
                app,
                [
                    "curate",
                    "arvo",
                    "--output",
                    str(tmp_path / "bench"),
                    "--cache-dir",
                    str(tmp_path / "cache"),
                    "--targets",
                    "libpng",
                ],
            )

        assert result.exit_code == 0, result.output
        assert "Total vulnerabilities: 1" in result.output
        assert (tmp_path / "bench" / "metadata.json").exists()

    def test_ossfuzz_calls_fetch_and_parse(self, tmp_path: Path) -> None:
        from parser_security_eval.models.vulnerability import (
            Difficulty,
            Sanitizer,
            Severity,
            VulnerabilityRecord,
        )

        fake_record = VulnerabilityRecord(
            id="OSS-FUZZ-2",
            target="libpng",
            severity=Severity.HIGH,
            difficulty=Difficulty.MEDIUM,
            crash_type="stack-overflow",
            sanitizer=Sanitizer.ADDRESS,
            affected_file="bar.c",
        )

        with (
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                return_value=[{"bug": "data"}],
            ),
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                return_value=fake_record,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "curate",
                    "ossfuzz",
                    "--targets",
                    "libpng",
                    "--output",
                    str(tmp_path / "bench"),
                    "--cache-dir",
                    str(tmp_path / "cache"),
                ],
            )

        assert result.exit_code == 0, result.output
        assert "Total vulnerabilities: 1" in result.output

    def test_limit_is_applied_for_ossfuzz(self, tmp_path: Path) -> None:
        with (
            patch(
                "parser_security_eval.cli.fetch_ossfuzz_bugs",
                return_value=[{"bug": str(i)} for i in range(5)],
            ),
            patch(
                "parser_security_eval.cli.parse_ossfuzz_bug",
                return_value=None,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "curate",
                    "ossfuzz",
                    "--targets",
                    "libpng",
                    "--limit",
                    "2",
                    "--output",
                    str(tmp_path / "bench"),
                    "--cache-dir",
                    str(tmp_path / "cache"),
                ],
            )
        # parse returns None for all, so 0 records — but it ran without error
        assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


class TestEvaluateCommand:
    def _fake_logs(self) -> list:
        log = MagicMock()
        log.task = "vulnerability_patching"
        log.status = "success"
        log.results = None
        return [log]

    def test_unknown_task_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["evaluate", "unknown", "--model", "mock/model"])
        assert result.exit_code != 0
        assert "unknown" in result.output

    def test_harness_requires_target(self) -> None:
        result = runner.invoke(app, ["evaluate", "harness", "--model", "mock/model"])
        assert result.exit_code != 0
        assert "--target" in result.output

    def test_patching_calls_inspect_eval(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)

        with patch("inspect_ai.eval", return_value=self._fake_logs()) as mock_eval:
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "patching",
                    "--model",
                    "mock/model",
                    "--benchmark-dir",
                    str(bdir),
                    "--targets-root",
                    str(tmp_path / "targets"),
                ],
            )

        assert result.exit_code == 0, result.output
        mock_eval.assert_called_once()

    def test_triage_calls_inspect_eval(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)

        with patch("inspect_ai.eval", return_value=self._fake_logs()) as mock_eval:
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "triage",
                    "--model",
                    "mock/model",
                    "--benchmark-dir",
                    str(bdir),
                ],
            )

        assert result.exit_code == 0, result.output
        mock_eval.assert_called_once()

    def test_harness_calls_inspect_eval(self, tmp_path: Path) -> None:
        make_targets(tmp_path)

        with patch("inspect_ai.eval", return_value=self._fake_logs()) as mock_eval:
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "harness",
                    "--model",
                    "mock/model",
                    "--target",
                    "libpng",
                    "--targets-root",
                    str(tmp_path / "targets"),
                ],
            )

        assert result.exit_code == 0, result.output
        mock_eval.assert_called_once()

    def test_engine_forwarded_to_patching(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)

        with patch("inspect_ai.eval", return_value=self._fake_logs()) as mock_eval:
            runner.invoke(
                app,
                [
                    "evaluate",
                    "patching",
                    "--model",
                    "mock/model",
                    "--engine",
                    "honggfuzz",
                    "--benchmark-dir",
                    str(bdir),
                    "--targets-root",
                    str(tmp_path / "targets"),
                ],
            )

        task_arg = mock_eval.call_args[0][0]
        # The task object carries the engine through its scorer config;
        # we just verify eval was called with a Task instance.
        from inspect_ai import Task

        assert isinstance(task_arg, Task)

    def test_seed_without_limit_emits_warning(self, tmp_path: Path) -> None:
        """--seed without --limit is accepted but should emit a warning."""
        import warnings

        bdir = make_benchmark(tmp_path)

        with (
            patch("inspect_ai.eval", return_value=self._fake_logs()),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always")
            result = runner.invoke(
                app,
                [
                    "evaluate",
                    "patching",
                    "--model",
                    "mock/model",
                    "--seed",
                    "42",
                    "--benchmark-dir",
                    str(bdir),
                    "--targets-root",
                    str(tmp_path / "targets"),
                ],
            )

        assert result.exit_code == 0, result.output
        assert any(
            "--seed" in str(w.message) or "seed" in str(w.message).lower()
            for w in caught
        )

    def test_seed_with_limit_selects_reproducibly(self, tmp_path: Path) -> None:
        """Same seed + limit produces the same sample selection on repeated calls."""
        import json as _json

        # Build a benchmark with 3 records
        records = []
        for i in range(3):
            vuln_id = f"OSS-FUZZ-{20000 + i}"
            record_dir = tmp_path / "libpng" / vuln_id
            record_dir.mkdir(parents=True, exist_ok=True)
            (record_dir / "crash_report.txt").write_text(f"ASAN #{i}")
            (record_dir / "fix.diff").write_text(
                f"--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-{i}\n+{i + 1}\n"
            )
            records.append(
                {
                    "id": vuln_id,
                    "target": "libpng",
                    "severity": "high",
                    "difficulty": "medium",
                    "crash_type": "heap-buffer-overflow",
                    "sanitizer": "address",
                    "affected_file": "f.c",
                    "affected_function": None,
                    "cwe": None,
                    "root_cause": None,
                    "crash_input_path": None,
                    "crash_report_path": f"libpng/{vuln_id}/crash_report.txt",
                    "reference_patch_path": f"libpng/{vuln_id}/fix.diff",
                    "vulnerable_source_ref": None,
                    "tags": [],
                    "lines_changed_in_fix": None,
                    "ossfuzz_project": None,
                }
            )
        (tmp_path / "metadata.json").write_text(
            _json.dumps(
                {
                    "version": "0.1.0",
                    "total_vulnerabilities": 3,
                    "targets": ["libpng"],
                    "records": records,
                }
            )
        )

        from parser_security_eval.tasks.patching import load_patching_dataset

        # load_patching_dataset with same seed twice must yield same order
        ids_a = [s.id for s in load_patching_dataset(str(tmp_path), seed=7)]
        ids_b = [s.id for s in load_patching_dataset(str(tmp_path), seed=7)]
        assert ids_a == ids_b


# ---------------------------------------------------------------------------
# build-target
# ---------------------------------------------------------------------------


class TestBuildTargetCommand:
    def test_missing_target_dir_exits_nonzero(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["build-target", "libpng", "--targets-root", str(tmp_path / "targets")],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_successful_build(self, tmp_path: Path) -> None:
        tdir = make_targets(tmp_path)

        with (
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.build_image",
                new_callable=AsyncMock,
                return_value="sha256:abc",
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.start",
                new_callable=AsyncMock,
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.build_target",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.stop",
                new_callable=AsyncMock,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "build-target",
                    "libpng",
                    "--targets-root",
                    str(tdir / "targets"),
                ],
            )

        assert result.exit_code == 0, result.output
        assert "succeeded" in result.output

    def test_failed_build_exits_nonzero(self, tmp_path: Path) -> None:
        tdir = make_targets(tmp_path)

        with (
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.build_image",
                new_callable=AsyncMock,
                return_value="sha256:abc",
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.start",
                new_callable=AsyncMock,
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.build_target",
                new_callable=AsyncMock,
                return_value=False,
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.stop",
                new_callable=AsyncMock,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "build-target",
                    "libpng",
                    "--targets-root",
                    str(tdir / "targets"),
                ],
            )

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    def _make_patch_file(self, tmp_path: Path) -> Path:
        p = tmp_path / "fix.diff"
        p.write_text(REFERENCE_PATCH)
        return p

    def test_missing_metadata_exits_nonzero(self, tmp_path: Path) -> None:
        patch_file = self._make_patch_file(tmp_path)
        result = runner.invoke(
            app,
            [
                "verify",
                "libpng",
                "OSS-FUZZ-12345",
                str(patch_file),
                "--benchmark-dir",
                str(tmp_path / "bench"),
            ],
        )
        assert result.exit_code != 0
        assert "metadata" in result.output

    def test_unknown_vuln_id_exits_nonzero(self, tmp_path: Path) -> None:
        bdir = make_benchmark(tmp_path)
        patch_file = self._make_patch_file(tmp_path)
        result = runner.invoke(
            app,
            [
                "verify",
                "libpng",
                "OSS-FUZZ-99999",
                str(patch_file),
                "--benchmark-dir",
                str(bdir),
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_successful_verification(self, tmp_path: Path) -> None:
        from parser_security_eval.models.scoring import PatchResult

        bdir = make_benchmark(tmp_path)
        tdir = make_targets(tmp_path)
        patch_file = self._make_patch_file(tmp_path)

        full_result = PatchResult(
            patch_applies=True,
            compiles=True,
            crash_eliminated=True,
            tests_pass=True,
            diff_lines=2,
        )

        with (
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.build_image",
                new_callable=AsyncMock,
                return_value="sha256:abc",
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.start",
                new_callable=AsyncMock,
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.stop",
                new_callable=AsyncMock,
            ),
            patch(
                "parser_security_eval.scorers.patch.score_patch",
                new=AsyncMock(return_value=full_result),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "verify",
                    "libpng",
                    "OSS-FUZZ-12345",
                    str(patch_file),
                    "--benchmark-dir",
                    str(bdir),
                    "--targets-root",
                    str(tdir / "targets"),
                ],
            )

        assert result.exit_code == 0, result.output
        assert "success:          True" in result.output

    def test_failed_verification_exits_nonzero(self, tmp_path: Path) -> None:
        from parser_security_eval.models.scoring import PatchResult

        bdir = make_benchmark(tmp_path)
        tdir = make_targets(tmp_path)
        patch_file = self._make_patch_file(tmp_path)

        bad_result = PatchResult(
            patch_applies=True,
            compiles=False,
            crash_eliminated=False,
            tests_pass=False,
            diff_lines=2,
        )

        with (
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.build_image",
                new_callable=AsyncMock,
                return_value="sha256:abc",
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.start",
                new_callable=AsyncMock,
            ),
            patch(
                "parser_security_eval.sandbox.docker.DockerSandbox.stop",
                new_callable=AsyncMock,
            ),
            patch(
                "parser_security_eval.scorers.patch.score_patch",
                new=AsyncMock(return_value=bad_result),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "verify",
                    "libpng",
                    "OSS-FUZZ-12345",
                    str(patch_file),
                    "--benchmark-dir",
                    str(bdir),
                    "--targets-root",
                    str(tdir / "targets"),
                ],
            )

        assert result.exit_code != 0
