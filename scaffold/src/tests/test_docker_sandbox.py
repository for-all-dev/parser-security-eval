"""Tests for DockerSandbox — mocked subprocess, no Docker required."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from parser_security_eval.sandbox.docker import (
    ENGINE_LIB,
    DockerSandbox,
    SandboxConfig,
    _build_env,
    _run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides: object) -> SandboxConfig:
    defaults: dict[str, object] = {
        "target_name": "libpng",
        "target_dir": Path("/tmp/targets/libpng"),
    }
    defaults.update(overrides)
    return SandboxConfig(**defaults)  # type: ignore[arg-type]


def _fake_process(stdout: str = "", stderr: str = "", returncode: int = 0) -> AsyncMock:
    """Return a mock that quacks like asyncio.subprocess.Process."""
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout.encode(), stderr.encode()))
    proc.returncode = returncode
    proc.kill = MagicMock()
    proc.wait = AsyncMock()
    return proc


# ---------------------------------------------------------------------------
# Unit: _build_env
# ---------------------------------------------------------------------------


class TestBuildEnv:
    def test_address_sanitizer(self) -> None:
        cfg = _make_config(sanitizer="address", engine="libfuzzer")
        env = _build_env(cfg)
        assert env["CC"] == "clang"
        assert env["CXX"] == "clang++"
        assert "-fsanitize=address" in env["CFLAGS"]
        assert env["LIB_FUZZING_ENGINE"] == ENGINE_LIB["libfuzzer"]
        assert env["SANITIZER"] == "address"

    def test_memory_sanitizer_afl(self) -> None:
        cfg = _make_config(sanitizer="memory", engine="afl")
        env = _build_env(cfg)
        assert "-fsanitize=memory" in env["CFLAGS"]
        assert env["LIB_FUZZING_ENGINE"] == ENGINE_LIB["afl"]

    def test_unknown_engine_falls_back(self) -> None:
        cfg = _make_config(engine="unknown-engine")
        env = _build_env(cfg)
        assert env["LIB_FUZZING_ENGINE"] == ENGINE_LIB["libfuzzer"]


# ---------------------------------------------------------------------------
# Unit: _run
# ---------------------------------------------------------------------------


class TestRun:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        proc = _fake_process(stdout="ok\n", returncode=0)
        with patch("parser_security_eval.sandbox.docker.asyncio") as mock_aio:
            mock_aio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_aio.subprocess = asyncio.subprocess
            mock_aio.wait_for = AsyncMock(return_value=(b"ok\n", b""))
            mock_aio.TimeoutError = asyncio.TimeoutError
            rc, out, err = await _run("echo", "hello")
        assert rc == 0
        assert out == "ok\n"

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        proc = _fake_process()
        with patch("parser_security_eval.sandbox.docker.asyncio") as mock_aio:
            mock_aio.create_subprocess_exec = AsyncMock(return_value=proc)
            mock_aio.subprocess = asyncio.subprocess
            mock_aio.wait_for = AsyncMock(side_effect=asyncio.TimeoutError)
            mock_aio.TimeoutError = asyncio.TimeoutError
            rc, out, err = await _run("sleep", "999", timeout=1)
        assert rc == -1
        assert err == "timeout"


# ---------------------------------------------------------------------------
# Integration-style: DockerSandbox with mocked _run
# ---------------------------------------------------------------------------


class TestDockerSandbox:
    """All tests patch _run so no real docker calls are made."""

    @pytest.mark.asyncio
    async def test_image_tag(self) -> None:
        sandbox = DockerSandbox(_make_config(target_name="libxml2"))
        assert sandbox.image_tag == "parser-eval-libxml2"

    @pytest.mark.asyncio
    async def test_build_image(self) -> None:
        sandbox = DockerSandbox(_make_config())
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.side_effect = [
                (0, "built\n", ""),  # docker build
                (0, "sha256:abc123\n", ""),  # docker inspect
            ]
            image_id = await sandbox.build_image()
        assert image_id == "sha256:abc123"
        assert sandbox._image_id == "sha256:abc123"

        # Verify docker build was called with the right args.
        build_call = mock_run.call_args_list[0]
        assert build_call == call(
            "docker",
            "build",
            "-t",
            "parser-eval-libpng",
            str(Path("/tmp/targets/libpng")),
        )

    @pytest.mark.asyncio
    async def test_build_image_failure(self) -> None:
        sandbox = DockerSandbox(_make_config())
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.return_value = (1, "", "error building")
            with pytest.raises(RuntimeError, match="docker build failed"):
                await sandbox.build_image()

    @pytest.mark.asyncio
    async def test_start(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._image_id = "sha256:abc"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.return_value = (0, "container123\n", "")
            await sandbox.start()
        assert sandbox._container_id == "container123"

        run_call = mock_run.call_args
        args = run_call[0]
        assert "docker" in args
        assert "run" in args
        assert "--security-opt=no-new-privileges" in args
        assert "--memory=4g" in args
        assert "--network=none" in args

    @pytest.mark.asyncio
    async def test_start_without_image_raises(self) -> None:
        sandbox = DockerSandbox(_make_config())
        with pytest.raises(RuntimeError, match="Must build_image"):
            await sandbox.start()

    @pytest.mark.asyncio
    async def test_stop(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.return_value = (0, "", "")
            await sandbox.stop()
        assert sandbox._container_id is None
        mock_run.assert_called_once_with("docker", "rm", "-f", "c123")

    @pytest.mark.asyncio
    async def test_stop_noop_when_not_running(self) -> None:
        sandbox = DockerSandbox(_make_config())
        # Should not raise.
        await sandbox.stop()

    @pytest.mark.asyncio
    async def test_exec(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.return_value = (0, "hello\n", "")
            rc, out, err = await sandbox.exec("echo hello")
        assert rc == 0
        assert out == "hello\n"
        mock_run.assert_called_once_with(
            "docker",
            "exec",
            "c123",
            "bash",
            "-c",
            "echo hello",
            timeout=None,
        )

    @pytest.mark.asyncio
    async def test_exec_not_running_raises(self) -> None:
        sandbox = DockerSandbox(_make_config())
        with pytest.raises(RuntimeError, match="Container not running"):
            await sandbox.exec("ls")

    @pytest.mark.asyncio
    async def test_copy_in(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.return_value = (0, "", "")
            await sandbox.copy_in(Path("/tmp/seed"), "/src/seed")
        mock_run.assert_called_once_with(
            "docker",
            "cp",
            "/tmp/seed",
            "c123:/src/seed",
        )

    @pytest.mark.asyncio
    async def test_copy_out(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.return_value = (0, "", "")
            await sandbox.copy_out("/out/crash-1", Path("/tmp/crash-1"))
        mock_run.assert_called_once_with(
            "docker",
            "cp",
            "c123:/out/crash-1",
            "/tmp/crash-1",
        )

    @pytest.mark.asyncio
    async def test_build_target(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, "ok", "")
            result = await sandbox.build_target()
        assert result is True
        # Check that build.sh is invoked with env vars.
        cmd = mock_exec.call_args[0][0]
        assert "bash /src/build.sh" in cmd
        assert 'CC="clang"' in cmd
        assert "fsanitize=address" in cmd

    @pytest.mark.asyncio
    async def test_build_target_failure(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (1, "", "compile error")
            result = await sandbox.build_target()
        assert result is False

    @pytest.mark.asyncio
    async def test_build_target_allow_network(self) -> None:
        """allow_network=True builds in a temp container, commits, and recreates."""
        sandbox = DockerSandbox(_make_config())
        sandbox._image_id = "sha256:old"
        sandbox._container_id = "main_c"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.side_effect = [
                (0, "tmp_c\n", ""),  # docker run (temp container)
                (0, "built ok", ""),  # docker exec (build)
                (0, "", ""),  # docker commit
                (0, "sha256:new\n", ""),  # docker image inspect
                (0, "", ""),  # docker rm -f tmp_c (finally)
                (0, "", ""),  # docker rm -f main_c (stop)
                (0, "new_main_c\n", ""),  # docker run (start)
            ]
            result = await sandbox.build_target(allow_network=True)

        assert result is True
        assert sandbox._container_id == "new_main_c"
        assert sandbox._image_id == "sha256:new"

        # Verify temp container had network (no --network=none).
        run_call_args = mock_run.call_args_list[0][0]
        assert "--network=none" not in run_call_args

        # Verify main container was recreated with --network=none.
        restart_call_args = mock_run.call_args_list[6][0]
        assert "--network=none" in restart_call_args

    @pytest.mark.asyncio
    async def test_build_target_allow_network_build_failure(self) -> None:
        """allow_network=True still returns False on build failure."""
        sandbox = DockerSandbox(_make_config())
        sandbox._image_id = "sha256:old"
        sandbox._container_id = "main_c"
        with patch("parser_security_eval.sandbox.docker._run") as mock_run:
            mock_run.side_effect = [
                (0, "tmp_c\n", ""),  # docker run (temp container)
                (1, "", "compile error"),  # docker exec (build fails)
                (0, "", ""),  # docker rm -f tmp_c (finally)
            ]
            result = await sandbox.build_target(allow_network=True)

        assert result is False
        # Main container should be unchanged (no restart on build failure).
        assert sandbox._container_id == "main_c"

    @pytest.mark.asyncio
    async def test_build_target_allow_network_no_image_raises(self) -> None:
        """allow_network=True requires build_image() first."""
        sandbox = DockerSandbox(_make_config())
        with pytest.raises(RuntimeError, match="Must build_image"):
            await sandbox.build_target(allow_network=True)

    @pytest.mark.asyncio
    async def test_run_fuzzer_libfuzzer(self) -> None:
        sandbox = DockerSandbox(_make_config(engine="libfuzzer"))
        sandbox._container_id = "c123"
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            # First call: mkdir; second call: actual fuzzer.
            mock_exec.side_effect = [
                (0, "", ""),
                (0, "DONE 1000 runs", ""),
            ]
            rc, log = await sandbox.run_fuzzer("fuzz_png", duration_seconds=60)
        assert rc == 0
        assert "DONE" in log
        fuzzer_cmd = mock_exec.call_args_list[1][0][0]
        assert "/out/fuzz_png" in fuzzer_cmd
        assert "-artifact_prefix=/out/crashes/" in fuzzer_cmd
        assert "-max_total_time=60" in fuzzer_cmd

    @pytest.mark.asyncio
    async def test_run_fuzzer_afl(self) -> None:
        sandbox = DockerSandbox(_make_config(engine="afl"))
        sandbox._container_id = "c123"
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = [
                (0, "", ""),
                (0, "afl done", ""),
            ]
            rc, log = await sandbox.run_fuzzer("fuzz_png")
        fuzzer_cmd = mock_exec.call_args_list[1][0][0]
        assert "afl-fuzz" in fuzzer_cmd

    @pytest.mark.asyncio
    async def test_run_fuzzer_unknown_engine(self) -> None:
        sandbox = DockerSandbox(_make_config(engine="nope"))
        sandbox._container_id = "c123"
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, "", "")
            with pytest.raises(ValueError, match="Unknown engine"):
                await sandbox.run_fuzzer("fuzz_png")

    @pytest.mark.asyncio
    async def test_collect_crashes_none(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = (0, "", "")
            crashes = await sandbox.collect_crashes()
        assert crashes == []

    @pytest.mark.asyncio
    async def test_collect_crashes(self) -> None:
        sandbox = DockerSandbox(_make_config())
        sandbox._container_id = "c123"
        with (
            patch.object(sandbox, "exec", new_callable=AsyncMock) as mock_exec,
            patch.object(sandbox, "copy_out", new_callable=AsyncMock) as mock_copy,
        ):
            mock_exec.return_value = (
                0,
                "/out/crashes/crash-abc\n/out/crashes/crash-def\n",
                "",
            )
            crashes = await sandbox.collect_crashes()
        assert len(crashes) == 2
        assert crashes[0].name == "crash-abc"
        assert crashes[1].name == "crash-def"
        assert mock_copy.call_count == 2

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        sandbox = DockerSandbox(_make_config())
        with (
            patch.object(sandbox, "build_image", new_callable=AsyncMock) as mock_build,
            patch.object(sandbox, "start", new_callable=AsyncMock) as mock_start,
            patch.object(sandbox, "stop", new_callable=AsyncMock) as mock_stop,
        ):
            mock_build.return_value = "sha256:abc"
            async with sandbox as s:
                assert s is sandbox
            mock_build.assert_awaited_once()
            mock_start.assert_awaited_once()
            mock_stop.assert_awaited_once()
