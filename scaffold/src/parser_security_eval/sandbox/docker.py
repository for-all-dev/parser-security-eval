"""Docker sandbox for building and running parser targets.

Each parser target runs in an isolated Docker container following
oss-fuzz conventions:
- /src/<project>  — parser source code
- /out/           — compiled fuzz targets, corpora, dictionaries
- /work/          — intermediate build artifacts
"""

import asyncio
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxConfig:
    """Configuration for a Docker sandbox instance."""

    target_name: str
    target_dir: Path  # local path to target definition
    sanitizer: str = "address"
    engine: str = "libfuzzer"
    timeout_seconds: int = 600
    memory_limit: str = "4g"


# Maps engine config values to oss-fuzz engine library paths.
# LIB_FUZZING_ENGINE values matching what oss-fuzz's compile_* scripts set.
# For libfuzzer the compile script sets LIB_FUZZING_ENGINE="-fsanitize=fuzzer".
ENGINE_LIB: dict[str, str] = {
    "libfuzzer": "-fsanitize=fuzzer",
    "afl": "/usr/lib/afl/afl-compiler-rt.o",
    "honggfuzz": "/src/honggfuzz/honggfuzz.a",
}


def _build_env(config: SandboxConfig) -> dict[str, str]:
    """Return oss-fuzz-style build environment variables."""
    sanitizer = config.sanitizer
    san_flags = f"-fsanitize={sanitizer} -fno-omit-frame-pointer -g"
    return {
        "CC": "clang",
        "CXX": "clang++",
        "CFLAGS": san_flags,
        "CXXFLAGS": san_flags,
        "LIB_FUZZING_ENGINE": ENGINE_LIB.get(config.engine, ENGINE_LIB["libfuzzer"]),
        "SANITIZER": sanitizer,
        "FUZZING_ENGINE": config.engine,
        "ARCHITECTURE": "x86_64",
        "SRC": "/src",
        "OUT": "/out",
        "WORK": "/work",
    }


async def _run(
    *args: str,
    timeout: int | None = None,
    stdin_data: bytes | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess and return (exit_code, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", "timeout"

    return (
        proc.returncode or 0,
        stdout_bytes.decode(errors="replace"),
        stderr_bytes.decode(errors="replace"),
    )


class DockerSandbox:
    """Manages a Docker container for building and fuzzing a parser target."""

    def __init__(self, config: SandboxConfig) -> None:
        self.config = config
        self._container_id: str | None = None
        self._image_id: str | None = None

    @property
    def image_tag(self) -> str:
        return f"parser-eval-{self.config.target_name}"

    # --- image / container lifecycle ---

    async def build_image(self) -> str:
        """Build the Docker image for this target. Returns the image ID."""
        tag = self.image_tag
        rc, stdout, stderr = await _run(
            "docker",
            "build",
            "-t",
            tag,
            str(self.config.target_dir),
        )
        if rc != 0:
            raise RuntimeError(f"docker build failed (rc={rc}): {stderr}")

        # Resolve to image ID for reproducibility.
        rc2, image_id, err2 = await _run(
            "docker",
            "image",
            "inspect",
            tag,
            "--format",
            "{{.Id}}",
        )
        if rc2 != 0:
            raise RuntimeError(f"docker inspect failed: {err2}")
        self._image_id = image_id.strip()
        return self._image_id

    async def start(self) -> None:
        """Start the sandbox container."""
        if self._image_id is None:
            raise RuntimeError("Must build_image() before start()")

        rc, stdout, stderr = await _run(
            "docker",
            "run",
            "-d",
            "--security-opt=no-new-privileges",
            f"--memory={self.config.memory_limit}",
            "--network=none",
            self.image_tag,
            "sleep",
            "infinity",
        )
        if rc != 0:
            raise RuntimeError(f"docker run failed (rc={rc}): {stderr}")
        self._container_id = stdout.strip()

    async def stop(self) -> None:
        """Stop and remove the sandbox container."""
        if self._container_id is None:
            return
        await _run("docker", "rm", "-f", self._container_id)
        self._container_id = None

    # --- execution helpers ---

    async def exec(
        self, command: str, timeout: int | None = None
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox. Returns (exit_code, stdout, stderr)."""
        if self._container_id is None:
            raise RuntimeError("Container not running")
        return await _run(
            "docker",
            "exec",
            self._container_id,
            "bash",
            "-c",
            command,
            timeout=timeout,
        )

    async def copy_in(self, local_path: Path, container_path: str) -> None:
        """Copy a file from host into the container."""
        if self._container_id is None:
            raise RuntimeError("Container not running")
        rc, _, stderr = await _run(
            "docker",
            "cp",
            str(local_path),
            f"{self._container_id}:{container_path}",
        )
        if rc != 0:
            raise RuntimeError(f"docker cp in failed: {stderr}")

    async def copy_out(self, container_path: str, local_path: Path) -> None:
        """Copy a file from the container to the host."""
        if self._container_id is None:
            raise RuntimeError("Container not running")
        rc, _, stderr = await _run(
            "docker",
            "cp",
            f"{self._container_id}:{container_path}",
            str(local_path),
        )
        if rc != 0:
            raise RuntimeError(f"docker cp out failed: {stderr}")

    # --- high-level operations ---

    async def build_target(self) -> bool:
        """Run build.sh inside the container. Returns True on success."""
        env = _build_env(self.config)
        env_flags = " ".join(f'{k}="{v}"' for k, v in env.items())
        command = f"export {env_flags} && bash /src/build.sh"
        rc, _stdout, _stderr = await self.exec(
            command, timeout=self.config.timeout_seconds
        )
        return rc == 0

    async def run_fuzzer(
        self,
        fuzz_target: str,
        duration_seconds: int = 300,
        corpus_dir: str = "/out/corpus",
    ) -> tuple[int, str]:
        """Run the fuzzer for a fixed duration. Returns (exit_code, output_log).

        Note: For richer result collection (stats parsing, OOM/timeout detection,
        coverage artifact collection), prefer the higher-level
        ``FuzzingCampaign`` API in ``parser_security_eval.sandbox.campaign``.
        """
        engine = self.config.engine

        # Ensure crash and corpus dirs exist.
        await self.exec(f"mkdir -p /out/crashes {corpus_dir}")

        if engine == "libfuzzer":
            cmd = (
                f"timeout {duration_seconds} "
                f"/out/{fuzz_target} "
                f"{corpus_dir} "
                f"-artifact_prefix=/out/crashes/ "
                f"-max_total_time={duration_seconds} "
                f"-print_final_stats=1"
            )
        elif engine == "afl":
            cmd = (
                f"timeout {duration_seconds} "
                f"afl-fuzz -i {corpus_dir} -o /out/crashes "
                f"-- /out/{fuzz_target}"
            )
        elif engine == "honggfuzz":
            cmd = (
                f"timeout {duration_seconds} "
                f"honggfuzz -f {corpus_dir} -W /out/crashes "
                f"-- /out/{fuzz_target}"
            )
        else:
            raise ValueError(f"Unknown engine: {engine}")

        rc, stdout, stderr = await self.exec(cmd, timeout=duration_seconds + 30)
        combined = stdout + "\n" + stderr
        return rc, combined

    async def collect_crashes(self) -> list[Path]:
        """Collect crash artifacts from the container."""
        rc, stdout, _stderr = await self.exec("find /out/crashes -type f 2>/dev/null")
        if rc != 0 or not stdout.strip():
            return []

        crash_files: list[Path] = []
        local_dir = Path(tempfile.mkdtemp(prefix=f"crashes-{self.config.target_name}-"))
        for line in stdout.strip().splitlines():
            container_path = line.strip()
            if not container_path:
                continue
            filename = Path(container_path).name
            local_path = local_dir / filename
            await self.copy_out(container_path, local_path)
            crash_files.append(local_path)
        return crash_files

    # --- context manager ---

    async def __aenter__(self) -> "DockerSandbox":
        await self.build_image()
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()
