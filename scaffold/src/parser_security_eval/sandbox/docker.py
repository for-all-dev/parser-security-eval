"""Docker sandbox for building and running parser targets.

Each parser target runs in an isolated Docker container following
oss-fuzz conventions:
- /src/<project>  — parser source code
- /out/           — compiled fuzz targets, corpora, dictionaries
- /work/          — intermediate build artifacts
"""

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


class DockerSandbox:
    """Manages a Docker container for building and fuzzing a parser target."""

    def __init__(self, config: SandboxConfig) -> None:
        self.config = config
        self._container_id: str | None = None

    async def build_image(self) -> str:
        """Build the Docker image for this target.

        Returns the image ID.
        """
        raise NotImplementedError

    async def start(self) -> None:
        """Start the sandbox container."""
        raise NotImplementedError

    async def stop(self) -> None:
        """Stop and remove the sandbox container."""
        raise NotImplementedError

    async def exec(self, command: str, timeout: int | None = None) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Returns (exit_code, stdout, stderr).
        """
        raise NotImplementedError

    async def copy_in(self, local_path: Path, container_path: str) -> None:
        """Copy a file from host into the container."""
        raise NotImplementedError

    async def copy_out(self, container_path: str, local_path: Path) -> None:
        """Copy a file from the container to the host."""
        raise NotImplementedError

    async def build_target(self) -> bool:
        """Run build.sh inside the container. Returns True on success."""
        raise NotImplementedError

    async def run_fuzzer(
        self,
        fuzz_target: str,
        duration_seconds: int = 300,
        corpus_dir: str = "/out/corpus",
    ) -> tuple[int, str]:
        """Run the fuzzer for a fixed duration.

        Returns (exit_code, output_log).
        """
        raise NotImplementedError

    async def collect_crashes(self) -> list[Path]:
        """Collect crash artifacts from the container."""
        raise NotImplementedError

    async def __aenter__(self) -> "DockerSandbox":
        await self.build_image()
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()
