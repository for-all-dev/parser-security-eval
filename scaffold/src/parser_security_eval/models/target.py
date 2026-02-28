"""Data models for parser targets."""

from pathlib import Path

from pydantic import BaseModel


class ParserTarget(BaseModel):
    """A parser target that can be built and fuzzed."""

    name: str  # e.g. "libpng"
    format_type: str  # e.g. "binary-image", "text-markup", "protocol"
    language: str  # e.g. "c", "cpp"
    ossfuzz_project: str | None = None  # oss-fuzz project name if it exists

    # Paths relative to targets/ directory
    dockerfile_path: Path
    build_sh_path: Path
    corpus_dir: Path | None = None
    dictionary_path: Path | None = None

    def target_dir(self, targets_root: Path) -> Path:
        """Absolute path to this target's directory."""
        return targets_root / self.name
