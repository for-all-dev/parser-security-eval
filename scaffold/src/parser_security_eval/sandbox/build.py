"""OSS-Fuzz-style build orchestration.

Handles building parser targets with different sanitizers and engines,
following oss-fuzz conventions for Dockerfile + build.sh.
"""

from pathlib import Path


def generate_dockerfile(
    base_image: str = "gcr.io/oss-fuzz-base/base-builder",
    project_source: str = "",
    extra_packages: list[str] | None = None,
) -> str:
    """Generate a Dockerfile for building a parser target.

    Follows oss-fuzz base-builder conventions.
    """
    raise NotImplementedError


def generate_build_sh(
    project_name: str,
    build_commands: list[str],
    fuzz_targets: list[str],
) -> str:
    """Generate a build.sh script for compiling fuzz targets.

    Follows oss-fuzz conventions:
    - Uses $CC, $CXX, $CFLAGS, $CXXFLAGS (set by base-builder)
    - Uses $LIB_FUZZING_ENGINE
    - Outputs to $OUT/
    """
    raise NotImplementedError


def validate_target_layout(target_dir: Path) -> list[str]:
    """Validate a target directory has the required files.

    Required:
    - Dockerfile
    - build.sh
    - metadata.yaml

    Returns list of validation errors (empty = valid).
    """
    errors = []
    if not (target_dir / "Dockerfile").exists():
        errors.append(f"Missing Dockerfile in {target_dir}")
    if not (target_dir / "build.sh").exists():
        errors.append(f"Missing build.sh in {target_dir}")
    if not (target_dir / "metadata.yaml").exists():
        errors.append(f"Missing metadata.yaml in {target_dir}")
    return errors
