"""OSS-Fuzz-style build orchestration.

Handles building parser targets with different sanitizers and engines,
following oss-fuzz conventions for Dockerfile + build.sh.
"""

import os
import re
import textwrap
from pathlib import Path

import yaml


def generate_dockerfile(
    base_image: str = "gcr.io/oss-fuzz-base/base-builder",
    project_source: str = "",
    extra_packages: list[str] | None = None,
) -> str:
    """Generate a Dockerfile for building a parser target.

    Follows oss-fuzz base-builder conventions.

    Args:
        base_image: Base Docker image (typically gcr.io/oss-fuzz-base/base-builder).
        project_source: Git URL or local path to copy into the container.
        extra_packages: Additional apt packages to install.

    Returns:
        Dockerfile content as a string.
    """
    lines: list[str] = [f"FROM {base_image}"]

    if extra_packages:
        pkg_list = " ".join(extra_packages)
        lines.append(
            f"RUN apt-get update && apt-get install -y {pkg_list} && rm -rf /var/lib/apt/lists/*"
        )

    lines.append("WORKDIR /src")

    if project_source:
        if project_source.startswith(("http://", "https://", "git://")):
            lines.append(f"RUN git clone --depth 1 {project_source} project")
        else:
            lines.append(f"COPY {project_source} project/")

    lines.append("COPY build.sh $SRC/")

    return "\n".join(lines) + "\n"


def generate_build_sh(
    project_name: str,
    build_commands: list[str],
    fuzz_targets: list[str],
) -> str:
    """Generate a build.sh script for compiling fuzz targets.

    Follows oss-fuzz conventions:
    - Uses $CC, $CXX, $CFLAGS, $CXXFLAGS (set by base-builder per sanitizer)
    - Links against $LIB_FUZZING_ENGINE
    - Outputs binaries to $OUT/

    Args:
        project_name: Name of the project being built.
        build_commands: Shell commands to build the project (e.g. make, cmake).
        fuzz_targets: List of fuzz target source files (e.g. fuzz_parser.c).

    Returns:
        build.sh content as a string.
    """
    header = textwrap.dedent(f"""\
        #!/bin/bash -eu
        # Build script for {project_name}
        # Uses $CC, $CXX, $CFLAGS, $CXXFLAGS, $LIB_FUZZING_ENGINE, $OUT, $SRC, $WORK

        cd $SRC/project
    """)

    build_section = ""
    if build_commands:
        build_section = "\n".join(build_commands) + "\n"

    compile_lines: list[str] = []
    for target in fuzz_targets:
        target_path = Path(target)
        binary_name = target_path.stem
        ext = target_path.suffix

        if ext in (".c",):
            compiler = "$CC"
            flags = "$CFLAGS"
        else:
            compiler = "$CXX"
            flags = "$CXXFLAGS"

        compile_lines.append(
            f"{compiler} {flags} -o $OUT/{binary_name} {target} $LIB_FUZZING_ENGINE"
        )

    compile_section = "\n".join(compile_lines) + "\n" if compile_lines else ""

    return header + "\n" + build_section + "\n" + compile_section


def validate_target_layout(target_dir: Path) -> list[str]:
    """Validate a target directory has the required files and structure.

    Checks:
    - Dockerfile exists and first line starts with FROM
    - build.sh exists and has executable permission
    - metadata.yaml exists and is parseable YAML

    Returns list of validation errors (empty = valid).
    """
    errors: list[str] = []

    dockerfile_path = target_dir / "Dockerfile"
    if not dockerfile_path.exists():
        errors.append(f"Missing Dockerfile in {target_dir}")
    else:
        # Find the first non-comment, non-blank line (oss-fuzz Dockerfiles
        # typically start with a license comment block).
        first_instruction = ""
        for line in dockerfile_path.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                first_instruction = stripped
                break
        if not first_instruction.startswith("FROM "):
            errors.append(
                f"Dockerfile in {target_dir} must start with a FROM instruction"
            )

    build_sh_path = target_dir / "build.sh"
    if not build_sh_path.exists():
        errors.append(f"Missing build.sh in {target_dir}")
    else:
        if not os.access(build_sh_path, os.X_OK):
            errors.append(f"build.sh in {target_dir} is not executable")

    metadata_path = target_dir / "metadata.yaml"
    if not metadata_path.exists():
        errors.append(f"Missing metadata.yaml in {target_dir}")
    else:
        try:
            content = metadata_path.read_text()
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                errors.append(
                    f"metadata.yaml in {target_dir} must contain a YAML mapping"
                )
        except yaml.YAMLError as e:
            errors.append(f"metadata.yaml in {target_dir} is not valid YAML: {e}")

    # Check that all files referenced in COPY/ADD directives exist on disk.
    if dockerfile_path.exists():
        missing = find_missing_copy_targets(target_dir, dockerfile_path)
        for f in missing:
            errors.append(f"Missing COPY target: {f}")

    return errors


def find_missing_copy_targets(target_dir: Path, dockerfile_path: Path) -> list[str]:
    """Return filenames referenced by COPY/ADD in *dockerfile_path* that are missing.

    Only checks local context files (not URLs or absolute paths).  Skips
    ``$``-prefixed env-var references and known Docker build args.
    """
    missing: list[str] = []
    text = dockerfile_path.read_text()

    for line in text.splitlines():
        stripped = line.strip()
        # Skip comments and continuation lines (leading backslash handled by
        # the preceding line).
        if not stripped or stripped.startswith("#"):
            continue

        # Match COPY or ADD instructions.
        m = re.match(r"^(?:COPY|ADD)\s+(?:--\S+\s+)*(.+)", stripped, re.IGNORECASE)
        if not m:
            continue

        tokens = m.group(1).split()
        if len(tokens) < 2:
            continue

        # Last token is the destination; everything else is a source.
        sources = tokens[:-1]
        for src in sources:
            # Skip env-var references ($SRC, ${SRC}, etc.) and absolute paths.
            if src.startswith("$") or src.startswith("/") or src.startswith("--"):
                continue
            # Skip URLs (ADD can fetch remote URLs).
            if src.startswith("http://") or src.startswith("https://"):
                continue
            # Check if the source file/dir exists in the target directory.
            if not (target_dir / src).exists():
                missing.append(src)

    return missing
