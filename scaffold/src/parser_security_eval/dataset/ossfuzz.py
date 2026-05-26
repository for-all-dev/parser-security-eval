"""Ingest vulnerability data from the oss-fuzz bug tracker.

Public oss-fuzz bugs (after 90-day disclosure) are fetched via the OSV
database at https://osv.dev which provides structured access to oss-fuzz
vulnerabilities through a JSON API.

Also integrates with oss-fuzz project definitions for target metadata.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any

from parser_security_eval.models import ParserTarget, VulnerabilityRecord
from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
)

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"

# Parser-related oss-fuzz projects (curated allowlist).
# These are projects where the primary workload is parsing untrusted input.
PARSER_PROJECTS: set[str] = {
    "arrow-java",
    "blosc2",
    "c-blosc2",
    "cjson",
    "double-conversion",
    "expat",
    "ffmpeg",
    "freetype2",
    "giflib",
    "graphicsmagick",
    "harfbuzz",
    "imagemagick",
    "jansson",
    "jsoncpp",
    "libarchive",
    "libavc",
    "libhevc",
    "libjpeg-turbo",
    "libpcap",
    "libpng",
    "libraw",
    "libtiff",
    "libvpx",
    "libwebp",
    "libxml2",
    "libxslt",
    "libyaml",
    "lz4",
    "minizip",
    "mupdf",
    "openjpeg",
    "openssl",
    "pcre2",
    "poppler",
    "protobuf",
    "rapidjson",
    "re2",
    "simdjson",
    "sqlite3",
    "tinyxml2",
    "woff2",
    "xz",
    "zlib",
    "zstd",
}

# Keywords that indicate a project is parser-related.
_PARSER_KEYWORDS: list[str] = [
    "parse",
    "parser",
    "codec",
    "decode",
    "deserializ",
    "format",
    "image",
    "json",
    "xml",
    "yaml",
    "toml",
    "csv",
    "protobuf",
    "font",
    "compress",
    "archive",
    "zip",
    "tar",
    "pdf",
    "html",
    "http",
    "tls",
    "ssl",
    "cert",
    "asn1",
    "ber",
    "der",
    "pem",
]

# Maps crash-type strings from OSV/oss-fuzz to severity heuristics.
_CRASH_TYPE_SEVERITY: dict[str, Severity] = {
    "heap-use-after-free": Severity.HIGH,
    "heap-buffer-overflow": Severity.HIGH,
    "heap-double-free": Severity.HIGH,
    "stack-buffer-overflow": Severity.HIGH,
    "stack-buffer-underflow": Severity.HIGH,
    "global-buffer-overflow": Severity.MEDIUM,
    "use-after-poison": Severity.MEDIUM,
    "null-dereference": Severity.LOW,
    "integer-overflow": Severity.MEDIUM,
    "undefined-shift": Severity.LOW,
    "out-of-memory": Severity.LOW,
    "timeout": Severity.LOW,
}

_SANITIZER_MAP: dict[str, Sanitizer] = {
    "address": Sanitizer.ADDRESS,
    "asan": Sanitizer.ADDRESS,
    "addresssanitizer": Sanitizer.ADDRESS,
    "memory": Sanitizer.MEMORY,
    "msan": Sanitizer.MEMORY,
    "memorysanitizer": Sanitizer.MEMORY,
    "undefined": Sanitizer.UNDEFINED,
    "ubsan": Sanitizer.UNDEFINED,
    "undefinedbehaviorsanitizer": Sanitizer.UNDEFINED,
}

# Default format_type when we cannot determine from project metadata.
_DEFAULT_FORMAT_TYPE = "unknown"

OSSFUZZ_REPO_URL = "https://github.com/google/oss-fuzz.git"


def clone_ossfuzz_repo(cache_dir: Path) -> Path:
    """Clone or update the google/oss-fuzz repository.

    Performs a shallow clone into ``cache_dir/oss-fuzz`` (or ``git pull
    --ff-only`` if it already exists).  Returns the path to the repo root.
    """
    repo_dir = cache_dir / "oss-fuzz"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if (repo_dir / ".git").is_dir():
        logger.info("Updating existing oss-fuzz clone at %s", repo_dir)
        subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only"],
            check=True,
            capture_output=True,
        )
    else:
        logger.info("Cloning oss-fuzz repo into %s (shallow)", repo_dir)
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                OSSFUZZ_REPO_URL,
                str(repo_dir),
            ],
            check=True,
            capture_output=True,
        )
        # Sparse-checkout to only materialise the projects/ directory.
        subprocess.run(
            [
                "git",
                "-C",
                str(repo_dir),
                "sparse-checkout",
                "set",
                "--skip-checks",
                "projects",
            ],
            check=True,
            capture_output=True,
        )

    projects_dir = repo_dir / "projects"
    if not projects_dir.is_dir():
        msg = f"projects/ directory not found at {projects_dir}"
        raise FileNotFoundError(msg)
    return repo_dir


@dataclass
class BootstrapResult:
    """Summary of a bulk target bootstrap operation."""

    succeeded: list[str] = dataclass_field(default_factory=list)
    skipped: list[str] = dataclass_field(default_factory=list)
    failed: dict[str, str] = dataclass_field(default_factory=dict)

    @property
    def summary(self) -> str:
        lines = [
            f"Bootstrap complete: {len(self.succeeded)} succeeded, "
            f"{len(self.skipped)} skipped, {len(self.failed)} failed"
        ]
        if self.succeeded:
            lines.append(f"  Succeeded: {', '.join(self.succeeded)}")
        if self.skipped:
            lines.append(f"  Skipped (already exist): {', '.join(self.skipped)}")
        if self.failed:
            lines.append("  Failed:")
            for name, err in self.failed.items():
                lines.append(f"    {name}: {err}")
        return "\n".join(lines)


def bootstrap_targets(
    projects: list[str],
    ossfuzz_repo: Path,
    targets_dir: Path,
    *,
    force: bool = False,
) -> BootstrapResult:
    """Import multiple oss-fuzz projects into ``targets_dir``.

    Parameters
    ----------
    projects:
        List of oss-fuzz project names to import.
    ossfuzz_repo:
        Path to the cloned ``google/oss-fuzz`` repository.
    targets_dir:
        Destination directory (e.g. ``targets/``).
    force:
        If *True*, overwrite existing target directories.
    """
    result = BootstrapResult()

    for project in sorted(set(projects)):
        dst = targets_dir / project
        if dst.exists() and not force:
            result.skipped.append(project)
            continue

        try:
            import_ossfuzz_target(project, ossfuzz_repo, targets_dir)
            # Ensure build.sh is executable.
            build_sh = dst / "build.sh"
            if build_sh.exists():
                build_sh.chmod(build_sh.stat().st_mode | 0o111)
            result.succeeded.append(project)
        except Exception as exc:
            logger.exception("Failed to import %s", project)
            # Clean up partial directory so it isn't wrongly skipped on retry.
            if dst.exists():
                shutil.rmtree(dst)
            result.failed[project] = str(exc)

    return result


def _osv_query(project: str, page_token: str | None = None) -> dict[str, Any]:
    """Execute a single OSV API query for an oss-fuzz project."""
    payload: dict[str, Any] = {
        "package": {"name": project, "ecosystem": "OSS-Fuzz"},
    }
    if page_token is not None:
        payload["page_token"] = page_token

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        OSV_API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def fetch_ossfuzz_bugs(
    project: str,
    cache_dir: Path,
) -> list[dict[str, Any]]:
    """Fetch public oss-fuzz bug reports for a project via the OSV API.

    Results are cached as JSON in *cache_dir* so repeated calls are fast.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"osv_{project}.json"

    if cache_file.exists():
        logger.info("Using cached OSV data for %s", project)
        return json.loads(cache_file.read_text())

    logger.info("Fetching OSV data for project %s", project)
    all_vulns: list[dict[str, Any]] = []
    page_token: str | None = None

    while True:
        result = _osv_query(project, page_token)
        vulns = result.get("vulns", [])
        all_vulns.extend(vulns)

        page_token = result.get("next_page_token")
        if not page_token:
            break

    cache_file.write_text(json.dumps(all_vulns, indent=2))
    logger.info("Fetched %d bugs for %s", len(all_vulns), project)
    return all_vulns


def _extract_crash_type(bug: dict[str, Any]) -> str:
    """Best-effort extraction of crash type from an OSV record."""
    # OSV oss-fuzz entries often store crash type in database_specific
    db_specific = bug.get("database_specific", {})
    if crash_type := db_specific.get("crash_type"):
        return crash_type.lower()

    # Fall back to summary text
    summary = bug.get("summary", "").lower()
    for known in _CRASH_TYPE_SEVERITY:
        if known in summary:
            return known
    return summary or "unknown"


def _extract_sanitizer(bug: dict[str, Any]) -> Sanitizer:
    """Best-effort extraction of sanitizer from an OSV record."""
    db_specific = bug.get("database_specific", {})

    for field in ("sanitizer", "detector"):
        raw = str(db_specific.get(field, "")).lower().strip()
        if raw in _SANITIZER_MAP:
            return _SANITIZER_MAP[raw]

    # Check the summary
    summary = bug.get("summary", "").lower()
    for key, san in _SANITIZER_MAP.items():
        if key in summary:
            return san

    return Sanitizer.ADDRESS  # default


def _extract_severity(bug: dict[str, Any], crash_type: str) -> Severity:
    """Derive severity from CVSS in the OSV record, or from crash type."""
    for sev_entry in bug.get("severity", []):
        score_str = sev_entry.get("score", "")
        try:
            score = float(score_str)
        except ValueError, TypeError:
            continue
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    return _CRASH_TYPE_SEVERITY.get(crash_type, Severity.MEDIUM)


# Regex matching a source-file name in a crash-state line.
# Matches bare filenames like "parser.c", "compress.cc", "xml.c", "api.c".
_CRASH_STATE_FILE_RE = re.compile(
    r"^\s*(\w[\w.\-/]*\.(c|cc|cpp|cxx|h|hpp))\s*$",
    re.IGNORECASE,
)

# Regex to extract the crash-state block from OSV details text.
_CRASH_STATE_BLOCK_RE = re.compile(
    r"Crash state:\s*\n(.*?)(?:```|\Z)",
    re.DOTALL,
)


def _extract_affected_file(bug: dict[str, Any]) -> str:
    """Extract the primarily affected source file from an OSV record.

    Strategies attempted in order:

    1. ``database_specific.affected_file`` — explicit field set by ARVO ingest.
    2. Crash-state block in ``details`` — OSV oss-fuzz records embed the
       sanitiser crash state as a fenced code block.  The last line of the
       crash state is sometimes a bare filename (e.g. ``compress.cc``,
       ``xml.c``).  We scan every line for a source-file pattern.
    3. GitHub ``/blob/`` or ``/tree/`` reference URLs — some records link
       directly to the affected file on GitHub.
    4. ``affected[].package.name`` — always present; better context than the
       literal string ``"unknown"``.
    """
    # Strategy 1: explicit field (ARVO records, or future enriched OSV records).
    db_specific = bug.get("database_specific", {})
    if af := db_specific.get("affected_file"):
        return af

    # Strategy 2: scan crash-state lines in the ``details`` fenced block.
    details = bug.get("details", "")
    if details:
        m = _CRASH_STATE_BLOCK_RE.search(details)
        if m:
            for line in m.group(1).splitlines():
                fm = _CRASH_STATE_FILE_RE.match(line)
                if fm:
                    # Return just the basename so callers get a stable short name.
                    return Path(fm.group(1)).name

    # Strategy 3: GitHub blob/tree reference URL.
    for ref in bug.get("references", []):
        url = ref.get("url", "")
        if "/blob/" in url or "/tree/" in url:
            # e.g. https://github.com/foo/bar/blob/main/src/parser.c
            parts = url.split("/blob/")
            if len(parts) == 2:
                return parts[1].split("/", 1)[-1] if "/" in parts[1] else parts[1]

    # Strategy 4: package name from affected block (always more informative than
    # "unknown" since it tells the reviewer which library is involved).
    for affected_entry in bug.get("affected", []):
        pkg_name = affected_entry.get("package", {}).get("name", "")
        if pkg_name:
            return pkg_name

    return "unknown"


def _estimate_difficulty(bug: dict[str, Any]) -> Difficulty:
    """Heuristic difficulty based on fix complexity signals in the OSV record."""
    db_specific = bug.get("database_specific", {})
    lines = db_specific.get("lines_changed_in_fix")
    if lines is not None:
        try:
            n = int(lines)
        except ValueError, TypeError:
            n = 0
        if n <= 5:
            return Difficulty.EASY
        if n <= 30:
            return Difficulty.MEDIUM
        return Difficulty.HARD
    return Difficulty.MEDIUM


def parse_ossfuzz_bug(bug: dict[str, Any], project: str) -> VulnerabilityRecord | None:
    """Parse an OSV oss-fuzz bug into our data model.

    Returns ``None`` if the record lacks enough information to be useful.
    """
    bug_id = bug.get("id", "")
    if not bug_id:
        return None

    crash_type = _extract_crash_type(bug)
    sanitizer = _extract_sanitizer(bug)
    severity = _extract_severity(bug, crash_type)
    affected_file = _extract_affected_file(bug)
    difficulty = _estimate_difficulty(bug)

    db_specific = bug.get("database_specific", {})

    # Extract CWE aliases
    cwe: str | None = None
    for alias in bug.get("aliases", []):
        if alias.upper().startswith("CWE-"):
            cwe = alias.upper()
            break

    return VulnerabilityRecord(
        id=bug_id,
        target=project,
        cwe=cwe,
        severity=severity,
        difficulty=difficulty,
        crash_type=crash_type,
        sanitizer=sanitizer,
        affected_file=affected_file,
        affected_function=db_specific.get("affected_function"),
        lines_changed_in_fix=db_specific.get("lines_changed_in_fix"),
        root_cause=db_specific.get("root_cause"),
        vulnerable_source_ref=db_specific.get("vulnerable_source_ref"),
    )


def _read_project_yaml(project_yaml: Path) -> dict[str, Any]:
    """Read an oss-fuzz project.yaml file."""
    # Use a simple YAML subset parser to avoid requiring PyYAML.
    # oss-fuzz project.yaml files are simple key: value or key: [list] format.
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[str] | None = None
    for line in project_yaml.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # List continuation (indented "- item")
        if (
            stripped.startswith("- ")
            and current_key is not None
            and current_list is not None
        ):
            current_list.append(stripped[2:].strip().strip("'\""))
            result[current_key] = current_list
            continue
        # New key
        if ":" in stripped:
            if current_list is not None and current_key is not None:
                current_list = None
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().strip("'\"")
            if value:
                # Inline list like [a, b, c]
                if value.startswith("[") and value.endswith("]"):
                    items = [v.strip().strip("'\"") for v in value[1:-1].split(",")]
                    result[key] = items
                    current_key = key
                    current_list = None
                else:
                    result[key] = value
                    current_key = key
                    current_list = None
            else:
                current_key = key
                current_list = []
    return result


def _detect_format_type(project_name: str) -> str:
    """Simple heuristic for format_type based on project name."""
    name = project_name.lower()
    if any(
        kw in name
        for kw in (
            "png",
            "jpeg",
            "jpg",
            "tiff",
            "gif",
            "webp",
            "image",
            "raw",
            "openjpeg",
        )
    ):
        return "binary-image"
    if any(kw in name for kw in ("xml", "html", "xslt")):
        return "text-markup"
    if any(kw in name for kw in ("json", "yaml", "toml", "csv")):
        return "text-data"
    if any(kw in name for kw in ("proto", "flatbuf", "avro", "thrift")):
        return "binary-serialization"
    if any(kw in name for kw in ("pdf", "mupdf", "poppler")):
        return "document"
    if any(kw in name for kw in ("ssl", "tls", "cert", "openssl")):
        return "protocol"
    if any(
        kw in name
        for kw in (
            "zip",
            "lz4",
            "zstd",
            "xz",
            "zlib",
            "compress",
            "archive",
            "tar",
            "blosc",
        )
    ):
        return "compression"
    if any(kw in name for kw in ("font", "freetype", "harfbuzz", "woff")):
        return "font"
    if any(kw in name for kw in ("pcre", "re2", "regex")):
        return "regex"
    if any(kw in name for kw in ("ffmpeg", "libav", "vpx", "hevc")):
        return "media"
    if any(kw in name for kw in ("sqlite", "sql")):
        return "database"
    if any(kw in name for kw in ("pcap",)):
        return "network-capture"
    return _DEFAULT_FORMAT_TYPE


def _write_metadata_yaml(path: Path, data: dict[str, Any]) -> None:
    """Write a simple YAML file without requiring PyYAML."""
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, list):
            lines.append(f"{key}:")
            for item in value:
                lines.append(f"  - {item}")
        else:
            lines.append(f"{key}: {value}")
    path.write_text("\n".join(lines) + "\n")


# Patterns matching Dockerfile content that creates $SRC/build.sh at image build time.
# Covers: cp/mv to $SRC/build.sh, cp/mv of build.sh to $SRC/, COPY build.sh $SRC/.
# Also handles multiline RUN with `&&` continuation.
_DOCKERFILE_BUILD_SH_RE = re.compile(
    r"(?:"
    r"(?:cp|mv)\s+.*\$SRC/build\.sh"  # cp ... $SRC/build.sh
    r"|(?:cp|mv)\s+\S*build\.sh\s+\$SRC/"  # cp .../build.sh $SRC/
    r"|COPY\s+.*build\.sh\s+\$SRC/"  # COPY build.sh $SRC/
    r")",
    re.IGNORECASE,
)


def _dockerfile_creates_build_sh(dockerfile: Path) -> bool:
    """Check if a Dockerfile contains a command that creates $SRC/build.sh."""
    text = dockerfile.read_text()
    return bool(_DOCKERFILE_BUILD_SH_RE.search(text))


def _write_stub_build_sh(path: Path, project: str) -> None:
    """Write a stub build.sh for projects whose build logic is in the Dockerfile."""
    path.write_text(
        "#!/bin/bash\n"
        f"# Stub for {project}: build.sh is created inside the Docker image\n"
        "# by the Dockerfile (e.g. copied from the cloned source repo).\n"
        "# This file exists so the target directory passes layout validation.\n"
        "# The actual build logic runs during `docker build`.\n"
        'echo "Error: this is a stub build.sh; the real build script is'
        ' generated by the Dockerfile at image build time." >&2\n'
        "exit 1\n"
    )
    path.chmod(path.stat().st_mode | 0o111)


def import_ossfuzz_target(
    project: str,
    ossfuzz_repo: Path,
    targets_dir: Path,
) -> ParserTarget:
    """Import an oss-fuzz project definition as a ParserTarget.

    Copies Dockerfile, build.sh, corpus, and dictionary from the oss-fuzz
    repo checkout into our ``targets/<project>/`` directory layout, and
    converts ``project.yaml`` to ``metadata.yaml``.
    """
    src_dir = ossfuzz_repo / "projects" / project
    if not src_dir.is_dir():
        msg = f"oss-fuzz project directory not found: {src_dir}"
        raise FileNotFoundError(msg)

    dst_dir = targets_dir / project
    dst_dir.mkdir(parents=True, exist_ok=True)

    # Copy Dockerfile
    dockerfile_src = src_dir / "Dockerfile"
    if dockerfile_src.exists():
        shutil.copy2(dockerfile_src, dst_dir / "Dockerfile")
    else:
        msg = f"Dockerfile not found in {src_dir}"
        raise FileNotFoundError(msg)

    # Copy build.sh (or generate stub if Dockerfile creates it at build time)
    build_sh_src = src_dir / "build.sh"
    build_sh_source = "static"
    if build_sh_src.exists():
        shutil.copy2(build_sh_src, dst_dir / "build.sh")
    elif _dockerfile_creates_build_sh(dockerfile_src):
        build_sh_source = "dockerfile"
        _write_stub_build_sh(dst_dir / "build.sh", project)
    else:
        msg = f"build.sh not found in {src_dir}"
        raise FileNotFoundError(msg)

    # Parse project.yaml for metadata
    project_yaml_path = src_dir / "project.yaml"
    project_meta: dict[str, Any] = {}
    if project_yaml_path.exists():
        project_meta = _read_project_yaml(project_yaml_path)

    language = project_meta.get("language", "c")
    sanitizers = project_meta.get("sanitizers", ["address"])
    engines = project_meta.get("fuzzing_engines", ["libfuzzer"])
    format_type = _detect_format_type(project)

    # Copy corpus directory if present
    corpus_dir: Path | None = None
    corpus_src = src_dir / "corpus"
    if corpus_src.is_dir():
        corpus_dst = dst_dir / "corpus"
        if corpus_dst.exists():
            shutil.rmtree(corpus_dst)
        shutil.copytree(corpus_src, corpus_dst)
        corpus_dir = Path("corpus")

    # Copy dictionary if present
    dictionary_path: Path | None = None
    for dict_candidate in sorted(src_dir.glob("*.dict")):
        shutil.copy2(dict_candidate, dst_dir / dict_candidate.name)
        dictionary_path = Path(dict_candidate.name)
        break  # take the first one

    # Write our metadata.yaml (after corpus/dict so we can record their presence)
    metadata: dict[str, Any] = {
        "name": project,
        "language": language,
        "sanitizers": sanitizers if isinstance(sanitizers, list) else [sanitizers],
        "engines": engines if isinstance(engines, list) else [engines],
        "format_type": format_type,
        "ossfuzz_project": project,
        "has_corpus": corpus_dir is not None,
        "has_dictionary": dictionary_path is not None,
        "build_sh_source": build_sh_source,
    }
    _write_metadata_yaml(dst_dir / "metadata.yaml", metadata)

    return ParserTarget(
        name=project,
        format_type=format_type,
        language=language,
        ossfuzz_project=project,
        dockerfile_path=Path("Dockerfile"),
        build_sh_path=Path("build.sh"),
        corpus_dir=corpus_dir,
        dictionary_path=dictionary_path,
    )


def _is_parser_project(project_name: str) -> bool:
    """Heuristic: does this oss-fuzz project involve parsing?

    Uses the curated allowlist plus keyword matching on the project name.
    """
    if project_name in PARSER_PROJECTS:
        return True
    name_lower = project_name.lower()
    return any(kw in name_lower for kw in _PARSER_KEYWORDS)


def list_parser_projects(ossfuzz_repo: Path) -> list[str]:
    """List oss-fuzz projects that are parser-related.

    Scans the ``projects/`` directory in the oss-fuzz repository checkout
    and returns project names that match our parser heuristic.
    """
    projects_dir = ossfuzz_repo / "projects"
    if not projects_dir.is_dir():
        msg = f"oss-fuzz projects directory not found: {projects_dir}"
        raise FileNotFoundError(msg)

    results: list[str] = []
    for entry in sorted(projects_dir.iterdir()):
        if entry.is_dir() and _is_parser_project(entry.name):
            results.append(entry.name)
    return results
