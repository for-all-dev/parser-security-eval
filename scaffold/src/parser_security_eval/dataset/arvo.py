"""Ingest vulnerability data from the ARVO dataset.

ARVO: Atlas of Reproducible Vulnerabilities for Open Source Software
https://github.com/n132/ARVO

Contains 5,001 patches over 5,651 vulnerabilities with triggering inputs,
canonical patches, and reproducible Docker builds.

The primary data source is the ``metadata.jsonl`` file in the ARVO repo
(``arvo/NewTracker/metadata.jsonl``), where each line is a JSON object
with fields like ``project``, ``crash_type``, ``severity``, ``sanitizer``,
``localId``, ``fuzz_target``, ``reproducer``, etc.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from parser_security_eval.log import get_log
from parser_security_eval.models.vulnerability import (
    Difficulty,
    Sanitizer,
    Severity,
    VulnerabilityRecord,
)

log = get_log(__name__)

ARVO_REPO_URL = "https://github.com/n132/ARVO.git"
METADATA_REL_PATH = Path("arvo/NewTracker/metadata.jsonl")

# Curated allowlist of oss-fuzz projects that are primarily parsers or
# format-processing libraries.  This is intentionally broad — the goal is
# to capture anything whose *fuzzing* exercises parsing logic.
_PARSER_PROJECT_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Image formats
        "libpng",
        "libjpeg-turbo",
        "libwebp",
        "libtiff",
        "libavif",
        "libheif",
        "openjpeg",
        "giflib",
        "jbig2dec",
        "libraw",
        "imlib2",
        # Audio / video containers & codecs
        "ffmpeg",
        "libvpx",
        "libflac",
        "vorbis",
        "opus",
        "mp4parse-rust",
        "libmpeg2",
        "libtheora",
        "libaom",
        "dav1d",
        # Document / markup
        "libxml2",
        "libxslt",
        "expat",
        "mupdf",
        "poppler",
        "xpdf",
        "ghostscript",
        # Fonts
        "freetype2",
        "harfbuzz",
        "woff2",
        "fonttools",
        # Network protocols / formats
        "curl",
        "openssl",
        "boringssl",
        "mbedtls",
        "gnutls",
        "libressl",
        "wolfssl",
        "nss",
        "wireshark",
        "libpcap",
        "grpc-go",
        "grpc-swift",
        "nghttp2",
        "httpd",
        # Data serialization
        "protobuf",
        "flatbuffers",
        "capnproto",
        "msgpack-c",
        "rapidjson",
        "cjson",
        "jansson",
        "json-c",
        "simdjson",
        "yyjson",
        "jsoncpp",
        "ujson",
        # Archive / compression
        "zlib",
        "bzip2",
        "xz",
        "zstd",
        "lz4",
        "brotli",
        "libarchive",
        "libzip",
        "snappy",
        "minizip",
        # Text / regex
        "icu",
        "re2",
        "pcre2",
        "oniguruma",
        "utf8proc",
        # Database / query
        "sqlite3",
        "cfl",
        # Configuration / scripting parsers
        "libucl",
        "libyaml",
        "libtoml",
        "libconfig",
        "lua",
        "mujs",
        "duktape",
        "quickjs",
        # PDF / Postscript
        "pdfium",
        # Email / MIME
        "libetpan",
        # Misc parsers
        "file",
        "binutils",
        "elfutils",
        "libelf",
        "libdwarf",
        "unrar",
        "ntp",
        "lldpd",
        "open62541",
        "wabt",
        "wasm3",
        "bloaty",
        "c-ares",
        "samba",
        # Crypto / ASN.1
        "libksba",
        "asn1c",
        "libtasn1",
        "libgcrypt",
        "gnupg",
    }
)

# Keywords that indicate a project involves parsing, even if not allowlisted.
_PARSER_KEYWORDS: tuple[str, ...] = (
    "parse",
    "parser",
    "codec",
    "decode",
    "deserializ",
    "format",
    "read",
    "xml",
    "json",
    "yaml",
    "toml",
    "csv",
    "http",
    "dns",
    "tls",
    "ssl",
    "proto",
    "font",
    "image",
    "audio",
    "video",
    "compress",
    "archive",
    "zip",
    "tar",
    "png",
    "jpeg",
    "gif",
    "wasm",
    "elf",
    "pdf",
    "regex",
    "utf",
    "unicode",
    "asn1",
    "mime",
)


def is_parser_project(project_name: str) -> bool:
    """Heuristic: does this oss-fuzz project involve parsing?

    Uses a curated allowlist of known parser projects plus keyword matching.
    """
    lower = project_name.lower()
    if lower in _PARSER_PROJECT_ALLOWLIST:
        return True
    return any(kw in lower for kw in _PARSER_KEYWORDS)


# ---------------------------------------------------------------------------
# Severity / difficulty / sanitizer mapping helpers
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_SANITIZER_MAP: dict[str, Sanitizer] = {
    "address": Sanitizer.ADDRESS,
    "undefined": Sanitizer.UNDEFINED,
    "memory": Sanitizer.MEMORY,
}


def _map_severity(raw: str) -> Severity:
    """Map an ARVO severity string to our enum, defaulting to MEDIUM."""
    return _SEVERITY_MAP.get(raw.strip().lower(), Severity.MEDIUM)


def _map_sanitizer(raw: str) -> Sanitizer:
    """Map an ARVO sanitizer string to our enum, defaulting to ADDRESS."""
    return _SANITIZER_MAP.get(raw.strip().lower(), Sanitizer.ADDRESS)


def _estimate_difficulty(crash_type: str) -> Difficulty:
    """Rough heuristic to estimate fix difficulty from crash type.

    Stack-buffer-overflow and null-dereference are generally simpler to fix.
    Use-after-free or type-confusion bugs tend to be harder.
    """
    lower = crash_type.lower()
    easy_patterns = (
        "null-dereference",
        "stack-buffer-overflow",
        "integer-overflow",
        "divide-by-zero",
        "assertion",
        "timeout",
        "oom",
        "out-of-memory",
    )
    hard_patterns = (
        "use-after-free",
        "double-free",
        "type-confusion",
        "use-after-poison",
        "wild-addr",
    )
    if any(p in lower for p in easy_patterns):
        return Difficulty.EASY
    if any(p in lower for p in hard_patterns):
        return Difficulty.HARD
    return Difficulty.MEDIUM


def _extract_affected_file(job_type: str, fuzz_target: str | None) -> str:
    """Best-effort extraction of an affected file from ARVO metadata.

    ARVO entries don't carry a source filename directly; we derive a
    representative string from the job_type or fuzz_target fields.
    """
    if fuzz_target:
        return fuzz_target
    # job_type looks like "libfuzzer_asan_freetype2" — take the project part
    parts = job_type.split("_")
    if len(parts) >= 3:
        return "_".join(parts[2:])
    return job_type


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def fetch_arvo_index(cache_dir: Path) -> Path:
    """Download or update the ARVO dataset index.

    Performs a shallow clone (or pull) of the ARVO repository into
    ``cache_dir/ARVO`` and returns the path to the ``metadata.jsonl`` file.
    """
    repo_dir = cache_dir / "ARVO"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if (repo_dir / ".git").is_dir():
        log.info("Updating existing ARVO clone at %s", repo_dir)
        subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only"],
            check=True,
            capture_output=True,
        )
    else:
        log.info("Cloning ARVO repo into %s (shallow)", repo_dir)
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                ARVO_REPO_URL,
                str(repo_dir),
            ],
            check=True,
            capture_output=True,
        )
        # Only check out the metadata we need.
        subprocess.run(
            [
                "git",
                "-C",
                str(repo_dir),
                "sparse-checkout",
                "set",
                "--skip-checks",
                str(METADATA_REL_PATH),
            ],
            check=True,
            capture_output=True,
        )

    metadata_path = repo_dir / METADATA_REL_PATH
    if not metadata_path.exists():
        msg = f"metadata.jsonl not found at {metadata_path}"
        raise FileNotFoundError(msg)
    return metadata_path


def parse_arvo_entry(entry: dict) -> VulnerabilityRecord | None:
    """Parse a single ARVO entry into our data model.

    Returns ``None`` if the entry is not a parser-related vulnerability.
    """
    project = entry.get("project", "")
    if not is_parser_project(project):
        return None

    local_id = entry.get("localId")
    if local_id is None:
        return None

    crash_type = entry.get("crash_type", "unknown")
    severity_raw = entry.get("severity", "medium")
    sanitizer_raw = entry.get("sanitizer", "address")
    job_type = entry.get("job_type", "")
    fuzz_target = entry.get("fuzz_target")

    return VulnerabilityRecord(
        id=f"ARVO-{local_id}",
        target=project,
        severity=_map_severity(severity_raw),
        difficulty=_estimate_difficulty(crash_type),
        crash_type=crash_type,
        sanitizer=_map_sanitizer(sanitizer_raw),
        affected_file=_extract_affected_file(job_type, fuzz_target),
        affected_function=None,
        tags=_build_tags(entry),
    )


def _parse_arvo_entry_unchecked(entry: dict) -> VulnerabilityRecord | None:
    """Parse an ARVO entry without checking ``is_parser_project``.

    Used for Category 3 local_id-based inclusion where the project may not
    pass the parser heuristic but individual samples have been reviewed.
    """
    local_id = entry.get("localId")
    if local_id is None:
        return None

    project = entry.get("project", "")
    crash_type = entry.get("crash_type", "unknown")
    severity_raw = entry.get("severity", "medium")
    sanitizer_raw = entry.get("sanitizer", "address")
    job_type = entry.get("job_type", "")
    fuzz_target = entry.get("fuzz_target")

    return VulnerabilityRecord(
        id=f"ARVO-{local_id}",
        target=project,
        severity=_map_severity(severity_raw),
        difficulty=_estimate_difficulty(crash_type),
        crash_type=crash_type,
        sanitizer=_map_sanitizer(sanitizer_raw),
        affected_file=_extract_affected_file(job_type, fuzz_target),
        affected_function=None,
        tags=_build_tags(entry),
    )


def _build_tags(entry: dict) -> list[str]:
    """Derive useful tags from an ARVO entry."""
    tags: list[str] = []
    crash_type = entry.get("crash_type", "").lower()
    if "overflow" in crash_type:
        tags.append("overflow")
    if "use-after" in crash_type:
        tags.append("use-after-free")
    if "null" in crash_type:
        tags.append("null-deref")
    if "leak" in crash_type:
        tags.append("leak")
    platform = entry.get("platform", "")
    if platform:
        tags.append(f"platform:{platform}")
    return tags


def ingest_arvo(
    cache_dir: Path,
    output_dir: Path,
    limit: int | None = None,
    targets: set[str] | None = None,
    local_ids: set[int] | None = None,
) -> list[VulnerabilityRecord]:
    """Ingest ARVO dataset, filter for parser vulns, write to output_dir.

    Parameters
    ----------
    targets:
        If provided, only ingest records whose ``target`` (lowercased)
        is in this set.  This avoids creating thousands of artifact stub
        directories for projects that will be filtered out downstream.
    local_ids:
        If provided, records whose ARVO ``localId`` is in this set are
        also included (union with *targets*).  This enables Category 3
        per-sample inclusion.

    Steps:
    1. Clone/update the ARVO repo and locate ``metadata.jsonl``.
    2. Stream entries, filter for parser-related projects (and *targets*/*local_ids*).
    3. Convert each to a ``VulnerabilityRecord``.
    4. Write ``records.jsonl``, ``crash_report.txt``, and ``reference_patch.diff``
       stubs per vulnerability into *output_dir*.
    5. Return the list of records.
    """
    metadata_path = fetch_arvo_index(cache_dir)

    records: list[VulnerabilityRecord] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    with metadata_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)

            # Check if this record is included via local_ids (Category 3).
            # If so, bypass the normal is_parser_project filter.
            entry_local_id = entry.get("localId")
            included_by_local_id = (
                local_ids is not None
                and entry_local_id is not None
                and entry_local_id in local_ids
            )

            if included_by_local_id:
                # Force-parse even if is_parser_project would reject it
                record = _parse_arvo_entry_unchecked(entry)
            else:
                record = parse_arvo_entry(entry)

            if record is None:
                continue

            # Skip records not matching requested targets (unless included by local_id)
            if not included_by_local_id:
                if targets is not None and record.target.lower() not in targets:
                    continue

            # Write per-vulnerability artifact stubs
            vuln_dir = output_dir / record.id
            vuln_dir.mkdir(parents=True, exist_ok=True)

            crash_report_path = vuln_dir / "crash_report.txt"
            crash_report_path.write_text(
                f"crash_type: {record.crash_type}\n"
                f"sanitizer: {record.sanitizer}\n"
                f"target: {record.target}\n"
            )
            record.crash_report_path = crash_report_path.relative_to(output_dir)

            # Reference patch placeholder — real patches require fetching from
            # the ARVO-Meta releases (arvo.db) or the Issues directory; we
            # create an empty stub so downstream code has a path to check.
            patch_path = vuln_dir / "reference_patch.diff"
            if not patch_path.exists():
                patch_path.write_text("")
            record.reference_patch_path = patch_path.relative_to(output_dir)

            # Reproducer URL (crash input) is remote; note it for later download.
            reproducer = entry.get("reproducer")
            if reproducer:
                reproducer_meta = vuln_dir / "reproducer_url.txt"
                reproducer_meta.write_text(reproducer)

            records.append(record)
            if limit is not None and len(records) >= limit:
                break

    # Write aggregated records file
    records_path = output_dir / "records.jsonl"
    with records_path.open("w") as fh:
        for record in records:
            fh.write(record.model_dump_json() + "\n")

    log.info(
        "Ingested %d parser-related vulnerabilities from ARVO (%d total in index)",
        len(records),
        _count_lines(metadata_path),
    )
    return records


def _count_lines(path: Path) -> int:
    """Count non-empty lines in a file without loading it all into memory."""
    count = 0
    with path.open() as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count
