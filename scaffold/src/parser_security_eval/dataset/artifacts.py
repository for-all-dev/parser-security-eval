"""Fetch reference patches and vulnerable source from the ARVO-Meta database.

Downloads arvo.db (SQLite) from the ARVO-Meta releases, queries it for
fix_commit and repo_addr fields, then generates reference patches via
``git diff fix_commit~1..fix_commit`` from shallow upstream clones.
Also extracts pre-fix source files for inclusion in patching task prompts.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

ARVO_DB_URL = "https://github.com/n132/ARVO-Meta/releases/download/v3.0.0/arvo.db"


def download_arvo_db(cache_dir: Path) -> Path:
    """Download arvo.db to *cache_dir* if not already present."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    db_path = cache_dir / "arvo.db"
    if db_path.exists():
        logger.info("arvo.db already cached at %s", db_path)
        return db_path

    logger.info("Downloading arvo.db from %s …", ARVO_DB_URL)
    urllib.request.urlretrieve(ARVO_DB_URL, db_path)  # noqa: S310
    logger.info("Downloaded arvo.db (%d MB)", db_path.stat().st_size // (1024 * 1024))
    return db_path


def query_arvo_db(db_path: Path, local_ids: list[int]) -> dict[int, dict]:
    """Query arvo.db for fix_commit and repo_addr by localId.

    Returns a mapping ``{localId: {fix_commit, repo_addr, patch_url}}``.
    """
    if not local_ids:
        return {}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        placeholders = ",".join("?" for _ in local_ids)
        rows = conn.execute(
            f"SELECT localId, fix_commit, repo_addr, patch_url "  # noqa: S608
            f"FROM arvo WHERE localId IN ({placeholders})",
            local_ids,
        ).fetchall()
        return {
            row["localId"]: {
                "fix_commit": row["fix_commit"],
                "repo_addr": row["repo_addr"],
                "patch_url": row["patch_url"],
            }
            for row in rows
        }
    finally:
        conn.close()


def _normalize_repo_url(repo_url: str) -> str:
    """Rewrite known problematic repo URLs to working alternatives."""
    # gitlab.gnome.org redirects to github.com but bare clones fail;
    # use the GitHub mirror directly.
    if "gitlab.gnome.org/GNOME/" in repo_url:
        project = repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
        return f"https://github.com/GNOME/{project}.git"
    return repo_url


def _clone_or_update(repo_url: str, clone_dir: Path) -> None:
    """Shallow-clone a repo or fetch if already present."""
    repo_url = _normalize_repo_url(repo_url)

    if (clone_dir / ".git").is_dir() or (clone_dir / "HEAD").is_file():
        return  # already cloned

    clone_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--bare", "--filter=blob:none", repo_url, str(clone_dir)],
        check=True,
        capture_output=True,
    )


def _git_diff_for_commit(repo_dir: Path, commit: str) -> str | None:
    """Generate ``git diff commit~1..commit`` from a bare/shallow clone."""
    # Ensure the commit is available locally
    try:
        subprocess.run(
            ["git", "-C", str(repo_dir), "fetch", "--depth=2", "origin", commit],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        logger.warning("Could not fetch commit %s in %s", commit, repo_dir)
        return None

    result = subprocess.run(
        ["git", "-C", str(repo_dir), "diff", f"{commit}~1..{commit}"],
        capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace")
        logger.warning("git diff failed for %s in %s: %s", commit, repo_dir, stderr)
        return None
    return result.stdout.decode(errors="replace")


def _fetch_patch_from_url(patch_url: str, timeout: int = 30) -> str | None:
    """Try to download a unified diff from a patch URL.

    For GitHub commit URLs, appends ``.diff`` to get raw diff output.
    For other URLs, fetches directly and checks if the response looks like
    a unified diff.
    """
    if not patch_url or not patch_url.startswith("http"):
        return None

    url = patch_url.rstrip("/")
    if "github.com" in url and "/commit/" in url:
        url = url + ".diff"

    try:
        req = urllib.request.Request(url, headers={"Accept": "text/plain"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            content = resp.read().decode(errors="replace")
    except Exception:
        logger.debug("Failed to fetch patch from %s", url)
        return None

    # Sanity check: does this look like a unified diff?
    if "diff --git" in content or content.startswith("--- "):
        return content
    return None


def _extract_sources_from_docker(
    local_id: int,
    c_files: list[str],
    vuln_dir: Path,
    *,
    timeout_pull: int = 120,
    timeout_cmd: int = 30,
    failed_images: set[int] | None = None,
) -> dict[str, str]:
    """Extract source files from an ARVO Docker image.

    Pulls ``n132/arvo:<localId>-vul``, creates a single stopped container,
    finds matching source files under ``/src/``, copies them out, and cleans
    up.  Returns a mapping ``{repo_path: benchmark_relative_path}``.
    """
    if failed_images and local_id in failed_images:
        return {}

    image = f"n132/arvo:{local_id}-vul"
    container_name = f"tmp-arvo-{local_id}"

    # Pull the image
    try:
        subprocess.run(
            ["docker", "pull", image],
            check=True,
            capture_output=True,
            timeout=timeout_pull,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.warning("Failed to pull Docker image %s: %s", image, e)
        if failed_images is not None:
            failed_images.add(local_id)
        return {}

    # Create a stopped container for file extraction
    try:
        subprocess.run(
            ["docker", "create", "--name", container_name, image],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        logger.warning("Failed to create container %s", container_name)
        return {}

    vuln_src_dir = vuln_dir / "vulnerable_src"
    vuln_src_dir.mkdir(parents=True, exist_ok=True)
    source_paths: dict[str, str] = {}

    try:
        for file_path in c_files:
            basename = Path(file_path).name
            try:
                # Locate the file inside the container
                find_result = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        image,
                        "find",
                        "/src",
                        "-name",
                        basename,
                        "-type",
                        "f",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout_cmd,
                )
                if find_result.returncode != 0 or not find_result.stdout.strip():
                    logger.debug("File %s not found in %s", basename, image)
                    continue

                container_path = find_result.stdout.strip().splitlines()[0]

                # Copy file out via docker cp
                dest = vuln_src_dir / basename
                subprocess.run(
                    ["docker", "cp", f"{container_name}:{container_path}", str(dest)],
                    check=True,
                    capture_output=True,
                    timeout=timeout_cmd,
                )
            except subprocess.CalledProcessError, subprocess.TimeoutExpired:
                logger.debug("Failed to extract %s from %s", basename, container_name)
                continue

            if dest.exists() and dest.stat().st_size > 0:
                rel = f"arvo/{vuln_dir.name}/vulnerable_src/{basename}"
                source_paths[file_path] = rel
    finally:
        # Clean up the stopped container
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
        )

    return source_paths


def _repo_cache_key(repo_url: str) -> str:
    """Derive a filesystem-safe cache key from a repo URL."""
    # e.g. "https://github.com/foo/bar.git" → "github.com_foo_bar"
    cleaned = repo_url.rstrip("/").removesuffix(".git")
    cleaned = cleaned.split("://", 1)[-1]
    return cleaned.replace("/", "_")


def fetch_reference_patches(
    benchmark_dir: Path,
    cache_dir: Path,
) -> tuple[int, int]:
    """Fetch reference patches for all records in benchmark/metadata.json.

    Returns ``(success_count, total_count)``.
    """
    metadata_path = benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    records = metadata.get("records", [])

    # Extract localIds from "ARVO-{localId}" IDs
    id_to_record: dict[int, dict] = {}
    for rec in records:
        rid = rec["id"]
        if rid.startswith("ARVO-"):
            try:
                local_id = int(rid.removeprefix("ARVO-"))
                id_to_record[local_id] = rec
            except ValueError:
                continue

    total = len(id_to_record)
    logger.info("Found %d ARVO records in metadata", total)

    db_path = download_arvo_db(cache_dir)
    arvo_data = query_arvo_db(db_path, list(id_to_record.keys()))
    logger.info("arvo.db matched %d / %d records", len(arvo_data), total)

    repos_dir = cache_dir / "repos"
    success = 0
    failed_repos: set[str] = set()

    for local_id, rec in id_to_record.items():
        info = arvo_data.get(local_id)
        if not info:
            continue

        raw_commit = (info.get("fix_commit") or "").strip()
        repo_addr = (info.get("repo_addr") or "").strip()
        if not raw_commit or not repo_addr:
            continue

        # Some entries have multiple commits separated by newlines; take only
        # the first one (the primary fix commit).
        fix_commit = raw_commit.split("\n")[0].strip()
        if not fix_commit:
            continue

        # Use normalized URL for cache key so redirected repos share a clone
        normalized_url = _normalize_repo_url(repo_addr)
        cache_key = _repo_cache_key(normalized_url)

        if cache_key in failed_repos:
            continue

        diff: str | None = None
        extraction_method = "git"

        repo_dir = repos_dir / cache_key
        try:
            _clone_or_update(repo_addr, repo_dir)
            diff = _git_diff_for_commit(repo_dir, fix_commit)
        except subprocess.CalledProcessError:
            logger.warning("Failed to clone %s", repo_addr)
            failed_repos.add(cache_key)

        # Fallback: fetch patch from patch_url when git fails
        if diff is None:
            patch_url = (info.get("patch_url") or "").strip()
            diff = _fetch_patch_from_url(patch_url)
            if diff:
                extraction_method = "patch_url"
                logger.info("Fetched patch from patch_url for %s", rec["id"])

        if not diff:
            continue

        # Write the patch into benchmark/arvo/ARVO-{id}/
        vuln_dir = benchmark_dir / "arvo" / rec["id"]
        vuln_dir.mkdir(parents=True, exist_ok=True)
        patch_path = vuln_dir / "reference_patch.diff"
        patch_path.write_text(diff)

        rec["reference_patch_path"] = f"arvo/{rec['id']}/reference_patch.diff"
        rec["source_extraction_method"] = extraction_method
        success += 1
        if success % 20 == 0:
            logger.info("Progress: %d / %d patches fetched", success, total)

    # Clean up arvo dirs not referenced by metadata
    _cleanup_unreferenced_arvo_dirs(benchmark_dir, metadata)

    # Write back updated metadata
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info("Wrote %d / %d reference patches", success, total)
    return success, total


_C_EXTENSIONS = frozenset((".c", ".cc", ".cpp", ".h", ".hh", ".hpp"))


def _parse_c_files_from_patch(patch_text: str) -> list[str]:
    """Extract C/C++ file paths from ``diff --git`` headers in a unified diff."""
    paths: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"^diff --git a/(\S+) b/\S+", patch_text, re.MULTILINE):
        p = m.group(1)
        suffix = Path(p).suffix.lower()
        if suffix in _C_EXTENSIONS and p not in seen:
            paths.append(p)
            seen.add(p)
    return paths


def _git_show_file(repo_dir: Path, commit: str, file_path: str) -> str | None:
    """Retrieve file contents at ``commit`` via ``git show``."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "show", f"{commit}:{file_path}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def extract_vulnerable_sources(
    benchmark_dir: Path,
    cache_dir: Path,
    max_files_per_record: int = 5,
) -> tuple[int, int]:
    """Extract pre-fix source files for records that have a reference patch.

    For each ARVO record with a reference patch and a fix_commit in arvo.db,
    parses the patch to find modified C/H files, then runs
    ``git show fix_commit~1:<path>`` to get the vulnerable version.

    When git extraction fails (non-git VCS, shallow clone gaps), falls back to
    extracting source files from the ARVO Docker image
    ``n132/arvo:<localId>-vul``.

    Returns ``(records_with_sources, total_records)``.
    """
    metadata_path = benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    records = metadata.get("records", [])

    # Build id → record mapping for ARVO records that have a reference patch
    id_to_record: dict[int, dict] = {}
    for rec in records:
        rid = rec["id"]
        if rid.startswith("ARVO-") and rec.get("reference_patch_path"):
            try:
                local_id = int(rid.removeprefix("ARVO-"))
                id_to_record[local_id] = rec
            except ValueError:
                continue

    total = len(id_to_record)
    logger.info("Found %d ARVO records with reference patches", total)

    db_path = download_arvo_db(cache_dir)
    arvo_data = query_arvo_db(db_path, list(id_to_record.keys()))
    repos_dir = cache_dir / "repos"
    success = 0
    git_extracted = 0
    docker_extracted = 0
    failed_repos: set[str] = set()
    failed_docker: set[int] = set()

    for local_id, rec in id_to_record.items():
        info = arvo_data.get(local_id)
        if not info:
            continue

        raw_commit = (info.get("fix_commit") or "").strip()
        repo_addr = (info.get("repo_addr") or "").strip()
        if not raw_commit or not repo_addr:
            continue

        fix_commit = raw_commit.split("\n")[0].strip()
        if not fix_commit:
            continue

        # Read the reference patch to find which files were modified
        patch_path = benchmark_dir / rec["reference_patch_path"]
        if not patch_path.exists():
            continue
        patch_text = patch_path.read_text()
        c_files = _parse_c_files_from_patch(patch_text)[:max_files_per_record]
        if not c_files:
            continue

        # Check if already extracted
        existing = rec.get("vulnerable_source_paths", {})
        if len(existing) >= len(c_files):
            # Verify files still exist on disk
            all_exist = all((benchmark_dir / p).exists() for p in existing.values())
            if all_exist:
                success += 1
                continue

        # --- Try git extraction first ---
        source_paths: dict[str, str] = {}
        normalized_url = _normalize_repo_url(repo_addr)
        cache_key = _repo_cache_key(normalized_url)
        git_available = cache_key not in failed_repos

        if git_available:
            repo_dir = repos_dir / cache_key
            try:
                _clone_or_update(repo_addr, repo_dir)
            except subprocess.CalledProcessError:
                logger.warning("Failed to clone %s", repo_addr)
                failed_repos.add(cache_key)
                git_available = False

        if git_available:
            # Ensure the commit is available
            try:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo_dir),
                        "fetch",
                        "--depth=2",
                        "origin",
                        fix_commit,
                    ],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError:
                logger.warning("Could not fetch commit %s in %s", fix_commit, repo_dir)
                git_available = False

        if git_available:
            vuln_dir = benchmark_dir / "arvo" / rec["id"] / "vulnerable_src"
            vuln_dir.mkdir(parents=True, exist_ok=True)

            for file_path in c_files:
                content = _git_show_file(repo_dir, f"{fix_commit}~1", file_path)
                if content is None:
                    logger.debug(
                        "Could not extract %s at %s~1 for %s",
                        file_path,
                        fix_commit,
                        rec["id"],
                    )
                    continue
                basename = Path(file_path).name
                dest = vuln_dir / basename
                dest.write_text(content)
                rel = f"arvo/{rec['id']}/vulnerable_src/{basename}"
                source_paths[file_path] = rel

        # --- Docker fallback when git produced no sources ---
        if not source_paths:
            docker_paths = _extract_sources_from_docker(
                local_id,
                c_files,
                benchmark_dir / "arvo" / rec["id"],
                failed_images=failed_docker,
            )
            if docker_paths:
                source_paths = docker_paths
                rec["source_extraction_method"] = "docker"
                docker_extracted += 1
                logger.info(
                    "Extracted %d sources from Docker for %s",
                    len(docker_paths),
                    rec["id"],
                )

        if source_paths:
            rec["vulnerable_source_paths"] = source_paths
            if rec.get("source_extraction_method") != "docker":
                rec["source_extraction_method"] = "git"
                git_extracted += 1
            success += 1

        if success % 20 == 0 and success > 0:
            logger.info("Progress: %d / %d sources extracted", success, total)

    # Write back updated metadata
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info(
        "Extracted vulnerable sources for %d / %d records (git: %d, docker: %d)",
        success,
        total,
        git_extracted,
        docker_extracted,
    )
    return success, total


def resolve_vulnerable_refs(
    benchmark_dir: Path,
    cache_dir: Path,
) -> tuple[int, int]:
    """Resolve ``vulnerable_source_ref`` (git commit hash) for each record.

    For each ARVO record with a fix_commit in arvo.db, resolves
    ``fix_commit~1`` to a full SHA and writes it to
    ``record["vulnerable_source_ref"]``.  This commit hash can then be
    used by the solver/scorer to ``git checkout`` the exact vulnerable
    state inside the Docker container.

    Returns ``(resolved_count, total_count)``.
    """
    metadata_path = benchmark_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    records = metadata.get("records", [])

    id_to_record: dict[int, dict] = {}
    for rec in records:
        rid = rec["id"]
        if rid.startswith("ARVO-"):
            try:
                local_id = int(rid.removeprefix("ARVO-"))
                id_to_record[local_id] = rec
            except ValueError:
                continue

    total = len(id_to_record)
    logger.info("Found %d ARVO records to resolve vulnerable refs", total)

    db_path = download_arvo_db(cache_dir)
    arvo_data = query_arvo_db(db_path, list(id_to_record.keys()))
    repos_dir = cache_dir / "repos"
    resolved = 0
    failed_repos: set[str] = set()

    for local_id, rec in id_to_record.items():
        # Skip if already resolved
        if rec.get("vulnerable_source_ref"):
            resolved += 1
            continue

        info = arvo_data.get(local_id)
        if not info:
            continue

        raw_commit = (info.get("fix_commit") or "").strip()
        repo_addr = (info.get("repo_addr") or "").strip()
        if not raw_commit or not repo_addr:
            continue

        fix_commit = raw_commit.split("\n")[0].strip()
        if not fix_commit:
            continue

        normalized_url = _normalize_repo_url(repo_addr)
        cache_key = _repo_cache_key(normalized_url)

        if cache_key in failed_repos:
            continue

        repo_dir = repos_dir / cache_key
        try:
            _clone_or_update(repo_addr, repo_dir)
        except subprocess.CalledProcessError:
            logger.warning("Failed to clone %s", repo_addr)
            failed_repos.add(cache_key)
            continue

        # Ensure the commit is available
        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo_dir),
                    "fetch",
                    "--depth=2",
                    "origin",
                    fix_commit,
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            logger.warning("Could not fetch commit %s in %s", fix_commit, repo_dir)
            continue

        # Resolve fix_commit~1 to a full SHA
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", f"{fix_commit}~1"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "Could not resolve %s~1 for %s: %s",
                fix_commit,
                rec["id"],
                result.stderr.strip(),
            )
            continue

        vuln_ref = result.stdout.strip()
        rec["vulnerable_source_ref"] = vuln_ref
        resolved += 1

        if resolved % 20 == 0:
            logger.info("Progress: %d / %d refs resolved", resolved, total)

    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info("Resolved vulnerable refs for %d / %d records", resolved, total)
    return resolved, total


def _cleanup_unreferenced_arvo_dirs(benchmark_dir: Path, metadata: dict) -> None:
    """Remove arvo/ subdirectories not referenced by any record in metadata."""
    arvo_dir = benchmark_dir / "arvo"
    if not arvo_dir.is_dir():
        return

    referenced = {r["id"] for r in metadata.get("records", [])}
    removed = 0
    for d in sorted(arvo_dir.iterdir()):
        if d.is_dir() and d.name not in referenced:
            shutil.rmtree(d)
            removed += 1
    if removed:
        logger.info("Cleaned up %d unreferenced arvo directories", removed)
