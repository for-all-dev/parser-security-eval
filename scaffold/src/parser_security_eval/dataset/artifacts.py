"""Fetch reference patches from the ARVO-Meta database.

Downloads arvo.db (SQLite) from the ARVO-Meta releases, queries it for
fix_commit and repo_addr fields, then generates reference patches via
``git diff fix_commit~1..fix_commit`` from shallow upstream clones.
"""

from __future__ import annotations

import json
import logging
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
        text=True,
    )
    if result.returncode != 0:
        logger.warning(
            "git diff failed for %s in %s: %s", commit, repo_dir, result.stderr
        )
        return None
    return result.stdout


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

        repo_dir = repos_dir / cache_key
        try:
            _clone_or_update(repo_addr, repo_dir)
        except subprocess.CalledProcessError:
            logger.warning("Failed to clone %s", repo_addr)
            failed_repos.add(cache_key)
            continue

        diff = _git_diff_for_commit(repo_dir, fix_commit)
        if not diff:
            continue

        # Write the patch
        vuln_dir = benchmark_dir / rec["id"]
        vuln_dir.mkdir(parents=True, exist_ok=True)
        patch_path = vuln_dir / "reference_patch.diff"
        patch_path.write_text(diff)

        rec["reference_patch_path"] = f"{rec['id']}/reference_patch.diff"
        success += 1
        if success % 20 == 0:
            logger.info("Progress: %d / %d patches fetched", success, total)

    # Write back updated metadata
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n")
    logger.info("Wrote %d / %d reference patches", success, total)
    return success, total
