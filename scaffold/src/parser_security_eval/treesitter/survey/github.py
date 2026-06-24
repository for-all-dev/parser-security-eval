"""A small, cached, restartable GitHub REST client (stdlib only).

Reads a token from the constructor or ``GITHUB_TOKEN``. Unauthenticated runs work
but are capped at 60 req/hr — fine for incremental, cache-backed re-runs. Each
repo's raw API responses are cached on disk so a survey can be resumed and re-run
cheaply.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast

from parser_security_eval.treesitter.survey.models import RepoMetrics

_API = "https://api.github.com"
_UA = "parser-security-eval-treesitter-survey"

# Last-page number in a GitHub `Link` header. Anchored on `[?&]page=` so it does
# NOT match the `per_page=` query parameter (a substring-match bug otherwise).
_LAST_PAGE_RE = re.compile(r'[?&]page=(\d+)>;\s*rel="last"')


def _as_dict(obj: object) -> dict[str, object]:
    """Return obj as a str-keyed dict (empty if it isn't a dict)."""
    return cast("dict[str, object]", obj) if isinstance(obj, dict) else {}


def contributors_from_link(link: str) -> int | None:
    """Extract the contributor count (last page, page size 1) from a Link header."""
    m = _LAST_PAGE_RE.search(link)
    return int(m.group(1)) if m else None


def detect_fuzz_setup(paths: list[str]) -> tuple[bool, str]:
    """Detect existing fuzzing infra from a repo's file paths.

    Any path segment containing ``fuzz`` (e.g. ``fuzz/``, ``fuzzer.cc``,
    ``test/fuzz/...``, ``.github/workflows/fuzz.yml``, ``oss-fuzz``) counts.
    Returns ``(found, first_matching_path)``.
    """
    for path in paths:
        if any("fuzz" in seg.lower() for seg in path.split("/")):
            return True, path
    return False, ""


class RateLimitError(RuntimeError):
    """Raised when the GitHub rate limit is exhausted."""

    def __init__(self, reset_epoch: int) -> None:
        self.reset_epoch = reset_epoch
        wait = max(0, reset_epoch - int(time.time()))
        super().__init__(f"GitHub rate limit exhausted; resets in ~{wait}s")


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        cache_dir: Path | None = None,
        refresh_days: float = 7.0,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN") or None
        self.cache_dir = cache_dir or (
            Path.home() / ".cache" / "parser-security-eval" / "treesitter" / "gh_cache"
        )
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.refresh_seconds = refresh_days * 86400.0
        self.rate_remaining: int | None = None

    @property
    def authenticated(self) -> bool:
        return self.token is not None

    # -- low-level ---------------------------------------------------------- #
    def _request(self, url: str) -> tuple[int, object, dict[str, str]]:
        headers = {
            "User-Agent": _UA,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, headers=headers)  # noqa: S310 — https only
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                self._note_rate(dict(resp.headers))
                body = resp.read().decode("utf-8", "replace")
                data = json.loads(body) if body else None
                return resp.status, data, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            hdrs = dict(exc.headers or {})
            self._note_rate(hdrs)
            if exc.code == 403 and hdrs.get("X-RateLimit-Remaining") == "0":
                raise RateLimitError(int(hdrs.get("X-RateLimit-Reset", "0"))) from exc
            return exc.code, None, hdrs

    def _note_rate(self, headers: dict[str, str]) -> None:
        rem = headers.get("X-RateLimit-Remaining")
        if rem is not None and rem.isdigit():
            self.rate_remaining = int(rem)

    # -- caching ------------------------------------------------------------ #
    def _cache_path(self, owner: str, repo: str) -> Path:
        return self.cache_dir / f"{owner.lower()}__{repo.lower()}.json"

    def _load_cache(self, owner: str, repo: str) -> dict[str, object] | None:
        path = self._cache_path(owner, repo)
        if not path.exists():
            return None
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except ValueError, OSError:
            return None
        fetched = float(blob.get("_fetched", 0))
        if time.time() - fetched > self.refresh_seconds:
            return None
        return blob

    # -- high-level --------------------------------------------------------- #
    def fetch_metrics(
        self, owner: str, repo: str, *, use_cache: bool = True
    ) -> RepoMetrics:
        """Fetch (or load cached) metrics for ``owner/repo``."""
        if use_cache:
            cached = self._load_cache(owner, repo)
            if cached is not None:
                return self._to_metrics(cached)

        blob: dict[str, object] = {}
        status, repo_data, _ = self._request(f"{_API}/repos/{owner}/{repo}")
        if status == 404:
            return RepoMetrics(fetched=False, error="repo not found (404)")
        if status != 200 or not isinstance(repo_data, dict):
            return RepoMetrics(fetched=False, error=f"repo fetch HTTP {status}")
        blob["repo"] = repo_data
        blob["commit_activity"] = self._commit_activity(owner, repo)
        blob["contributors"] = self._contributors_count(owner, repo)
        default_branch = _as_dict(repo_data).get("default_branch")
        blob["fuzz"] = self.fuzz_signals(
            owner, repo, default_branch if isinstance(default_branch, str) else "HEAD"
        )
        blob["_fetched"] = time.time()
        self._cache_path(owner, repo).write_text(json.dumps(blob), encoding="utf-8")
        return self._to_metrics(blob)

    def _commit_activity(self, owner: str, repo: str) -> list[object]:
        # Stats endpoints return 202 while GitHub computes; retry briefly.
        url = f"{_API}/repos/{owner}/{repo}/stats/commit_activity"
        for _ in range(4):
            status, data, _ = self._request(url)
            if status == 200 and isinstance(data, list):
                return cast("list[object]", data)
            if status == 202:
                time.sleep(1.5)
                continue
            break
        return []

    def _contributors_count(self, owner: str, repo: str) -> int | None:
        url = f"{_API}/repos/{owner}/{repo}/contributors?per_page=1&anon=1"
        status, data, headers = self._request(url)
        if status != 200:
            return None
        return contributors_from_link(headers.get("Link", "")) or (
            len(data) if isinstance(data, list) else None
        )

    def fuzz_signals(self, owner: str, repo: str, branch: str) -> dict[str, object]:
        """Scan the repo's file tree for existing fuzzing infrastructure."""
        url = f"{_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        status, data, _ = self._request(url)
        tree = _as_dict(data).get("tree") if status == 200 else None
        paths = [
            str(_as_dict(t).get("path", ""))
            for t in (tree if isinstance(tree, list) else [])
        ]
        found, evidence = detect_fuzz_setup(paths)
        return {"has_fuzz_setup": found, "fuzz_evidence": evidence}

    @staticmethod
    def _to_metrics(blob: dict[str, object]) -> RepoMetrics:
        repo = _as_dict(blob.get("repo"))
        if not repo:
            return RepoMetrics(fetched=False, error="no repo data")
        activity = blob.get("commit_activity")
        weeks = activity if isinstance(activity, list) else []
        totals: list[int] = []
        for w in weeks:
            total = _as_dict(w).get("total")
            if isinstance(total, int):
                totals.append(total)
        last_year = sum(totals) if totals else None
        last_90d = sum(totals[-13:]) if totals else None
        active_weeks = sum(1 for t in totals if t > 0) if totals else None

        license_id = _as_dict(repo.get("license")).get("spdx_id")
        parent_name = _as_dict(repo.get("parent")).get("full_name")
        contributors = blob.get("contributors")
        topics_raw = repo.get("topics")
        topics = [str(t) for t in topics_raw] if isinstance(topics_raw, list) else []
        fuzz = _as_dict(blob.get("fuzz"))

        # Build via model_validate so pydantic coerces the dynamically-typed
        # (``object``) API values into the typed fields.
        return RepoMetrics.model_validate(
            {
                "fetched": True,
                "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"),
                "is_fork": repo.get("fork"),
                "parent": parent_name,
                "archived": bool(repo.get("archived", False)),
                "disabled": bool(repo.get("disabled", False)),
                "pushed_at": repo.get("pushed_at"),
                "created_at": repo.get("created_at"),
                "updated_at": repo.get("updated_at"),
                "open_issues": repo.get("open_issues_count"),
                "has_issues": repo.get("has_issues"),
                "license": license_id
                if license_id and license_id != "NOASSERTION"
                else None,
                "size_kb": repo.get("size"),
                "topics": topics,
                "subscribers": repo.get("subscribers_count"),
                "contributors": contributors if isinstance(contributors, int) else None,
                "commits_last_year": last_year,
                "commits_last_90d": last_90d,
                "active_weeks_last_year": active_weeks,
                "has_fuzz_setup": bool(fuzz.get("has_fuzz_setup", False)),
                "fuzz_evidence": str(fuzz.get("fuzz_evidence", "") or ""),
            }
        )
