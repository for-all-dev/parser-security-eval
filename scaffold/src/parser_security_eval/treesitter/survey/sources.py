"""Source collectors: tree-sitter wiki, Zed, Emacs, and RedMonk rankings.

All network access uses stdlib ``urllib`` (no new dependency) and degrades
gracefully — a failed fetch returns an empty result rather than aborting the run.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from parser_security_eval.treesitter.survey.models import WikiGrammar

WIKI_URL = (
    "https://raw.githubusercontent.com/wiki/tree-sitter/tree-sitter/List-of-parsers.md"
)
ZED_CARGO_LOCK = "https://raw.githubusercontent.com/zed-industries/zed/main/Cargo.lock"
EMACS_TREE = (
    "https://api.github.com/repos/emacs-mirror/emacs/git/trees/master?recursive=1"
)
EMACS_RAW = "https://raw.githubusercontent.com/emacs-mirror/emacs/master/"
CRATES_API = "https://crates.io/api/v1/crates/"

_UA = "parser-security-eval-treesitter-survey"


def _get_text(url: str, *, token: str | None = None, timeout: int = 30) -> str:
    headers = {"User-Agent": _UA}
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 — https only
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read().decode("utf-8", "replace")


def _get_text_safe(url: str, *, token: str | None = None) -> str:
    try:
        return _get_text(url, token=token)
    except urllib.error.URLError, TimeoutError, OSError:
        return ""


# --------------------------------------------------------------------------- #
# URL normalization
# --------------------------------------------------------------------------- #
def normalize_repo_url(raw: str) -> tuple[str, str, str] | None:
    """Return ``(https_url, owner, repo)`` for a GitHub repo URL, or None.

    Tolerates ``github.com/o/r``, trailing ``.git``, and ``/tree/...`` suffixes.
    """
    raw = raw.strip()
    if raw.startswith("github.com"):
        raw = "https://" + raw
    if "github.com" not in raw:
        return None
    parsed = urllib.parse.urlparse(raw)
    if "github.com" not in parsed.netloc:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}", owner, repo


def repo_key(owner: str, repo: str) -> str:
    """Case-insensitive ``owner/repo`` match key."""
    return f"{owner.lower()}/{repo.lower()}"


# --------------------------------------------------------------------------- #
# tree-sitter wiki
# --------------------------------------------------------------------------- #
_LINK_RE = re.compile(r"\((https?://[^)]+)\)")


def parse_wiki(markdown: str) -> list[WikiGrammar]:
    """Parse the 'List of parsers' markdown table into WikiGrammar rows."""
    grammars: list[WikiGrammar] = []
    for line in markdown.splitlines():
        if not line.startswith("| "):
            continue
        parts = [c.strip() for c in line.split("|")]
        # parts: ['', name, link, date, abi, grammar.json, external scanner, '']
        if len(parts) < 8:
            continue
        name, link_cell, date, abi, gj, es = (
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            parts[5],
            parts[6],
        )
        if name in {"name", "---"} or "github.com" not in link_cell:
            continue
        m = _LINK_RE.search(link_cell)
        url_raw = m.group(1) if m else link_cell
        norm = normalize_repo_url(url_raw)
        if norm is None:
            continue
        https, owner, repo = norm
        grammars.append(
            WikiGrammar(
                name=name.lower(),
                repo_url=https,
                owner=owner,
                repo=repo,
                wiki_last_commit=date if date and date != "-" else None,
                abi=abi if abi and abi != "-" else None,
                has_grammar_json=gj.lower() == "yes",
                has_external_scanner=es.lower() == "yes",
            )
        )
    return grammars


def fetch_wiki_grammars(token: str | None = None) -> list[WikiGrammar]:
    return parse_wiki(_get_text_safe(WIKI_URL, token=token))


# --------------------------------------------------------------------------- #
# Zed
# --------------------------------------------------------------------------- #
_ZED_GIT_RE = re.compile(r'source = "git\+(https://github\.com/[^?"#]+)')
_ZED_CRATE_RE = re.compile(r'^name = "(tree-sitter-[^"]+)"', re.MULTILINE)


def parse_zed_cargo_lock(text: str) -> tuple[set[str], set[str]]:
    """Return (repo_keys, crate_names) of tree-sitter deps in a Zed Cargo.lock."""
    repo_keys: set[str] = set()
    for url in _ZED_GIT_RE.findall(text):
        norm = normalize_repo_url(url)
        if norm:
            repo_keys.add(repo_key(norm[1], norm[2]))
    crate_names = set(_ZED_CRATE_RE.findall(text))
    return repo_keys, crate_names


def resolve_crate_repo(crate: str) -> tuple[str, str] | None:
    """Resolve a crates.io crate to its ``(owner, repo)`` via the crates.io API."""
    body = _get_text_safe(f"{CRATES_API}{crate}")
    if not body:
        return None
    try:
        data = json.loads(body)
        repository = data.get("crate", {}).get("repository") or ""
    except ValueError, AttributeError:
        return None
    norm = normalize_repo_url(repository)
    return (norm[1], norm[2]) if norm else None


def fetch_zed_grammars() -> tuple[set[str], set[str]]:
    """Return (repo_keys, basenames) of grammars Zed depends on.

    Combines git-sourced deps with crates.io crates resolved to their repos.
    Basenames (the ``tree-sitter-x`` repo name) catch Zed's forks of wiki grammars.
    """
    text = _get_text_safe(ZED_CARGO_LOCK)
    if not text:
        return set(), set()
    repo_keys, crate_names = parse_zed_cargo_lock(text)
    for crate in sorted(crate_names):
        resolved = resolve_crate_repo(crate)
        if resolved:
            repo_keys.add(repo_key(*resolved))
    basenames = {key.split("/", 1)[1] for key in repo_keys}
    basenames |= {c.lower() for c in crate_names}
    return repo_keys, basenames


# --------------------------------------------------------------------------- #
# Emacs
# --------------------------------------------------------------------------- #
_GH_TS_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]*tree[-_]?sitter[A-Za-z0-9_.-]*"
)


def fetch_emacs_grammars(token: str | None = None) -> tuple[set[str], set[str]]:
    """Return (repo_keys, basenames) of grammars referenced by Emacs *-ts-mode.el."""
    tree_body = _get_text_safe(EMACS_TREE, token=token)
    if not tree_body:
        return set(), set()
    try:
        tree = json.loads(tree_body).get("tree", [])
    except ValueError:
        return set(), set()
    paths = [t["path"] for t in tree if str(t.get("path", "")).endswith("-ts-mode.el")]
    repo_keys: set[str] = set()
    for path in paths:
        content = _get_text_safe(EMACS_RAW + path, token=token)
        for url in _GH_TS_URL_RE.findall(content):
            norm = normalize_repo_url(url)
            if norm:
                repo_keys.add(repo_key(norm[1], norm[2]))
    basenames = {key.split("/", 1)[1] for key in repo_keys}
    return repo_keys, basenames


# --------------------------------------------------------------------------- #
# RedMonk programming-language rankings (RedMonk, ~2024; lower rank = more popular)
# --------------------------------------------------------------------------- #
REDMONK_RANKS: dict[str, int] = {
    "javascript": 1,
    "python": 2,
    "java": 3,
    "php": 4,
    "csharp": 5,
    "typescript": 6,
    "css": 6,
    "cpp": 8,
    "ruby": 9,
    "c": 9,
    "swift": 11,
    "r": 12,
    "objc": 12,
    "shell": 14,
    "scala": 15,
    "go": 15,
    "powershell": 17,
    "kotlin": 17,
    "rust": 19,
    "dart": 19,
    "lua": 21,
    "groovy": 22,
    "perl": 23,
    "haskell": 24,
    "elixir": 25,
    "clojure": 26,
    "julia": 27,
    "elm": 28,
    "ocaml": 29,
    "erlang": 30,
}

# Map wiki language names → RedMonk canonical key.
_REDMONK_ALIASES: dict[str, str] = {
    "c_sharp": "csharp",
    "c-sharp": "csharp",
    "cs": "csharp",
    "c++": "cpp",
    "objective_c": "objc",
    "objective-c": "objc",
    "objc": "objc",
    "bash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "fish": "shell",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "golang": "go",
    "rs": "rust",
    "py": "python",
}


def redmonk_rank(name: str) -> int | None:
    """Look up a RedMonk rank for a wiki language name (with aliases)."""
    key = name.lower().strip()
    key = _REDMONK_ALIASES.get(key, key)
    return REDMONK_RANKS.get(key)
