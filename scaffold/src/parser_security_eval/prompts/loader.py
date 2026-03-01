"""Jinja2-backed prompt loader for parser-security-eval.

Prompt files live next to this module under domain subdirectories:

    prompts/
    ├── patching/system.prompt
    ├── triage/system.prompt
    ├── triage/root_cause_grading.prompt.template
    ├── harness/system.prompt
    ├── harness/user.prompt.template
    ├── fuzzing/system.prompt
    └── fuzzing/user.prompt.template

Name convention (dot-separated):
    "patching.system"           -> patching/system.prompt
    "triage.root_cause_grading" -> triage/root_cause_grading.prompt.template

Rules:
    - Files ending in ``.prompt`` are returned verbatim (no rendering).
    - Files ending in ``.prompt.template`` are rendered with Jinja2 using
      any ``**kwargs`` passed to :func:`render`.
    - :func:`load` raises ``FileNotFoundError`` for missing prompts.
    - Rendered templates are NOT cached (because kwargs vary); plain
      ``.prompt`` content IS cached via :func:`functools.lru_cache`.
"""

from __future__ import annotations

import functools
from pathlib import Path

from jinja2 import Environment, StrictUndefined

_PROMPTS_DIR = Path(__file__).parent

# Jinja2 environment — strict so we notice missing variables immediately.
_env = Environment(  # noqa: S701  (not rendering HTML, no autoescape needed)
    keep_trailing_newline=True,
    undefined=StrictUndefined,
)


def _resolve_path(name: str) -> Path:
    """Convert a dot-separated *name* to a filesystem path.

    Tries ``.prompt.template`` first, then ``.prompt``.
    Raises ``FileNotFoundError`` if neither exists.
    """
    parts = name.rsplit(".", 1)
    if len(parts) != 2:
        raise ValueError(f"Prompt name must be 'domain.key', got: {name!r}")
    domain, key = parts
    base = _PROMPTS_DIR / domain / key

    template_path = base.with_suffix("").with_name(key + ".prompt.template")
    plain_path = base.with_name(key + ".prompt")

    if template_path.exists():
        return template_path
    if plain_path.exists():
        return plain_path

    raise FileNotFoundError(
        f"Prompt not found for {name!r}. Tried:\n  {template_path}\n  {plain_path}"
    )


@functools.lru_cache(maxsize=None)
def _load_plain(path: Path) -> str:
    """Read and cache a plain ``.prompt`` file."""
    return path.read_text(encoding="utf-8")


def load(name: str, **kwargs: object) -> str:
    """Load and optionally render a prompt file.

    Args:
        name: Dot-separated prompt identifier, e.g. ``"patching.system"`` or
              ``"triage.root_cause_grading"``.
        **kwargs: Jinja2 template variables.  Only used when the resolved file
                  ends in ``.prompt.template``; silently ignored for plain
                  ``.prompt`` files.

    Returns:
        The prompt text, rendered if it is a template.

    Raises:
        FileNotFoundError: If no matching file exists.
        jinja2.UndefinedError: If a template variable is missing.
    """
    path = _resolve_path(name)

    if path.name.endswith(".prompt.template"):
        source = path.read_text(encoding="utf-8")
        template = _env.from_string(source)
        return template.render(**kwargs)

    return _load_plain(path)


# Convenience alias kept for callers who prefer explicit naming.
render = load
