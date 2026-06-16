"""Input-format grammar extraction via LLM.

Given a format name and spec text (or source-code context), asks an LLM to
produce a machine-readable :class:`FormatGrammar` describing the format's
structure, magic bytes, size limits, and notable quirks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from parser_security_eval.log import get_log

log = get_log(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class GrammarRule(BaseModel):
    """A single structural rule in the input format."""

    name: str  # e.g. "PNG_chunk", "XML_element"
    description: str  # human-readable explanation
    pattern: str  # BNF-ish or regex pattern describing the syntax
    constraints: list[str]  # e.g. ["length must be > 0", "magic bytes = 0x89504E47"]


class FormatGrammar(BaseModel):
    """Machine-readable description of an input format."""

    target: str
    format_name: str  # e.g. "PNG", "XML", "JPEG"
    description: str
    rules: list[GrammarRule]
    magic_bytes_hex: str | None = None  # hex-encoded magic bytes, e.g. "89504e47"
    max_size_hint: int | None = None  # typical max valid input size in bytes
    notes: list[str] = []  # quirks or edge cases the LLM flagged

    @property
    def magic_bytes(self) -> bytes | None:
        """Return magic bytes decoded from hex, or ``None``."""
        if self.magic_bytes_hex is None:
            return None
        try:
            return bytes.fromhex(self.magic_bytes_hex)
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_GRAMMAR_SYSTEM_PROMPT = """\
You are a binary/text format analysis expert. Given a format specification or
source code, you extract a machine-readable grammar description.

You MUST respond with valid JSON matching this schema (no markdown fences,
no extra text — raw JSON only):

{
  "description": "<one-paragraph summary of the format>",
  "rules": [
    {
      "name": "<rule name>",
      "description": "<what this rule describes>",
      "pattern": "<BNF-like or regex pattern>",
      "constraints": ["<constraint 1>", ...]
    }
  ],
  "magic_bytes_hex": "<hex string or null>",
  "max_size_hint": <integer bytes or null>,
  "notes": ["<quirk or edge case>", ...]
}
"""

_GRAMMAR_USER_TEMPLATE = """\
Format name: {format_name}
Target parser: {target}

Spec / documentation text:
---
{spec_text}
---

Extract a machine-readable grammar for this format. Cover:
- All major message/chunk/element types
- Field types and valid value ranges
- State machine or sequencing constraints
- Magic bytes or file signatures
- Typical size limits
- Known edge cases that fuzz testing should target (e.g. integer overflow in
  length fields, unexpected nesting depth, truncated records)

Respond with raw JSON only — no markdown, no prose outside the JSON object.
"""


# ---------------------------------------------------------------------------
# JSON parsing helper
# ---------------------------------------------------------------------------


def _parse_llm_json(raw: str) -> dict[str, Any]:
    """Extract and parse a JSON object from an LLM response string."""
    # Strip any accidental markdown fences
    text = raw.strip()
    # Remove ```json ... ``` or ``` ... ``` wrappers
    text = re.sub(r"^```[a-z]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)  # type: ignore[no-any-return]
    except json.JSONDecodeError:
        # Try to find the first { ... } block
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group(0))  # type: ignore[no-any-return]
        raise


def _build_grammar_from_dict(
    target: str, format_name: str, data: dict[str, Any]
) -> FormatGrammar:
    """Construct a FormatGrammar from a parsed LLM JSON dict."""
    rules: list[GrammarRule] = []
    for r in data.get("rules", []):
        rules.append(
            GrammarRule(
                name=r.get("name", ""),
                description=r.get("description", ""),
                pattern=r.get("pattern", ""),
                constraints=r.get("constraints", []),
            )
        )

    magic_bytes_hex: str | None = None
    raw_magic_hex = data.get("magic_bytes_hex")
    if raw_magic_hex:
        clean = raw_magic_hex.replace(" ", "")
        try:
            bytes.fromhex(clean)  # validate
            magic_bytes_hex = clean
        except ValueError:
            log.warn("Could not parse magic_bytes_hex: %r", raw_magic_hex)

    return FormatGrammar(
        target=target,
        format_name=format_name,
        description=data.get("description", ""),
        rules=rules,
        magic_bytes_hex=magic_bytes_hex,
        max_size_hint=data.get("max_size_hint"),
        notes=data.get("notes", []),
    )


# ---------------------------------------------------------------------------
# Fallback: extract from source comments and headers
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(
    r"/\*.*?\*/|//[^\n]*",
    re.DOTALL,
)


def _extract_spec_from_source(source_dir: Path) -> str:
    """Collect comments from header files as a pseudo-spec."""
    headers = list(source_dir.rglob("*.h"))[:20]  # cap to avoid huge prompts
    chunks: list[str] = []
    for h in headers:
        try:
            text = h.read_text(errors="replace")
        except OSError:
            continue
        comments = _COMMENT_RE.findall(text)
        if comments:
            rel = h.relative_to(source_dir)
            chunks.append(f"=== {rel} ===\n" + "\n".join(comments[:50]))
    return "\n\n".join(chunks)[:8000]  # keep prompt manageable


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def extract_grammar(
    target: str,
    format_name: str,
    spec_text: str,
    _model: Any = None,
) -> FormatGrammar:
    """Extract a :class:`FormatGrammar` from *spec_text* using an LLM.

    Uses ``inspect_ai.model.get_model()`` to call whichever model is active
    in the current Inspect-AI evaluation context (or the default model if
    called standalone).

    Parameters
    ----------
    target:
        Parser project name (e.g. ``"libpng"``).
    format_name:
        Short format name (e.g. ``"PNG"``).
    spec_text:
        Specification or documentation text to parse.  For targets without a
        spec URL, pass the result of :func:`_extract_spec_from_source`.
    _model:
        Optional pre-built model instance (used in tests to bypass
        ``get_model()`` without patching the inspect_ai internals).

    Returns
    -------
    FormatGrammar
        Parsed grammar ready to embed in a :class:`HarnessContext`.
    """
    from inspect_ai.model import ChatMessageSystem, ChatMessageUser, get_model

    model = _model if _model is not None else get_model()

    user_content = _GRAMMAR_USER_TEMPLATE.format(
        format_name=format_name,
        target=target,
        spec_text=spec_text[:6000],  # stay well inside context window
    )

    response = await model.generate(
        [
            ChatMessageSystem(content=_GRAMMAR_SYSTEM_PROMPT),
            ChatMessageUser(content=user_content),
        ]
    )

    raw = response.completion
    try:
        data = _parse_llm_json(raw)
        return _build_grammar_from_dict(target, format_name, data)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        log.warn(
            "Failed to parse LLM grammar JSON for %s/%s: %s. Returning empty grammar.",
            target,
            format_name,
            exc,
        )
        return FormatGrammar(
            target=target,
            format_name=format_name,
            description=f"Grammar extraction failed: {exc}",
            rules=[],
        )


async def extract_grammar_from_source(
    target: str,
    format_name: str,
    source_dir: Path,
) -> FormatGrammar:
    """Extract grammar by mining source comments when no spec URL is available."""
    spec_text = _extract_spec_from_source(source_dir)
    if not spec_text.strip():
        log.warn(
            "No spec text found in headers for %s; returning minimal grammar", target
        )
        return FormatGrammar(
            target=target,
            format_name=format_name,
            description="No specification or header comments available.",
            rules=[],
        )
    return await extract_grammar(target, format_name, spec_text)
