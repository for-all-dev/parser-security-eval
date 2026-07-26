"""Transparent fuzzing-priority scoring for grammar records.

The composite favors grammars that are **impactful** (used by Zed/Emacs, popular
language, some stars), **likely to have bugs** (hand-written external scanner, less
scrutiny, older), and **tractable** (actively maintained, not archived). All
sub-scores are stored on the record so the priority list can be re-weighted later.
"""

from __future__ import annotations

import math
from datetime import datetime

from parser_security_eval.treesitter.survey.models import GrammarRecord

# Orgs whose grammars are well-maintained and continuously fuzzed by OSS-Fuzz, so
# latent memory bugs are far less likely — deprioritized as fuzzing targets.
CORE_ORGS = {"tree-sitter", "tree-sitter-grammars"}


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _months_between(iso: str | None, now: datetime) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - dt).days / 30.44


def _years_between(iso: str | None, now: datetime) -> float | None:
    months = _months_between(iso, now)
    return None if months is None else months / 12.0


def _activity_gate(months_since_push: float | None) -> float:
    """1.0 if pushed within a year, decaying to 0 by ~30 months (abandoned)."""
    if months_since_push is None:
        return 0.35  # unknown — neither reward nor exclude
    if months_since_push <= 12:
        return 1.0
    if months_since_push >= 30:
        return 0.0
    return _clamp(1.0 - (months_since_push - 12) / 18.0 * 0.85)


def compute_priority(rec: GrammarRecord, now: datetime) -> None:
    """Populate ``rec.scores``, ``rec.fuzz_priority`` and ``rec.priority_reasons``."""
    m = rec.metrics
    reasons: list[str] = []

    # --- impact ---------------------------------------------------------------
    adoption = _clamp(0.6 * rec.used_by_zed + 0.6 * rec.used_by_emacs)
    if rec.used_by_zed:
        reasons.append("used by Zed")
    if rec.used_by_emacs:
        reasons.append("used by Emacs")

    redmonk = 0.0
    if rec.redmonk_rank is not None:
        redmonk = _clamp(1.0 - (rec.redmonk_rank - 1) / 30.0)
        reasons.append(f"RedMonk #{rec.redmonk_rank}")

    stars = m.stars if m.stars is not None else None
    pop = 0.0
    if stars is not None:
        pop = _clamp(math.log10(stars + 1) / math.log10(5000))

    impact = _clamp(0.45 * adoption + 0.30 * redmonk + 0.25 * pop)

    # --- bug likelihood (crash surface × neglect × latent) --------------------
    # Crash surface: a grammar's only hand-written C is its external scanner.
    # Generated parser.c is table-driven and memory-safe by construction, so a
    # no-scanner grammar offers almost no grammar-specific crash surface.
    crash_surface = 1.0 if rec.has_external_scanner else 0.15
    if rec.has_external_scanner:
        reasons.append("external scanner (hand-written C)")
    else:
        reasons.append("no scanner — minimal crash surface")

    # Neglect: if the repo is already fuzzed, the easy crashes are likely found.
    already_fuzzed = (
        m.has_fuzz_setup
        or rec.owner.lower() in CORE_ORGS
        or any("fuzz" in t.lower() for t in m.topics)
    )
    neglect = 1.0
    if already_fuzzed:
        neglect = 0.2
        if m.has_fuzz_setup:
            reasons.append(f"already fuzzed ({m.fuzz_evidence})")
        elif rec.owner.lower() in CORE_ORGS:
            reasons.append("core tree-sitter org (continuously fuzzed by OSS-Fuzz)")
        else:
            reasons.append("already fuzzed (oss-fuzz topic)")
    else:
        reasons.append("no existing fuzz harness")

    low_scrutiny = 1.0 - pop  # fewer stars/eyeballs → more latent bugs
    years = _years_between(m.created_at, now)
    age = _clamp((years or 0.0) / 5.0)
    latent = _clamp(0.5 + 0.3 * low_scrutiny + 0.2 * age)  # in [0.5, 1.0]
    bug = _clamp(crash_surface * neglect * latent)

    if stars is not None:
        if stars >= 3000:
            reasons.append(f"{stars}★ — very popular, likely well-tested")
        elif stars >= 50:
            reasons.append(f"{stars}★")
        else:
            reasons.append(f"{stars}★ — niche")

    # --- tractability gate ----------------------------------------------------
    months_push = _months_between(m.pushed_at, now)
    gate = _activity_gate(months_push)
    if m.archived or m.disabled:
        gate = 0.0
        reasons.append("ARCHIVED/disabled — excluded")
    elif months_push is not None:
        if months_push <= 12:
            reasons.append(f"active ({months_push:.0f}mo ago)")
        elif months_push >= 30:
            reasons.append(f"abandoned ({months_push:.0f}mo) — excluded")
        else:
            reasons.append(f"slowing ({months_push:.0f}mo ago)")

    fork_factor = 1.0
    if m.is_fork and not (rec.used_by_zed or rec.used_by_emacs):
        fork_factor = 0.85
        reasons.append("fork")
    issues_factor = 0.7 if m.has_issues is False else 1.0
    if m.has_issues is False:
        reasons.append("issues disabled")

    tractability = _clamp(gate * fork_factor * issues_factor)

    if rec.competing_impls > 1:
        reasons.append(f"{rec.competing_impls} competing impls")

    # Multiplicative: impact modulates (floor 0.3 so a great niche target still
    # scores), but crash-surface/neglect/activity can each veto. This pushes
    # already-fuzzed and no-scanner grammars down hard, as intended.
    impact_term = 0.3 + 0.7 * impact
    fuzz_priority = round(100.0 * impact_term * bug * tractability, 2)

    rec.scores = {
        "impact": round(impact, 3),
        "bug_likelihood": round(bug, 3),
        "tractability": round(tractability, 3),
        "crash_surface": crash_surface,
        "neglect": neglect,
        "already_fuzzed": float(already_fuzzed),
        "latent": round(latent, 3),
        "adoption": round(adoption, 3),
        "redmonk": round(redmonk, 3),
        "popularity": round(pop, 3),
        "low_scrutiny": round(low_scrutiny, 3),
        "age": round(age, 3),
        "activity_gate": round(gate, 3),
        "months_since_push": round(months_push, 1) if months_push is not None else -1.0,
    }
    rec.fuzz_priority = fuzz_priority
    rec.priority_reasons = reasons
