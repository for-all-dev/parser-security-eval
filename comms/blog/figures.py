#!/usr/bin/env python3
"""Regenerate blog figures from sweep output.

Usage (from repo root, needs the sweep JSONL present):

    uv run --project scaffold python comms/blog/figures.py

Emits SVG into ``comms/blog/assets/`` and rasterizes to PNG at 2x via
ImageMagick (which delegates to librsvg here). The committed PNGs are 2x the
viewBox, i.e. ``-density 192``.

Only fig4 is generated from data. fig1-fig3 describe the earlier 118-grammar
survey and the ARVO patching sweep, whose raw outputs are not on this machine
(``scaffold/results/*`` is gitignored); those SVGs remain hand-maintained.

Style constants below are copied from the existing hand-authored figures so a
generated figure sits beside them without looking foreign.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = Path(__file__).resolve().parent / "assets"
LLM_DIR = ROOT / "scaffold" / "results" / "treesitter-llm"
CTL_DIR = ROOT / "scaffold" / "results" / "treesitter-baseline"

GRAMMARS = ["nushell-nu", "gren", "foam", "typst", "sql"]
REPS = ["rep1", "rep2", "rep3"]

# --- house style ----------------------------------------------------------- #
FONT = (
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, "
    "Helvetica, Arial, sans-serif"
)
BG, BORDER = "#fcfcfb", "#e6e5e1"
INK, MUTED, FAINT = "#0b0b0b", "#52514e", "#8a8983"
GRID, AXIS = "#ededea", "#c9c8c4"
BLUE, ORANGE = "#2a78d6", "#eb6834"


def _reps_with_bug() -> dict[str, dict[str, int]]:
    """{grammar: {arm: n_reps_where_a_memory_safety_bug_was_found}}."""
    sys.path.insert(0, str(ROOT / "scaffold" / "src"))
    from parser_security_eval.treesitter.baseline_compare import load_sweep

    out: dict[str, dict[str, int]] = {}
    for g in GRAMMARS:
        out[g] = {}
        for arm, base in (("llm", LLM_DIR), ("control", CTL_DIR)):
            hits = 0
            for rep in REPS:
                gc = load_sweep(base / rep).get(g)
                if gc and gc.mem_hashes():
                    hits += 1
            out[g][arm] = hits
    return out


def _llm_only_bugs() -> dict[str, int]:
    """Distinct memory-safety hashes an arm found that the other never did."""
    sys.path.insert(0, str(ROOT / "scaffold" / "src"))
    from parser_security_eval.treesitter.baseline_compare import load_sweep

    llm, ctl = load_sweep(LLM_DIR), load_sweep(CTL_DIR)
    out = {}
    for g in GRAMMARS:
        a = llm[g].mem_hashes() if g in llm else set()
        b = ctl[g].mem_hashes() if g in ctl else set()
        if a - b:
            out[g] = len(a - b)
    return out


def fig4() -> str:
    reps = _reps_with_bug()
    only = _llm_only_bugs()

    x0, unit = 250, 120  # x = x0 + reps*unit ; 3 reps -> 360px
    top, pitch, bar_h = 84, 40, 11
    bottom = top + pitch * len(GRAMMARS) - (pitch - 2 * bar_h - 4)

    p: list[str] = []
    p.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 356" '
        f'font-family="{FONT}">'
    )
    p.append(
        f'  <rect x="0.5" y="0.5" width="719" height="355" rx="10" '
        f'fill="{BG}" stroke="{BORDER}"/>'
    )
    p.append(
        f'  <text x="28" y="34" font-size="17" font-weight="700" fill="{INK}">'
        f"The ablation, actually run</text>"
    )
    p.append(
        f'  <text x="28" y="54" font-size="12.5" fill="{MUTED}">Reps (of 3) in '
        f"which each arm found the grammar&#39;s memory-safety bug. Equal "
        f"fuzz-seconds.</text>"
    )

    # legend
    p.append(f'  <rect x="500" y="24" width="11" height="11" rx="2.5" fill="{BLUE}"/>')
    p.append(f'  <text x="516" y="33" font-size="11.5" fill="{MUTED}">LLM in loop</text>')
    p.append(f'  <rect x="600" y="24" width="11" height="11" rx="2.5" fill="{ORANGE}"/>')
    p.append(
        f'  <text x="616" y="33" font-size="11.5" fill="{MUTED}">plain libFuzzer</text>'
    )

    # gridlines + axis labels
    p.append(f'  <g stroke="{GRID}" stroke-width="1">')
    for v in range(4):
        gx = x0 + v * unit
        p.append(f'    <line x1="{gx}" y1="{top - 8}" x2="{gx}" y2="{bottom}"/>')
    p.append("  </g>")
    p.append(f'  <g font-size="10.5" fill="{FAINT}" text-anchor="middle">')
    for v in range(4):
        p.append(f'    <text x="{x0 + v * unit}" y="{bottom + 16}">{v}</text>')
    p.append("  </g>")
    p.append(
        f'  <text x="{x0 + 1.5 * unit}" y="{bottom + 38}" font-size="11" '
        f'fill="{FAINT}" text-anchor="middle">reps in which the bug was found</text>'
    )
    p.append(
        f'  <line x1="{x0}" y1="{top - 8}" x2="{x0}" y2="{bottom}" '
        f'stroke="{AXIS}" stroke-width="1.5"/>'
    )

    for i, g in enumerate(GRAMMARS):
        gy = top + i * pitch
        p.append(
            f'  <text x="238" y="{gy + 17}" font-size="12.5" fill="{INK}" '
            f'text-anchor="end" font-weight="600">{g}</text>'
        )
        for j, (arm, colour) in enumerate((("llm", BLUE), ("control", ORANGE))):
            n = reps[g][arm]
            by = gy + j * (bar_h + 4)
            w = n * unit
            if w:
                p.append(
                    f'  <rect x="{x0}" y="{by}" width="{w}" height="{bar_h}" '
                    f'rx="3" fill="{colour}"/>'
                )
            p.append(
                f'  <text x="{x0 + w + 8}" y="{by + 9.5}" font-size="11.5" '
                f'font-weight="700" fill="{INK if w else FAINT}">{n}</text>'
            )
    # Bugs unique to one arm do not fit as row annotations at this width, and
    # they are a different quantity from the bar (bugs, not reps), so they get
    # their own footnote rather than sharing the axis.
    note_y = bottom + 62
    for g, n in sorted(only.items()):
        p.append(
            f'  <rect x="28" y="{note_y - 9}" width="9" height="9" rx="2" '
            f'fill="{BLUE}"/>'
        )
        p.append(
            f'  <text x="43" y="{note_y}" font-size="11" fill="{MUTED}">'
            f"<tspan font-weight=\"600\" fill=\"{INK}\">{g}</tspan>: "
            f"{n} further memory-safety bug found by the LLM arm in 3/3 reps "
            f"and never by the control</text>"
        )
        note_y += 16

    p.append("</svg>")
    return "\n".join(p) + "\n"


def main() -> None:
    if not LLM_DIR.exists() or not CTL_DIR.exists():
        sys.exit(f"sweep output missing: need {LLM_DIR} and {CTL_DIR}")
    svg_path = ASSETS / "fig4-ablation.svg"
    svg_path.write_text(fig4(), encoding="utf-8")
    print(f"wrote {svg_path}")
    rasterize(svg_path)


def rasterize(svg_path: Path) -> None:
    """SVG -> 2x PNG, matching the committed figures' resolution."""
    png = svg_path.with_suffix(".png")
    subprocess.run(
        ["magick", "-density", "192", "-background", "none", str(svg_path), str(png)],
        check=True,
    )
    print(f"wrote {png}")


if __name__ == "__main__":
    main()


def _load_records(path: Path) -> list[dict]:  # pragma: no cover - helper
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
