"""
Static site generator for parser-security-eval experiment results.

Accepts two data formats from the experiment framework (see data/schema.md):
  - manifest.json   — ExperimentManifest JSON (always present after a run starts)
  - analysis.json   — ExperimentAnalysis JSON (from `experiment analyze --json`)

Usage:
    uv run python build.py              # build to dist/
    uv run python build.py --help       # show options
"""

from __future__ import annotations

import json
import tomllib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import frontmatter
import markdown as md_lib
import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(add_completion=False)
console = Console()

HERE = Path(__file__).parent

# task_kwargs keys that aren't interesting enough to surface in the UI
_BORING_KWARGS = frozenset({
    "benchmark_dir", "targets_root", "ready_only", "seed",
})


# ---------------------------------------------------------------------------
# Model-name helpers
# ---------------------------------------------------------------------------

def _short_model(model: str) -> str:
    """anthropic/claude-sonnet-4-6  →  sonnet"""
    if "/" in model:
        model = model.split("/", 1)[1]
    return (
        model.replace("claude-", "")
             .replace("-4-6", "")
             .replace("-4-5", "")
             .replace("-20251001", "")
    )


def _provider(model: str) -> str:
    return model.split("/")[0] if "/" in model else "unknown"


def _interesting_kwargs(task_kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v for k, v in task_kwargs.items()
        if k not in _BORING_KWARGS
        and not k.endswith("_dir")
        and not k.endswith("_root")
    }


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _detect_type(data: dict[str, Any]) -> str:
    """Return 'manifest', 'analysis', or 'unknown'."""
    if (
        "experiment_name" in data
        and "runs" in data
        and isinstance(data.get("runs"), dict)
    ):
        return "manifest"
    if "leaderboard" in data and "task_type" in data:
        return "analysis"
    return "unknown"


def load_data_dir(
    data_dir: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Scan data_dir and return (manifest, analysis). Files starting with _ are skipped."""
    manifest: dict[str, Any] | None = None
    analysis: dict[str, Any] | None = None

    for path in sorted(data_dir.iterdir()):
        if path.name.startswith("_") or path.suffix not in {".json", ".toml"}:
            continue
        if path.suffix == ".json":
            data: dict[str, Any] = json.loads(path.read_text())
        else:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)

        kind = _detect_type(data)
        if kind == "manifest":
            manifest = data
            n = len(data.get("runs", {}))
            console.print(f"  [dim]manifest[/dim] {path.name} ([cyan]{n}[/cyan] runs)")
        elif kind == "analysis":
            analysis = data
            n = len(data.get("leaderboard", []))
            console.print(f"  [dim]analysis[/dim] {path.name} ([cyan]{n}[/cyan] models)")
        else:
            console.print(f"  [yellow]skipped[/yellow] {path.name} (unrecognised format)")

    return manifest, analysis


# ---------------------------------------------------------------------------
# Content loading
# ---------------------------------------------------------------------------

def load_content(content_dir: Path) -> dict[str, dict[str, Any]]:
    md_converter = md_lib.Markdown(
        extensions=["extra", "tables", "toc", "fenced_code"]
    )
    pages: dict[str, dict[str, Any]] = {}
    for path in sorted(content_dir.glob("*.md")):
        post = frontmatter.load(path)
        md_converter.reset()
        html = md_converter.convert(post.content)
        key = path.stem
        pages[key] = {
            "title": post.get("title", key.replace("-", " ").title()),
            "order": int(post.get("order", 99)),
            "html": html,
        }
    return dict(sorted(pages.items(), key=lambda kv: kv[1]["order"]))


# ---------------------------------------------------------------------------
# Duration helpers
# ---------------------------------------------------------------------------

def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _duration_minutes(started: str | None, ended: str | None) -> float | None:
    s, e = _parse_dt(started), _parse_dt(ended)
    if s and e:
        return round((e - s).total_seconds() / 60, 1)
    return None


# ---------------------------------------------------------------------------
# Statistics from manifest
# ---------------------------------------------------------------------------

def _status_counts(runs: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for r in runs.values():
        counts[r.get("status", "pending")] += 1
    return dict(counts)


def _build_status_donut(counts: dict[str, int]) -> dict[str, Any]:
    labels = ["Completed", "Failed", "Running", "Pending"]
    keys   = ["completed", "failed", "running", "pending"]
    colors = [
        "rgba(52,211,153,0.85)",   # green
        "rgba(248,113,113,0.85)",  # red
        "rgba(251,191,36,0.85)",   # amber
        "rgba(148,163,184,0.4)",   # slate
    ]
    return {
        "labels": labels,
        "datasets": [{
            "data": [counts.get(k, 0) for k in keys],
            "backgroundColor": colors,
            "borderWidth": 2,
            "borderColor": "#0b0f1a",
        }],
    }


def _build_status_matrix(
    runs: dict[str, Any],
) -> dict[str, Any]:
    """Build a model × target status grid for the overview page."""
    # Collect all models and targets in order
    models_seen: list[str] = []
    targets_seen: list[str] = []
    for r in runs.values():
        m = r.get("model", "")
        t = r.get("target") or "—"
        if m and m not in models_seen:
            models_seen.append(m)
        if t not in targets_seen:
            targets_seen.append(t)

    # Build cell data
    cell_map: dict[tuple[str, str], dict[str, Any]] = {}
    for r in runs.values():
        m = r.get("model", "")
        t = r.get("target") or "—"
        status = r.get("status", "pending")
        dur = _duration_minutes(r.get("started_at"), r.get("completed_at"))
        cell_map[(m, t)] = {
            "model": m,
            "model_short": _short_model(m),
            "target": t,
            "status": status,
            "duration_min": dur,
            "run_id": r.get("run_id", "")[:8],
            "error": (r.get("error") or "")[:80],
        }

    cells = [
        cell_map.get((m, t), {"model": m, "target": t, "status": "not_scheduled"})
        for m in models_seen
        for t in targets_seen
    ]
    return {
        "models": [_short_model(m) for m in models_seen],
        "targets": targets_seen,
        "cells": cells,
    }


def _build_runs_table(runs: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in runs.values():
        kw = _interesting_kwargs(r.get("task_kwargs", {}))
        dur = _duration_minutes(r.get("started_at"), r.get("completed_at"))
        rows.append({
            "run_id": r.get("run_id", "")[:8],
            "model": r.get("model", ""),
            "model_short": _short_model(r.get("model", "")),
            "target": r.get("target") or "—",
            "repetition": r.get("repetition", 0),
            "status": r.get("status", "pending"),
            "kwargs": kw,
            "duration_min": dur,
            "error": (r.get("error") or "")[:100],
            "eval_log": bool(r.get("eval_log_path")),
        })
    return rows


def _build_duration_chart(runs: dict[str, Any]) -> dict[str, Any] | None:
    """Bar chart: completion duration per run (completed runs only)."""
    labels: list[str] = []
    data: list[float] = []
    colors: list[str] = []
    MODEL_COLORS = [
        "rgba(59,130,246,0.8)",
        "rgba(20,184,166,0.8)",
        "rgba(168,85,247,0.8)",
        "rgba(251,146,60,0.8)",
    ]
    models_seen: list[str] = []

    for r in runs.values():
        if r.get("status") != "completed":
            continue
        dur = _duration_minutes(r.get("started_at"), r.get("completed_at"))
        if dur is None:
            continue
        m = r.get("model", "")
        t = r.get("target") or "—"
        if m not in models_seen:
            models_seen.append(m)
        labels.append(f"{_short_model(m)} / {t}")
        data.append(dur)
        colors.append(MODEL_COLORS[models_seen.index(m) % len(MODEL_COLORS)])

    if not data:
        return None
    return {
        "labels": labels,
        "datasets": [{
            "label": "Duration (minutes)",
            "data": data,
            "backgroundColor": colors,
        }],
    }


# ---------------------------------------------------------------------------
# Statistics from analysis
# ---------------------------------------------------------------------------

_PALETTE = [
    "rgba(59,130,246,0.85)",
    "rgba(20,184,166,0.85)",
    "rgba(168,85,247,0.85)",
    "rgba(251,146,60,0.85)",
    "rgba(34,197,94,0.85)",
    "rgba(239,68,68,0.85)",
]


def _build_leaderboard_chart(leaderboard: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [_short_model(m["model"]) for m in leaderboard]
    data = [round(m["mean_score"], 4) for m in leaderboard]
    colors = [_PALETTE[i % len(_PALETTE)] for i in range(len(labels))]
    return {
        "labels": labels,
        "datasets": [{"label": "Mean score", "data": data, "backgroundColor": colors}],
    }


def _build_pipeline_chart(leaderboard: list[dict[str, Any]]) -> dict[str, Any]:
    """Grouped bar: patch_applies / compiles / crash_eliminated / tests_pass rates per model."""
    stages = ["patch_applies_rate", "compiles_rate", "crash_eliminated_rate", "tests_pass_rate"]
    stage_labels = ["Patch Applies", "Compiles", "Crash Eliminated", "Tests Pass"]
    datasets: list[dict[str, Any]] = []
    for i, entry in enumerate(leaderboard):
        datasets.append({
            "label": _short_model(entry["model"]),
            "data": [round(entry.get(s, 0.0) * 100, 1) for s in stages],
            "backgroundColor": _PALETTE[i % len(_PALETTE)],
        })
    return {"labels": stage_labels, "datasets": datasets}


def _build_target_breakdown_chart(target_breakdown: list[dict[str, Any]]) -> dict[str, Any]:
    targets = sorted({e["target"] for e in target_breakdown})
    models  = sorted({e["model"]  for e in target_breakdown})
    lookup = {(e["model"], e["target"]): e["mean_score"] for e in target_breakdown}
    datasets: list[dict[str, Any]] = []
    for i, m in enumerate(models):
        datasets.append({
            "label": _short_model(m),
            "data": [round(lookup.get((m, t), 0.0), 4) for t in targets],
            "backgroundColor": _PALETTE[i % len(_PALETTE)],
        })
    return {"labels": targets, "datasets": datasets}


def _build_cwe_chart(cwe_breakdown: list[dict[str, Any]]) -> dict[str, Any]:
    cwes   = sorted({e["cwe"]   for e in cwe_breakdown})
    models = sorted({e["model"] for e in cwe_breakdown})
    lookup = {(e["model"], e["cwe"]): e["mean_score"] for e in cwe_breakdown}
    datasets: list[dict[str, Any]] = []
    for i, m in enumerate(models):
        datasets.append({
            "label": _short_model(m),
            "data": [round(lookup.get((m, c), 0.0), 4) for c in cwes],
            "backgroundColor": _PALETTE[i % len(_PALETTE)],
        })
    return {"labels": cwes, "datasets": datasets}


def _build_difficulty_chart(difficulty_breakdown: list[dict[str, Any]]) -> dict[str, Any]:
    # Keep difficulty in natural order if possible
    DIFF_ORDER = {"easy": 0, "medium": 1, "hard": 2, "very_hard": 3}
    diffs  = sorted(
        {e["difficulty"] for e in difficulty_breakdown},
        key=lambda d: DIFF_ORDER.get(d, 99),
    )
    models = sorted({e["model"] for e in difficulty_breakdown})
    lookup = {(e["model"], e["difficulty"]): e["mean_score"] for e in difficulty_breakdown}
    datasets: list[dict[str, Any]] = []
    for i, m in enumerate(models):
        datasets.append({
            "label": _short_model(m),
            "data": [round(lookup.get((m, d), 0.0), 4) for d in diffs],
            "borderColor": _PALETTE[i % len(_PALETTE)].replace("0.85", "1"),
            "backgroundColor": _PALETTE[i % len(_PALETTE)].replace("0.85", "0.15"),
            "tension": 0.3,
            "fill": False,
            "pointRadius": 5,
        })
    return {"labels": diffs, "datasets": datasets}


def _build_token_chart(leaderboard: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [_short_model(m["model"]) for m in leaderboard]
    return {
        "labels": labels,
        "datasets": [
            {
                "label": "Input tokens (mean)",
                "data": [round(m.get("mean_input_tokens", 0)) for m in leaderboard],
                "backgroundColor": "rgba(59,130,246,0.75)",
            },
            {
                "label": "Output tokens (mean)",
                "data": [round(m.get("mean_output_tokens", 0)) for m in leaderboard],
                "backgroundColor": "rgba(20,184,166,0.75)",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Top-level compute_stats
# ---------------------------------------------------------------------------

def compute_stats(
    manifest: dict[str, Any] | None,
    analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    stats: dict[str, Any] = {}

    # ── Manifest-derived stats ────────────────────────────────────────────
    if manifest:
        runs = manifest.get("runs", {})
        config = manifest.get("config", {})
        counts = _status_counts(runs)

        stats["task_type"]     = config.get("task", "unknown")
        stats["total_runs"]    = len(runs)
        stats["completed"]     = counts.get("completed", 0)
        stats["failed"]        = counts.get("failed", 0)
        stats["running"]       = counts.get("running", 0)
        stats["pending"]       = counts.get("pending", 0)

        # Timing
        completed_runs = [
            r for r in runs.values()
            if r.get("status") == "completed"
            and r.get("started_at") and r.get("completed_at")
        ]
        durations = [
            _duration_minutes(r["started_at"], r["completed_at"])
            for r in completed_runs
            if _duration_minutes(r["started_at"], r["completed_at"]) is not None
        ]
        if durations:
            stats["mean_duration_min"] = round(sum(durations) / len(durations), 1)
            stats["min_duration_min"]  = round(min(durations), 1)
            stats["max_duration_min"]  = round(max(durations), 1)

        stats["status_donut"]   = _build_status_donut(counts)
        stats["status_matrix"]  = _build_status_matrix(runs)
        stats["runs_table"]     = _build_runs_table(runs)
        stats["duration_chart"] = _build_duration_chart(runs)

        # Grid summary from config
        grid = config.get("grid", {})
        stats["grid_models"]  = grid.get("model", [])
        stats["grid_targets"] = [t for t in (grid.get("target") or []) if t]
        stats["grid_extra"]   = grid.get("extra", {})

        # Defaults
        defaults = config.get("defaults", {})
        stats["engine"]        = defaults.get("engine", "")
        stats["fuzz_duration"] = defaults.get("fuzz_duration")
        stats["max_rounds"]    = defaults.get("max_rounds")
        stats["round_duration"]= defaults.get("round_duration")

    # ── Analysis-derived stats ────────────────────────────────────────────
    if analysis:
        if not stats.get("task_type"):
            stats["task_type"] = analysis.get("task_type", "unknown")

        leaderboard        = analysis.get("leaderboard", [])
        cwe_breakdown      = analysis.get("cwe_breakdown", [])
        difficulty_breakdown = analysis.get("difficulty_breakdown", [])
        target_breakdown   = analysis.get("target_breakdown", [])

        stats["leaderboard"]          = leaderboard
        stats["cwe_breakdown"]        = cwe_breakdown
        stats["difficulty_breakdown"] = difficulty_breakdown
        stats["target_breakdown"]     = target_breakdown

        if leaderboard:
            stats["leaderboard_chart"]  = _build_leaderboard_chart(leaderboard)
            stats["token_chart"]        = _build_token_chart(leaderboard)
            best = max(leaderboard, key=lambda m: m["mean_score"])
            stats["best_model"]         = _short_model(best["model"])
            stats["best_score"]         = round(best["mean_score"], 3)

            # Patching-specific
            if analysis.get("task_type") == "patching" and leaderboard[0].get("patch_applies_rate") is not None:
                stats["pipeline_chart"] = _build_pipeline_chart(leaderboard)

        if target_breakdown:
            stats["target_chart"] = _build_target_breakdown_chart(target_breakdown)
        if cwe_breakdown:
            stats["cwe_chart"] = _build_cwe_chart(cwe_breakdown)
        if difficulty_breakdown:
            stats["difficulty_chart"] = _build_difficulty_chart(difficulty_breakdown)

    return stats


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def build_site(
    data_dir: Path,
    content_dir: Path,
    output_dir: Path,
    templates_dir: Path,
) -> None:
    console.print(Panel("[bold]parser-security-eval site builder[/bold]", style="blue"))

    console.print("\n[bold]Loading data...[/bold]")
    manifest, analysis = load_data_dir(data_dir)
    if manifest is None and analysis is None:
        console.print("  [yellow]No data files found — building empty site.[/yellow]")

    is_example = bool(
        (manifest and manifest.get("_example"))
        or (analysis and analysis.get("_example"))
    )

    console.print("\n[bold]Loading content...[/bold]")
    content = load_content(content_dir)
    console.print(f"  {len(content)} content page(s) loaded")

    console.print("\n[bold]Computing statistics...[/bold]")
    stats = compute_stats(manifest, analysis)
    console.print(
        f"  {stats.get('total_runs', 0)} runs — "
        f"{stats.get('completed', 0)} completed / "
        f"{stats.get('failed', 0)} failed / "
        f"{stats.get('pending', 0)} pending"
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html"]),
    )

    # Experiment metadata for the hero
    exp_meta: dict[str, Any] = {}
    if manifest:
        cfg = manifest.get("config", {})
        exp_meta = {
            "name":        cfg.get("description") or manifest.get("experiment_name", ""),
            "id":          manifest.get("experiment_name", ""),
            "task":        cfg.get("task", ""),
            "description": cfg.get("description", ""),
            "updated_at":  manifest.get("updated_at", ""),
            "created_at":  manifest.get("created_at", ""),
        }
    elif analysis:
        exp_meta = {
            "name":   analysis.get("experiment_name", ""),
            "id":     analysis.get("experiment_name", ""),
            "task":   analysis.get("task_type", ""),
        }

    ctx: dict[str, Any] = {
        "experiment": exp_meta,
        "manifest":   manifest,
        "analysis":   analysis,
        "stats":      stats,
        "content":    content,
        "is_example": is_example,
        "pages": [
            {"id": "index",      "title": "Overview",    "href": "index.html"},
            {"id": "results",    "title": "Results",     "href": "results.html"},
            {"id": "breakdowns", "title": "Breakdowns",  "href": "breakdowns.html"},
        ],
    }

    pages_to_render = [
        ("index.html.j2",      "index.html"),
        ("results.html.j2",    "results.html"),
        ("breakdowns.html.j2", "breakdowns.html"),
    ]

    console.print("\n[bold]Rendering pages...[/bold]")
    for tpl_name, out_name in pages_to_render:
        tpl = env.get_template(tpl_name)
        out_path = output_dir / out_name
        out_path.write_text(
            tpl.render(**ctx, current_page=out_name.replace(".html", ""))
        )
        size_kb = round(out_path.stat().st_size / 1024, 1)
        console.print(f"  [green]✓[/green] {out_name} ({size_kb} KB)")

    # Summary table
    table = Table(title="Build Summary", style="dim")
    table.add_column("Metric")
    table.add_column("Value", style="cyan")
    table.add_row("Experiment", exp_meta.get("id", "—"))
    table.add_row("Task type",  stats.get("task_type", "—"))
    table.add_row("Total runs", str(stats.get("total_runs", 0)))
    table.add_row(
        "Status",
        f"{stats.get('completed',0)} completed / "
        f"{stats.get('failed',0)} failed / "
        f"{stats.get('running',0)} running / "
        f"{stats.get('pending',0)} pending",
    )
    if stats.get("best_model"):
        table.add_row("Best model", f"{stats['best_model']} (score {stats['best_score']})")
    console.print(table)

    console.print(f"\n[bold green]Done![/bold green] Output → [cyan]{output_dir}[/cyan]")
    if is_example:
        console.print(
            "[yellow]⚠  Built with EXAMPLE data. "
            "Point --data-dir at your actual results directory and rebuild.[/yellow]"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.command()
def main(
    data_dir: Path = typer.Option(HERE / "data", help="Directory with manifest.json / analysis.json"),
    content_dir: Path = typer.Option(HERE / "content", help="Directory with .md content files"),
    output_dir: Path = typer.Option(HERE / "dist", help="Output directory"),
    templates_dir: Path = typer.Option(HERE / "templates", help="Jinja2 templates directory"),
) -> None:
    """Build the experiment results static site."""
    build_site(data_dir, content_dir, output_dir, templates_dir)


if __name__ == "__main__":
    app()
