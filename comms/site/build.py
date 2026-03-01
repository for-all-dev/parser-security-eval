"""
Static site generator for parser-security-eval experiment results.

Usage:
    uv run python build.py              # build to dist/ using data/ and content/
    uv run python build.py --help       # show options
"""

from __future__ import annotations

import json
import tomllib
from collections import defaultdict
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


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(data_dir: Path) -> dict[str, Any]:
    """Load and merge all JSON and TOML files from data_dir."""
    merged: dict[str, Any] = {"experiment": {}, "runs": []}

    for path in sorted(data_dir.iterdir()):
        if path.name.startswith("_") or path.suffix not in {".json", ".toml"}:
            continue
        if path.suffix == ".json":
            raw = json.loads(path.read_text())
        else:
            with open(path, "rb") as fh:
                raw = tomllib.load(fh)
        if "experiment" in raw:
            merged["experiment"].update(raw["experiment"])
        if "runs" in raw:
            merged["runs"].extend(raw["runs"])
        console.print(f"  [dim]loaded[/dim] {path.name} "
                      f"([cyan]{len(raw.get('runs', []))}[/cyan] runs)")

    return merged


# ---------------------------------------------------------------------------
# Content loading
# ---------------------------------------------------------------------------

def load_content(content_dir: Path) -> dict[str, dict[str, Any]]:
    """Convert all .md files in content_dir to HTML with frontmatter metadata."""
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
            "meta": dict(post.metadata),
        }

    return dict(sorted(pages.items(), key=lambda kv: kv[1]["order"]))


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def compute_stats(data: dict[str, Any]) -> dict[str, Any]:
    """Derive aggregate statistics used by the templates."""
    runs: list[dict[str, Any]] = data.get("runs", [])
    if not runs:
        return {}

    targets = data["experiment"].get("targets") or sorted(
        {r["target"] for r in runs}
    )
    models = data["experiment"].get("models") or sorted(
        {r["model"] for r in runs if r.get("model")}
    )
    conditions = data["experiment"].get("conditions") or sorted(
        {r["condition"] for r in runs}
    )
    engines = data["experiment"].get("engines") or sorted(
        {r["engine"] for r in runs}
    )

    total_crashes = sum(r.get("unique_crashes", 0) for r in runs)
    ttfc_values = [
        r["time_to_first_crash_seconds"]
        for r in runs
        if r.get("time_to_first_crash_seconds") is not None
    ]

    # Crashes-per-CPU-hour grouped by target / model / condition
    rate_groups: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for r in runs:
        cpu = r.get("cpu_hours", 0) or 0
        crashes = r.get("unique_crashes", 0) or 0
        rate = crashes / cpu if cpu > 0 else 0.0
        key = (r["target"], r.get("model") or "baseline", r["condition"])
        rate_groups[key].append(rate)

    avg_rates = {k: sum(v) / len(v) for k, v in rate_groups.items()}

    # Best config
    best_key = max(avg_rates, key=lambda k: avg_rates[k]) if avg_rates else None
    best_config = (
        {
            "target": best_key[0],
            "model": best_key[1],
            "condition": best_key[2],
            "rate": avg_rates[best_key],
        }
        if best_key
        else None
    )

    # Per-target crash rate bar chart data (grouped by model, AI conditions only)
    ai_conditions = [c for c in conditions if c not in {"oss-fuzz-baseline", "random-harness"}]
    crash_rate_chart = _build_crash_rate_chart(
        runs, targets, models, ai_conditions, avg_rates
    )

    # Cycle-comparison chart (30min-cycles vs 2hr-continuous, per model)
    cycle_chart = _build_cycle_comparison_chart(runs, models, targets)

    # Coverage timeline data (per target, per run)
    timeline_chart = _build_timeline_chart(runs, targets)

    # Harness compile attempts distribution
    compile_chart = _build_compile_chart(runs)

    # Summary table rows
    table_rows = _build_table_rows(runs, avg_rates)

    return {
        "total_runs": len(runs),
        "total_crashes": total_crashes,
        "targets": targets,
        "models": models,
        "conditions": conditions,
        "engines": engines,
        "avg_ttfc_minutes": (
            round(sum(ttfc_values) / len(ttfc_values) / 60, 1) if ttfc_values else None
        ),
        "min_ttfc_minutes": (
            round(min(ttfc_values) / 60, 1) if ttfc_values else None
        ),
        "best_config": best_config,
        "crash_rate_chart": crash_rate_chart,
        "cycle_chart": cycle_chart,
        "timeline_chart": timeline_chart,
        "compile_chart": compile_chart,
        "table_rows": table_rows,
    }


def _build_crash_rate_chart(
    runs: list[dict[str, Any]],
    targets: list[str],
    models: list[str],
    conditions: list[str],
    avg_rates: dict[tuple[str, str, str], float],
) -> dict[str, Any]:
    """Bar chart: crashes/CPU-hour by target, grouped by model+condition."""
    PALETTE = [
        "rgba(59,130,246,0.85)",   # blue
        "rgba(20,184,166,0.85)",   # teal
        "rgba(168,85,247,0.85)",   # purple
        "rgba(251,146,60,0.85)",   # orange
        "rgba(34,197,94,0.85)",    # green
        "rgba(239,68,68,0.85)",    # red
    ]
    datasets = []
    i = 0
    for model in models:
        for cond in conditions:
            if cond in {"oss-fuzz-baseline", "random-harness"}:
                continue
            label = f"{_short_model(model)} / {_short_cond(cond)}"
            data = [
                round(avg_rates.get((t, model, cond), 0.0), 3)
                for t in targets
            ]
            datasets.append({
                "label": label,
                "data": data,
                "backgroundColor": PALETTE[i % len(PALETTE)],
            })
            i += 1
    # Add baselines as separate datasets with dashed border
    for cond in ["oss-fuzz-baseline"]:
        data = [
            round(avg_rates.get((t, "baseline", cond), 0.0), 3)
            for t in targets
        ]
        if any(v > 0 for v in data):
            datasets.append({
                "label": _short_cond(cond),
                "data": data,
                "backgroundColor": "rgba(148,163,184,0.5)",
                "borderColor": "rgba(148,163,184,0.9)",
                "borderWidth": 2,
                "borderDash": [4, 4],
            })

    return {"labels": targets, "datasets": datasets}


def _build_cycle_comparison_chart(
    runs: list[dict[str, Any]],
    models: list[str],
    targets: list[str],
) -> dict[str, Any]:
    """
    Grouped bar chart: 30min-cycles vs 2hr-continuous crashes/cpu-hour per model
    (averaged across targets).
    """
    CONDS = ["30min-cycles", "2hr-continuous"]
    COLORS = {
        "30min-cycles": "rgba(59,130,246,0.85)",
        "2hr-continuous": "rgba(251,146,60,0.85)",
    }
    # avg rate per model+condition across all targets
    bucket: dict[tuple[str, str], list[float]] = defaultdict(list)
    for r in runs:
        model = r.get("model")
        if not model or r["condition"] not in CONDS:
            continue
        cpu = r.get("cpu_hours", 0) or 0
        crashes = r.get("unique_crashes", 0) or 0
        rate = crashes / cpu if cpu > 0 else 0.0
        bucket[(model, r["condition"])].append(rate)

    datasets = []
    for cond in CONDS:
        data = []
        for m in models:
            vals = bucket.get((m, cond), [])
            data.append(round(sum(vals) / len(vals), 3) if vals else 0.0)
        datasets.append({
            "label": _short_cond(cond),
            "data": data,
            "backgroundColor": COLORS[cond],
        })

    return {
        "labels": [_short_model(m) for m in models],
        "datasets": datasets,
    }


def _build_timeline_chart(
    runs: list[dict[str, Any]],
    targets: list[str],
) -> dict[str, dict[str, Any]]:
    """
    Per-target dict of Chart.js line chart data for coverage over time.
    Returns {target: {coverage_chart, crash_chart}}.
    """
    LINE_COLORS = [
        ("#3b82f6", "rgba(59,130,246,0.12)"),    # blue
        ("#14b8a6", "rgba(20,184,166,0.12)"),    # teal
        ("#a855f7", "rgba(168,85,247,0.12)"),    # purple
        ("#fb923c", "rgba(251,146,60,0.12)"),    # orange
        ("#22c55e", "rgba(34,197,94,0.12)"),     # green
        ("#f87171", "rgba(248,113,113,0.12)"),   # red
        ("#94a3b8", "rgba(148,163,184,0.12)"),   # slate
    ]
    result: dict[str, dict[str, Any]] = {}

    for target in targets:
        target_runs = [r for r in runs if r["target"] == target and r.get("timeline")]
        cov_datasets: list[dict[str, Any]] = []
        crash_datasets: list[dict[str, Any]] = []

        for idx, r in enumerate(target_runs):
            timeline = r["timeline"]
            border_color, bg_color = LINE_COLORS[idx % len(LINE_COLORS)]
            label = _run_label(r)
            pts_cov = [
                {"x": round(pt["time_seconds"] / 60, 1), "y": pt["coverage_pct"]}
                for pt in timeline
            ]
            pts_crash = [
                {"x": round(pt["time_seconds"] / 60, 1), "y": pt["crashes"]}
                for pt in timeline
            ]
            cov_datasets.append({
                "label": label,
                "data": pts_cov,
                "borderColor": border_color,
                "backgroundColor": bg_color,
                "fill": False,
                "tension": 0.3,
                "pointRadius": 3,
            })
            crash_datasets.append({
                "label": label,
                "data": pts_crash,
                "borderColor": border_color,
                "backgroundColor": bg_color,
                "fill": False,
                "tension": 0.3,
                "stepped": True,
                "pointRadius": 3,
            })

        result[target] = {
            "coverage": {"datasets": cov_datasets},
            "crashes": {"datasets": crash_datasets},
        }

    return result


def _build_compile_chart(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Horizontal bar chart: mean compile attempts per model."""
    bucket: dict[str, list[int]] = defaultdict(list)
    for r in runs:
        model = r.get("model")
        attempts = r.get("harness_compile_attempts")
        if model and attempts is not None:
            bucket[model].append(attempts)

    labels = sorted(bucket.keys(), key=_short_model)
    data = [round(sum(v) / len(v), 2) for v in [bucket[m] for m in labels]]
    return {
        "labels": [_short_model(m) for m in labels],
        "datasets": [{
            "label": "Mean compile attempts",
            "data": data,
            "backgroundColor": [
                "rgba(59,130,246,0.85)",
                "rgba(20,184,166,0.85)",
                "rgba(168,85,247,0.85)",
            ][: len(labels)],
        }],
    }


def _build_table_rows(
    runs: list[dict[str, Any]],
    avg_rates: dict[tuple[str, str, str], float],
) -> list[dict[str, Any]]:
    """Flatten runs into table-friendly dicts."""
    rows = []
    for r in runs:
        cpu = r.get("cpu_hours", 0) or 0
        crashes = r.get("unique_crashes", 0) or 0
        rate = round(crashes / cpu, 3) if cpu > 0 else 0.0
        ttfc = r.get("time_to_first_crash_seconds")
        compile_attempts = r.get("harness_compile_attempts")
        rows.append({
            "id": r["id"],
            "target": r["target"],
            "model": r.get("model") or "—",
            "engine": r.get("engine", ""),
            "condition": r["condition"],
            "replicate": r.get("replicate", ""),
            "crashes": crashes,
            "cpu_hours": round(cpu, 2),
            "rate": rate,
            "coverage_pct": r.get("coverage_pct", ""),
            "compile_attempts": "" if compile_attempts is None else compile_attempts,
            "ttfc_minutes": round(ttfc / 60, 1) if ttfc is not None else "—",
        })
    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_model(model: str) -> str:
    return (
        model.replace("claude-", "")
          .replace("-4-6", "")
          .replace("-4-5", "")
          .replace("-20251001", "")
    )


def _short_cond(cond: str) -> str:
    return {
        "30min-cycles": "30-min cycles",
        "2hr-continuous": "2-hr continuous",
        "oss-fuzz-baseline": "OSS-Fuzz",
        "random-harness": "random",
    }.get(cond, cond)


def _run_label(r: dict[str, Any]) -> str:
    parts = [r["target"]]
    if r.get("model"):
        parts.append(_short_model(r["model"]))
    parts.append(_short_cond(r["condition"]))
    if r.get("replicate"):
        parts.append(f"#{r['replicate']}")
    return " / ".join(parts)


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
    data = load_data(data_dir)
    is_example = "example" in data["experiment"].get("notes", "").lower()

    console.print("\n[bold]Loading content...[/bold]")
    content = load_content(content_dir)
    console.print(f"  {len(content)} content pages loaded")

    console.print("\n[bold]Computing statistics...[/bold]")
    stats = compute_stats(data)
    n_runs = stats.get("total_runs", 0)
    console.print(f"  {n_runs} runs, {stats.get('total_crashes', 0)} total crashes")

    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2)

    ctx: dict[str, Any] = {
        "experiment": data["experiment"],
        "stats": stats,
        "content": content,
        "is_example": is_example,
        "pages": [
            {"id": "index",    "title": "Overview",  "href": "index.html"},
            {"id": "results",  "title": "Results",   "href": "results.html"},
            {"id": "coverage", "title": "Coverage",  "href": "coverage.html"},
        ],
    }

    pages_to_render = [
        ("index.html.j2",    "index.html"),
        ("results.html.j2",  "results.html"),
        ("coverage.html.j2", "coverage.html"),
    ]

    console.print("\n[bold]Rendering pages...[/bold]")
    for tpl_name, out_name in pages_to_render:
        tpl = env.get_template(tpl_name)
        out_path = output_dir / out_name
        out_path.write_text(tpl.render(**ctx, current_page=out_name.replace(".html", "")))
        size_kb = round(out_path.stat().st_size / 1024, 1)
        console.print(f"  [green]✓[/green] {out_name} ({size_kb} KB)")

    # Print summary table
    table = Table(title="Build Summary", style="dim")
    table.add_column("Metric")
    table.add_column("Value", style="cyan")
    table.add_row("Runs", str(stats.get("total_runs", 0)))
    table.add_row("Unique crashes", str(stats.get("total_crashes", 0)))
    table.add_row("Targets", ", ".join(stats.get("targets", [])))
    if stats.get("best_config"):
        bc = stats["best_config"]
        table.add_row(
            "Best config",
            f"{bc['target']} / {_short_model(bc['model'])} / "
            f"{_short_cond(bc['condition'])} "
            f"({bc['rate']:.2f} crashes/cpu-hr)",
        )
    console.print(table)
    console.print(f"\n[bold green]Done![/bold green] Output → [cyan]{output_dir}[/cyan]")
    if is_example:
        console.print(
            "[yellow]⚠  Built with EXAMPLE data. "
            "Drop real experiment JSON/TOML into data/ and rebuild.[/yellow]"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.command()
def main(
    data_dir: Path = typer.Option(HERE / "data", help="Directory with JSON/TOML data files"),
    content_dir: Path = typer.Option(HERE / "content", help="Directory with .md content files"),
    output_dir: Path = typer.Option(HERE / "dist", help="Output directory"),
    templates_dir: Path = typer.Option(HERE / "templates", help="Jinja2 templates directory"),
) -> None:
    """Build the experiment results static site."""
    build_site(data_dir, content_dir, output_dir, templates_dir)


if __name__ == "__main__":
    app()
