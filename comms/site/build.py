"""
Static site generator for parser-security-eval experiment results.

Primary data source (auto-detected by file structure):
  - results.json  — written by the experiment framework after each run;
                    top-level counts + array of non-pending runs with scores.
  - manifest.json — supplementary; provides full grid config and timing data.
  - analysis.json — written by `experiment analyze --json`; provides
                    leaderboard and CWE/difficulty/target breakdowns.

Usage:
    uv run python build.py              # builds from scaffold/results/ v2 dirs
    uv run python build.py --data-dir ../../scaffold/results/patching-model-sweep-v2 \\
                            --data-dir ../../scaffold/results/fuzzing-baseline-v2
    uv run python build.py --help
"""

from __future__ import annotations

import json
import tomllib
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import frontmatter
import markdown as md_lib
import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(add_completion=False)
console = Console()

HERE = Path(__file__).parent

# task_kwargs keys not worth surfacing in the UI
_BORING_KWARGS = frozenset({"benchmark_dir", "targets_root", "ready_only", "seed"})


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


def _interesting_kwargs(task_kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v for k, v in task_kwargs.items()
        if k not in _BORING_KWARGS
        and not k.endswith("_dir")
        and not k.endswith("_root")
    }


def _display_name(name: str, task: str) -> str:
    """Human-readable display name for an experiment."""
    return {
        "patching": "Vulnerability Patching",
        "fuzzing":  "Crash Finding (Fuzzing)",
        "harness":  "Harness Generation",
        "triage":   "Vulnerability Triage",
    }.get(task, name.replace("-", " ").replace("_", " ").title())


def _primary_score(run: dict[str, Any], task: str) -> float | None:
    """Extract the headline scalar from a run's scores dict."""
    scores = run.get("scores")
    if not scores:
        return None
    preferred: dict[str, str] = {
        "fuzzing":  "_live_fuzzing_scorer",
        "patching": "_patch_scorer",
        "harness":  "_harness_scorer",
    }
    key = preferred.get(task)
    if key and key in scores:
        metrics = scores[key]
        return metrics.get("mean", next(iter(metrics.values()), None))
    first_metrics = next(iter(scores.values()), {})
    return next(iter(first_metrics.values()), None)


def _run_kwarg_label(run: dict[str, Any]) -> str:
    """Short display label for a run's target + interesting task_kwargs."""
    parts = [run.get("target") or "—"]
    for k, v in _interesting_kwargs(run.get("task_kwargs") or {}).items():
        parts.append(f"{k}={v}")
    return " / ".join(parts)


# ---------------------------------------------------------------------------
# File-type detection
# ---------------------------------------------------------------------------

def _detect_type(data: dict[str, Any]) -> str:
    """Return 'results', 'manifest', 'analysis', or 'unknown'."""
    if (
        "total_runs" in data
        and isinstance(data.get("runs"), list)
        and ("task" in data or "experiment" in data)
    ):
        return "results"
    if "experiment_name" in data and isinstance(data.get("runs"), dict):
        return "manifest"
    if "leaderboard" in data and "task_type" in data:
        return "analysis"
    return "unknown"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data_dir(
    data_dir: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Scan data_dir for data files; return (results, manifest, analysis)."""
    results:  dict[str, Any] | None = None
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
        if kind == "results":
            results = data
            n = len(data.get("runs", []))
            console.print(
                f"  [dim]results[/dim]  {path.name} "
                f"([cyan]{data.get('completed', 0)}[/cyan] completed / "
                f"{data.get('total_runs', n)} total)"
            )
        elif kind == "manifest":
            manifest = data
            n = len(data.get("runs", {}))
            console.print(f"  [dim]manifest[/dim] {path.name} ([cyan]{n}[/cyan] runs)")
        elif kind == "analysis":
            analysis = data
            n = len(data.get("leaderboard", []))
            console.print(f"  [dim]analysis[/dim] {path.name} ([cyan]{n}[/cyan] models)")
        else:
            console.print(f"  [yellow]skipped[/yellow] {path.name} (unrecognised format)")

    return results, manifest, analysis


# ---------------------------------------------------------------------------
# Content loading
# ---------------------------------------------------------------------------

def load_content(content_dir: Path) -> dict[str, dict[str, Any]]:
    md_conv = md_lib.Markdown(extensions=["extra", "tables", "toc", "fenced_code"])
    pages: dict[str, dict[str, Any]] = {}
    for path in sorted(content_dir.glob("*.md")):
        if path.name.startswith("_"):
            continue
        post = frontmatter.load(path)
        md_conv.reset()
        html = md_conv.convert(post.content)
        key = path.stem
        pages[key] = {
            "title": post.get("title", key.replace("-", " ").title()),
            "order": int(post.get("order", 99)),
            "html": html,
        }
    return dict(sorted(pages.items(), key=lambda kv: kv[1]["order"]))


# ---------------------------------------------------------------------------
# Duration helpers (manifest timestamps only)
# ---------------------------------------------------------------------------

def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _duration_minutes(started: str | None, ended: str | None) -> float | None:
    s, e = _parse_dt(started), _parse_dt(ended)
    if s and e:
        return round((e - s).total_seconds() / 60, 1)
    return None


# ---------------------------------------------------------------------------
# Chart builders
# ---------------------------------------------------------------------------

_STATUS_COLORS = {
    "completed": "rgba(52,211,153,0.85)",
    "failed":    "rgba(248,113,113,0.85)",
    "running":   "rgba(251,191,36,0.85)",
    "pending":   "rgba(148,163,184,0.35)",
}

_PALETTE = [
    "rgba(59,130,246,0.85)",
    "rgba(20,184,166,0.85)",
    "rgba(168,85,247,0.85)",
    "rgba(251,146,60,0.85)",
    "rgba(34,197,94,0.85)",
    "rgba(239,68,68,0.85)",
]


def _build_status_donut(completed: int, failed: int, running: int, pending: int) -> dict[str, Any]:
    return {
        "labels": ["Completed", "Failed", "Running", "Pending"],
        "datasets": [{
            "data": [completed, failed, running, pending],
            "backgroundColor": [
                _STATUS_COLORS["completed"],
                _STATUS_COLORS["failed"],
                _STATUS_COLORS["running"],
                _STATUS_COLORS["pending"],
            ],
            "borderWidth": 2,
            "borderColor": "#0b0f1a",
        }],
    }


def _build_status_matrix(
    manifest_runs: dict[str, Any],
) -> dict[str, Any]:
    """Model × target grid built from manifest.
    When multiple runs share a (model, target) cell, keeps the best-scored completed run."""
    models_seen: list[str] = []
    targets_seen: list[str] = []
    for r in manifest_runs.values():
        m, t = r.get("model", ""), r.get("target") or "—"
        if m and m not in models_seen:
            models_seen.append(m)
        if t not in targets_seen:
            targets_seen.append(t)

    cell_map: dict[tuple[str, str], dict[str, Any]] = {}
    STATUS_ORDER = {"completed": 0, "running": 1, "failed": 2, "pending": 3}
    for r in manifest_runs.values():
        m, t = r.get("model", ""), r.get("target") or "—"
        status = r.get("status", "pending")
        task_kw = _interesting_kwargs(r.get("task_kwargs") or {})
        result = r.get("result") or {}
        score: float | None = None
        if result.get("scores"):
            first_scorer = next(iter(result["scores"].values()), {})
            score = next(iter(first_scorer.values()), None)
        existing = cell_map.get((m, t))
        new_rank = STATUS_ORDER.get(status, 9)
        if existing is None:
            replace = True
        else:
            old_rank = STATUS_ORDER.get(existing["status"], 9)
            if new_rank < old_rank:
                replace = True
            elif new_rank == old_rank and score is not None and (
                existing["score"] is None or score > existing["score"]
            ):
                replace = True
            else:
                replace = False
        if replace:
            cell_map[(m, t)] = {
                "model":       m,
                "model_short": _short_model(m),
                "target":      t,
                "status":      status,
                "run_id":      r.get("run_id", "")[:8],
                "score":       round(score, 3) if score is not None else None,
                "extra":       ", ".join(f"{k}={v}" for k, v in task_kw.items()) if task_kw else "",
            }

    cells = [
        cell_map.get(
            (m, t),
            {"model": m, "target": t, "status": "not_scheduled",
             "model_short": _short_model(m), "score": None},
        )
        for m in models_seen
        for t in targets_seen
    ]
    return {
        "models":  [_short_model(m) for m in models_seen],
        "targets": targets_seen,
        "cells":   cells,
    }


def _build_status_matrix_from_results(
    runs_list: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fallback matrix from results.json runs (no pending rows)."""
    models_seen: list[str] = []
    targets_seen: list[str] = []
    for r in runs_list:
        m, t = r.get("model", ""), r.get("target") or "—"
        if m and m not in models_seen:
            models_seen.append(m)
        if t not in targets_seen:
            targets_seen.append(t)

    cell_map: dict[tuple[str, str], dict[str, Any]] = {}
    STATUS_ORDER = {"completed": 0, "running": 1, "failed": 2, "pending": 3}
    for r in runs_list:
        m, t = r.get("model", ""), r.get("target") or "—"
        status = r.get("status", "pending")
        score = _primary_score(r, "")
        existing = cell_map.get((m, t))
        if existing is None or STATUS_ORDER.get(status, 9) < STATUS_ORDER.get(existing["status"], 9):
            cell_map[(m, t)] = {
                "model":       m,
                "model_short": _short_model(m),
                "target":      t,
                "status":      status,
                "run_id":      r.get("run_id", "")[:8],
                "score":       round(score, 3) if score is not None else None,
                "extra":       "",
            }

    cells = [
        cell_map.get(
            (m, t),
            {"model": m, "target": t, "status": "pending",
             "model_short": _short_model(m), "score": None},
        )
        for m in models_seen
        for t in targets_seen
    ]
    return {
        "models":  [_short_model(m) for m in models_seen],
        "targets": targets_seen,
        "cells":   cells,
    }


def _build_score_chart(
    runs_list: list[dict[str, Any]],
    task: str,
) -> dict[str, Any] | None:
    """Bar chart: primary scorer value per completed run, colored by model."""
    completed = [r for r in runs_list if r.get("status") == "completed"]
    if not completed:
        return None

    models = list(dict.fromkeys(r.get("model", "") for r in completed))
    model_color = {m: _PALETTE[i % len(_PALETTE)] for i, m in enumerate(models)}

    labels = [_run_kwarg_label(r) for r in completed]
    data   = [_primary_score(r, task) or 0.0 for r in completed]
    colors = [model_color.get(r.get("model", ""), _PALETTE[0]) for r in completed]

    datasets: list[dict[str, Any]] = [{"label": "Score", "data": data, "backgroundColor": colors}]

    if len(models) > 1:
        datasets = []
        for m in models:
            m_runs = [r for r in completed if r.get("model") == m]
            datasets.append({
                "label": _short_model(m),
                "data":  [_primary_score(r, task) or 0.0 for r in m_runs],
                "backgroundColor": model_color[m],
            })
        labels = [_run_kwarg_label(r) for r in (
            [r for r in completed if r.get("model") == models[0]]
        )]

    return {
        "labels":   labels,
        "datasets": datasets,
        "_scorer_name": _preferred_scorer(task),
        "_models":  [_short_model(m) for m in models],
        "_colors":  [model_color[m] for m in models],
    }


def _build_model_avg_chart(
    runs_list: list[dict[str, Any]],
    task: str,
) -> dict[str, Any] | None:
    """Horizontal bar chart: mean score per model across all targets."""
    completed = [r for r in runs_list if r.get("status") == "completed"]
    if not completed:
        return None
    model_scores: dict[str, list[float]] = defaultdict(list)
    for r in completed:
        s = _primary_score(r, task)
        if s is not None:
            model_scores[r.get("model", "")].append(s)
    if not model_scores:
        return None
    # Sort descending by mean (best model first = top of horizontal bar)
    sorted_models = sorted(
        model_scores,
        key=lambda m: -(sum(model_scores[m]) / len(model_scores[m])),
    )
    labels = [_short_model(m) for m in sorted_models]
    means  = [round(sum(model_scores[m]) / len(model_scores[m]), 4) for m in sorted_models]
    colors = [_PALETTE[i % len(_PALETTE)] for i in range(len(sorted_models))]
    return {
        "labels": labels,
        "datasets": [{
            "label": "Mean success rate across targets",
            "data":  means,
            "backgroundColor": colors,
        }],
    }


def _preferred_scorer(task: str) -> str:
    return {
        "fuzzing":  "_live_fuzzing_scorer",
        "patching": "_patch_scorer",
        "triage":   "_triage_scorer",
        "harness":  "_harness_scorer",
    }.get(task, "primary scorer")


def _build_duration_chart(manifest_runs: dict[str, Any]) -> dict[str, Any] | None:
    """Horizontal bar: completion duration per run (from manifest timestamps)."""
    labels: list[str] = []
    data:   list[float] = []
    colors: list[str] = []
    models_seen: list[str] = []

    for r in manifest_runs.values():
        if r.get("status") != "completed":
            continue
        dur = _duration_minutes(r.get("started_at"), r.get("completed_at"))
        if dur is None:
            continue
        m, t = r.get("model", ""), r.get("target") or "—"
        kw = _interesting_kwargs(r.get("task_kwargs") or {})
        kw_str = ", ".join(f"{k}={v}" for k, v in kw.items())
        if m not in models_seen:
            models_seen.append(m)
        label = f"{_short_model(m)} / {t}" + (f" ({kw_str})" if kw_str else "")
        labels.append(label)
        data.append(dur)
        colors.append(_PALETTE[models_seen.index(m) % len(_PALETTE)])

    if not data:
        return None
    return {
        "labels":   labels,
        "datasets": [{"label": "Duration (minutes)", "data": data, "backgroundColor": colors}],
    }


# ---------------------------------------------------------------------------
# Run table builder
# ---------------------------------------------------------------------------

def _build_runs_table(
    runs_list: list[dict[str, Any]],
    task: str,
) -> list[dict[str, Any]]:
    rows = []
    for r in runs_list:
        score = _primary_score(r, task)
        rows.append({
            "run_id":       r.get("run_id", "")[:8],
            "model":        r.get("model", ""),
            "model_short":  _short_model(r.get("model", "")),
            "target":       r.get("target") or "—",
            "status":       r.get("status", "unknown"),
            "kwargs":       _interesting_kwargs(r.get("task_kwargs") or {}),
            "score":        round(score, 4) if score is not None else None,
            "n_samples":    r.get("n_samples"),
            "total_time_s": round(r.get("total_time", 0), 1) if r.get("total_time") else None,
            "eval_log":     bool(r.get("eval_log")),
            "error":        (r.get("error") or "")[:120],
        })
    return rows


# ---------------------------------------------------------------------------
# Analysis chart builders
# ---------------------------------------------------------------------------

def _build_leaderboard_chart(leaderboard: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [_short_model(m["model"]) for m in leaderboard]
    return {
        "labels": labels,
        "datasets": [{
            "label": "Mean score",
            "data":  [round(m["mean_score"], 4) for m in leaderboard],
            "backgroundColor": [_PALETTE[i % len(_PALETTE)] for i in range(len(labels))],
        }],
    }


def _build_pipeline_chart(leaderboard: list[dict[str, Any]]) -> dict[str, Any]:
    stages = ["patch_applies_rate", "compiles_rate", "crash_eliminated_rate", "tests_pass_rate"]
    labels = ["Patch Applies", "Compiles", "Crash Eliminated", "Tests Pass"]
    return {
        "labels": labels,
        "datasets": [
            {
                "label": _short_model(m["model"]),
                "data":  [round(m.get(s, 0.0) * 100, 1) for s in stages],
                "backgroundColor": _PALETTE[i % len(_PALETTE)],
            }
            for i, m in enumerate(leaderboard)
        ],
    }


def _build_target_breakdown_chart(target_breakdown: list[dict[str, Any]]) -> dict[str, Any]:
    targets = sorted({e["target"] for e in target_breakdown})
    models  = sorted({e["model"]  for e in target_breakdown})
    lookup  = {(e["model"], e["target"]): e["mean_score"] for e in target_breakdown}
    return {
        "labels": targets,
        "datasets": [
            {
                "label": _short_model(m),
                "data":  [round(lookup.get((m, t), 0.0), 4) for t in targets],
                "backgroundColor": _PALETTE[i % len(_PALETTE)],
            }
            for i, m in enumerate(models)
        ],
    }


def _build_cwe_chart(cwe_breakdown: list[dict[str, Any]]) -> dict[str, Any]:
    cwes   = sorted({e["cwe"]   for e in cwe_breakdown})
    models = sorted({e["model"] for e in cwe_breakdown})
    lookup = {(e["model"], e["cwe"]): e["mean_score"] for e in cwe_breakdown}
    return {
        "labels": cwes,
        "datasets": [
            {
                "label": _short_model(m),
                "data":  [round(lookup.get((m, c), 0.0), 4) for c in cwes],
                "backgroundColor": _PALETTE[i % len(_PALETTE)],
            }
            for i, m in enumerate(models)
        ],
    }


def _build_difficulty_chart(difficulty_breakdown: list[dict[str, Any]]) -> dict[str, Any]:
    DIFF_ORDER = {"easy": 0, "medium": 1, "hard": 2, "very_hard": 3}
    diffs  = sorted({e["difficulty"] for e in difficulty_breakdown},
                    key=lambda d: DIFF_ORDER.get(d, 99))
    models = sorted({e["model"] for e in difficulty_breakdown})
    lookup = {(e["model"], e["difficulty"]): e["mean_score"] for e in difficulty_breakdown}
    return {
        "labels": diffs,
        "datasets": [
            {
                "label": _short_model(m),
                "data":  [round(lookup.get((m, d), 0.0), 4) for d in diffs],
                "borderColor":      _PALETTE[i % len(_PALETTE)].replace("0.85", "1"),
                "backgroundColor":  _PALETTE[i % len(_PALETTE)].replace("0.85", "0.15"),
                "tension": 0.3, "fill": False, "pointRadius": 5,
            }
            for i, m in enumerate(models)
        ],
    }


def _build_token_chart(leaderboard: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [_short_model(m["model"]) for m in leaderboard]
    return {
        "labels": labels,
        "datasets": [
            {"label": "Input tokens (mean)",  "data": [round(m.get("mean_input_tokens",  0)) for m in leaderboard], "backgroundColor": "rgba(59,130,246,0.75)"},
            {"label": "Output tokens (mean)", "data": [round(m.get("mean_output_tokens", 0)) for m in leaderboard], "backgroundColor": "rgba(20,184,166,0.75)"},
        ],
    }


# ---------------------------------------------------------------------------
# Top-level compute_stats
# ---------------------------------------------------------------------------

def compute_stats(
    results:  dict[str, Any] | None,
    manifest: dict[str, Any] | None,
    analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    stats: dict[str, Any] = {}

    # ── From results.json (primary) ───────────────────────────────────────
    if results:
        task      = results.get("task", "unknown")
        completed = results.get("completed", 0)
        failed    = results.get("failed", 0)
        pending   = results.get("pending", 0)
        total     = results.get("total_runs", 0)
        running   = max(0, total - completed - failed - pending)

        stats.update({
            "task_type":  task,
            "total_runs": total,
            "completed":  completed,
            "failed":     failed,
            "pending":    pending,
            "running":    running,
        })

        runs_list: list[dict[str, Any]] = results.get("runs", [])
        stats["status_donut"]    = _build_status_donut(completed, failed, running, pending)
        stats["runs_table"]      = _build_runs_table(runs_list, task)
        stats["score_chart"]     = _build_score_chart(runs_list, task)
        stats["model_avg_chart"] = _build_model_avg_chart(runs_list, task)

        if not manifest:
            stats["status_matrix"] = _build_status_matrix_from_results(runs_list)

        # Score stats
        scores_flat = [
            _primary_score(r, task) for r in runs_list if r.get("status") == "completed"
        ]
        scores_flat = [s for s in scores_flat if s is not None]
        if scores_flat:
            stats["mean_score"]  = round(sum(scores_flat) / len(scores_flat), 4)
            stats["max_score"]   = round(max(scores_flat), 4)
            stats["scorer_name"] = _preferred_scorer(task)

        # Per-model aggregates for headline display
        model_avgs: dict[str, list[float]] = defaultdict(list)
        for r in runs_list:
            if r.get("status") == "completed":
                s = _primary_score(r, task)
                if s is not None:
                    model_avgs[r.get("model", "")].append(s)
        stats["model_count"]  = len(model_avgs)
        stats["target_count"] = len(list(dict.fromkeys(
            r.get("target", "") for r in runs_list if r.get("target")
        )))
        if model_avgs:
            best_m = max(model_avgs, key=lambda m: sum(model_avgs[m]) / len(model_avgs[m]))
            stats["best_model_name"] = _short_model(best_m)
            stats["best_model_avg"]  = round(
                sum(model_avgs[best_m]) / len(model_avgs[best_m]), 4
            )

    # ── From manifest.json (supplementary) ───────────────────────────────
    if manifest:
        cfg  = manifest.get("config", {})
        grid = cfg.get("grid", {})
        defs = cfg.get("defaults", {})
        manifest_runs = manifest.get("runs", {})

        if not stats.get("task_type"):
            stats["task_type"] = cfg.get("task", "unknown")

        stats["grid_models"]    = grid.get("model", [])
        stats["grid_targets"]   = [t for t in (grid.get("target") or []) if t]
        stats["grid_extra"]     = grid.get("extra", {})
        stats["engine"]         = defs.get("engine", "")
        stats["max_rounds"]     = defs.get("max_rounds")
        stats["round_duration"] = defs.get("round_duration")

        stats["status_matrix"] = _build_status_matrix(manifest_runs)
        dur = _build_duration_chart(manifest_runs)
        if dur:
            stats["duration_chart"] = dur

        durations = []
        for r in manifest_runs.values():
            d = _duration_minutes(r.get("started_at"), r.get("completed_at"))
            if d is not None:
                durations.append(d)
        if durations:
            stats["mean_duration_min"] = round(sum(durations) / len(durations), 1)
            stats["min_duration_min"]  = round(min(durations), 1)
            stats["max_duration_min"]  = round(max(durations), 1)

    # ── From analysis.json ────────────────────────────────────────────────
    if analysis:
        if not stats.get("task_type"):
            stats["task_type"] = analysis.get("task_type", "unknown")

        lb   = analysis.get("leaderboard", [])
        cwe  = analysis.get("cwe_breakdown", [])
        diff = analysis.get("difficulty_breakdown", [])
        tgt  = analysis.get("target_breakdown", [])

        stats.update({
            "leaderboard":          lb,
            "cwe_breakdown":        cwe,
            "difficulty_breakdown": diff,
            "target_breakdown":     tgt,
        })
        if lb:
            stats["leaderboard_chart"] = _build_leaderboard_chart(lb)
            stats["token_chart"]       = _build_token_chart(lb)
            best = max(lb, key=lambda m: m["mean_score"])
            stats["best_model"] = _short_model(best["model"])
            stats["best_score"] = round(best["mean_score"], 3)
            if analysis.get("task_type") == "patching":
                stats["pipeline_chart"] = _build_pipeline_chart(lb)
        if tgt:
            stats["target_chart"] = _build_target_breakdown_chart(tgt)
        if cwe:
            stats["cwe_chart"] = _build_cwe_chart(cwe)
        if diff:
            stats["difficulty_chart"] = _build_difficulty_chart(diff)

    return stats


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def build_site(
    data_dirs: list[Path],
    content_dir: Path,
    output_dir: Path,
    templates_dir: Path,
) -> None:
    console.print(Panel("[bold]parser-security-eval site builder[/bold]", style="blue"))

    # ── Load experiments ──────────────────────────────────────────────────
    experiments: list[dict[str, Any]] = []
    for data_dir in data_dirs:
        if not data_dir.exists():
            console.print(f"  [yellow]skip[/yellow] {data_dir.name} (not found)")
            continue
        console.print(f"\n[bold]Loading {data_dir.name}...[/bold]")
        results, manifest, analysis = load_data_dir(data_dir)
        if results is None and manifest is None and analysis is None:
            console.print("  [yellow]No recognised data — skipping.[/yellow]")
            continue
        stats = compute_stats(results, manifest, analysis)
        task  = stats.get("task_type", "unknown")
        name  = data_dir.name
        experiments.append({
            "name":         name,
            "display_name": _display_name(name, task),
            "task":         task,
            "results":      results,
            "manifest":     manifest,
            "analysis":     analysis,
            "stats":        stats,
        })

    # Sort: patching first, fuzzing second, rest alphabetically
    _TASK_ORDER = {"patching": 0, "fuzzing": 1}
    experiments.sort(key=lambda e: (_TASK_ORDER.get(e["task"], 9), e["name"]))

    is_example = any((e.get("results") or {}).get("_example") for e in experiments)

    # ── Load content ──────────────────────────────────────────────────────
    console.print("\n[bold]Loading content...[/bold]")
    content = load_content(content_dir)
    console.print(f"  {len(content)} content page(s) loaded")

    # ── Render ────────────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html"]),
    )

    ctx: dict[str, Any] = {
        "experiments": experiments,
        "content":     content,
        "is_example":  is_example,
        "build_date":  datetime.now().strftime("%Y-%m-%d"),
        "pages": [
            {"id": "patching", "title": "Patching", "href": "#patching"},
            {"id": "fuzzing",  "title": "Fuzzing",  "href": "#fuzzing"},
            {"id": "about",    "title": "About",    "href": "#about"},
            {"id": "roadmap",  "title": "Roadmap",  "href": "#roadmap"},
        ],
    }

    console.print("\n[bold]Rendering...[/bold]")
    tpl = env.get_template("index.html.j2")
    out = output_dir / "index.html"
    out.write_text(tpl.render(**ctx, current_page="index"))
    console.print(f"  [green]✓[/green] index.html ({round(out.stat().st_size / 1024, 1)} KB)")

    console.print(f"\n[bold green]Done![/bold green] Output → [cyan]{output_dir}[/cyan]")
    for exp in experiments:
        s = exp["stats"]
        line = (
            f"  {exp['display_name']:38} "
            f"{s.get('completed', 0)} ✓ / {s.get('total_runs', 0)} total"
        )
        if s.get("best_model_avg") is not None:
            line += f"  |  best: {s['best_model_name']} {s['best_model_avg']:.3f}"
        console.print(line)
    if is_example:
        console.print("[yellow]⚠  Built with EXAMPLE data.[/yellow]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.command()
def main(
    data_dir: Optional[list[Path]] = typer.Option(
        None,
        "--data-dir",
        help="Experiment result directory (repeat to load multiple experiments). "
             "Defaults to scaffold/results/patching-model-sweep-v2 and fuzzing-baseline-v2.",
    ),
    content_dir:   Path = typer.Option(HERE / "content",   help="Markdown content directory"),
    output_dir:    Path = typer.Option(HERE / "dist",      help="Output directory"),
    templates_dir: Path = typer.Option(HERE / "templates", help="Jinja2 templates directory"),
) -> None:
    """Build the funder-facing experiment results site."""
    dirs: list[Path] = list(data_dir) if data_dir else [
        HERE / "../../scaffold/results/patching-model-sweep-v2",
        HERE / "../../scaffold/results/fuzzing-baseline-v2",
    ]
    build_site(dirs, content_dir, output_dir, templates_dir)


if __name__ == "__main__":
    app()
