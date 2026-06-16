"""Results analysis — load eval logs, build DataFrames, compute breakdowns."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd
from inspect_ai.log import read_eval_log_sample_summaries

from parser_security_eval.experiments.models import (
    CWEBreakdown,
    DifficultyBreakdown,
    ExperimentAnalysis,
    ModelScore,
    RunStatus,
    TargetBreakdown,
)
from parser_security_eval.experiments.state import load_manifest
from parser_security_eval.log import get_log
from parser_security_eval.scorers.efficiency import (
    EFF_FUZZ_SECONDS,
    EFF_MODEL_SECONDS,
    EFF_TOKENS,
    EFF_VULNS,
    EfficiencyInputs,
    pooled_efficiency_rates,
)

log = get_log(__name__)


# ---------------------------------------------------------------------------
# Inline row-parsing (avoids importing streamlit-dependent viz/loader.py)
# ---------------------------------------------------------------------------

_PATCH_RE = re.compile(
    r"patch_applies=(\w+).*?compiles=(\w+).*?crash_eliminated=(\w+).*?tests_pass=(\w+).*?diff_lines=(\d+)",
    re.DOTALL,
)


def _parse_patch_explanation(explanation: str | None) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "patch_applies": False,
        "compiles": False,
        "crash_eliminated": False,
        "tests_pass": False,
        "diff_lines": 0,
    }
    if not explanation:
        return defaults
    m = _PATCH_RE.search(explanation)
    if not m:
        return defaults
    return {
        "patch_applies": m.group(1).lower() == "true",
        "compiles": m.group(2).lower() == "true",
        "crash_eliminated": m.group(3).lower() == "true",
        "tests_pass": m.group(4).lower() == "true",
        "diff_lines": int(m.group(5)),
    }


def _usage_from_summary(summary: Any) -> tuple[int, int, int]:
    if not summary.model_usage:
        return 0, 0, 0
    inp = sum(u.input_tokens for u in summary.model_usage.values())
    out = sum(u.output_tokens for u in summary.model_usage.values())
    tot = sum(u.total_tokens for u in summary.model_usage.values())
    return inp, out, tot


def _ci_to_int(value: Any) -> int:
    if value is None:
        return -1
    s = str(value).strip().upper()
    if s == "C":
        return 1
    if s == "I":
        return 0
    return -1


def _summary_to_row_patching(summary: Any, model: str) -> dict[str, Any]:
    meta = summary.metadata or {}
    scores = summary.scores or {}

    patch_obj = scores.get("_patch_scorer")
    patch_score = patch_obj.as_float() if patch_obj else 0.0
    explanation = patch_obj.explanation if patch_obj else None
    parsed = _parse_patch_explanation(explanation)

    inp, out, tot = _usage_from_summary(summary)

    pipeline_stages = []
    for stage in ("patch_applies", "compiles", "crash_eliminated", "tests_pass"):
        if parsed[stage]:
            pipeline_stages.append(stage)

    return {
        "model": model,
        "sample_id": str(summary.id),
        "target": meta.get("target", ""),
        "difficulty": meta.get("difficulty", ""),
        "cwe": meta.get("cwe", ""),
        "sanitizer": meta.get("sanitizer", ""),
        "total_time": summary.total_time or 0.0,
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": tot,
        "completed": summary.completed,
        "score": patch_score,
        "patch_applies": parsed["patch_applies"],
        "compiles": parsed["compiles"],
        "crash_eliminated": parsed["crash_eliminated"],
        "tests_pass": parsed["tests_pass"],
        "diff_lines": parsed["diff_lines"],
        "pipeline_stage": ", ".join(pipeline_stages) if pipeline_stages else "none",
    }


def _summary_to_row_triage(summary: Any, model: str) -> dict[str, Any]:
    meta = summary.metadata or {}
    scores = summary.scores or {}

    cwe_score_obj = scores.get("cwe_scorer")
    sev_score_obj = scores.get("severity_scorer")
    fact_score_obj = scores.get("model_graded_fact")

    cwe_score = _ci_to_int(cwe_score_obj.value if cwe_score_obj else None)
    severity_score = _ci_to_int(sev_score_obj.value if sev_score_obj else None)
    fact_score = _ci_to_int(fact_score_obj.value if fact_score_obj else None)

    inp, out, tot = _usage_from_summary(summary)

    # Use average of available scores as the composite score
    valid_scores = [s for s in (cwe_score, severity_score, fact_score) if s >= 0]
    composite = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0

    return {
        "model": model,
        "sample_id": str(summary.id),
        "target": meta.get("target", ""),
        "difficulty": meta.get("difficulty", ""),
        "cwe": meta.get("cwe", ""),
        "total_time": summary.total_time or 0.0,
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": tot,
        "completed": summary.completed,
        "score": composite,
        "cwe_score": cwe_score,
        "severity_score": severity_score,
        "fact_score": fact_score,
    }


def _summary_to_row_fuzzing(summary: Any, model: str) -> dict[str, Any]:
    meta = summary.metadata or {}
    scores = summary.scores or {}

    fuzz_obj = scores.get("_live_fuzzing_scorer")
    score_val = fuzz_obj.as_float() if fuzz_obj else 0.0
    smeta = (fuzz_obj.metadata or {}) if fuzz_obj else {}

    inp, out, tot = _usage_from_summary(summary)

    def _num(key: str) -> float:
        value = smeta.get(key, 0.0)
        return float(value) if isinstance(value, (int, float)) else 0.0

    return {
        "model": model,
        "sample_id": str(summary.id),
        "target": meta.get("target") or meta.get("target_name", ""),
        "difficulty": meta.get("difficulty", ""),
        "cwe": meta.get("cwe", ""),
        "total_time": summary.total_time or 0.0,
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": tot,
        "completed": summary.completed,
        "score": score_val,
        "unique_crashes": int(_num("unique_crashes")),
        # Raw efficiency inputs (issue #135), read straight off the scorer
        # metadata so the leaderboard's pooled rates match the registered
        # metrics exactly. See scorers/efficiency.py.
        "eff_vulns": _num(EFF_VULNS),
        "eff_total_tokens": _num(EFF_TOKENS),
        "eff_model_seconds": _num(EFF_MODEL_SECONDS),
        "eff_fuzz_seconds": _num(EFF_FUZZ_SECONDS),
    }


# ---------------------------------------------------------------------------
# DataFrame building
# ---------------------------------------------------------------------------


def build_combined_dataframe(
    manifest: Any,
) -> pd.DataFrame:
    """Load all completed .eval logs into one DataFrame."""
    rows: list[dict[str, Any]] = []
    task_type = manifest.config.task

    for run in manifest.runs.values():
        if run.status != RunStatus.completed or not run.eval_log_path:
            continue

        log_path = run.eval_log_path
        try:
            summaries = read_eval_log_sample_summaries(log_path)
        except Exception:
            log.warn("Failed to read eval log: %s", log_path)
            continue

        for s in summaries:
            if task_type == "patching":
                rows.append(_summary_to_row_patching(s, run.model))
            elif task_type == "triage":
                rows.append(_summary_to_row_triage(s, run.model))
            elif task_type == "fuzzing":
                rows.append(_summary_to_row_fuzzing(s, run.model))

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def compute_model_leaderboard(df: pd.DataFrame, task_type: str) -> list[ModelScore]:
    """Aggregate per-model scores."""
    if df.empty:
        return []

    results: list[ModelScore] = []
    for model, group in df.groupby("model"):
        kwargs: dict[str, Any] = {
            "model": str(model),
            "mean_score": float(group["score"].mean()),
            "mean_input_tokens": float(group["input_tokens"].mean()),
            "mean_output_tokens": float(group["output_tokens"].mean()),
            "mean_total_time": float(group["total_time"].mean()),
            "n_samples": len(group),
        }
        if task_type == "patching":
            for stage in (
                "patch_applies",
                "compiles",
                "crash_eliminated",
                "tests_pass",
            ):
                if stage in group.columns:
                    kwargs[f"{stage}_rate"] = float(group[stage].mean())
        elif task_type == "fuzzing" and "eff_vulns" in group.columns:
            # Pooled efficiency rates (sum vulns / sum resource), computed via the
            # same helper the registered metrics use — never a mean of per-sample
            # ratios. See scorers/efficiency.py.
            rates = pooled_efficiency_rates(
                EfficiencyInputs(
                    vulns=int(vulns),
                    total_tokens=int(tokens),
                    model_seconds=float(model_seconds),
                    fuzz_seconds=float(fuzz_seconds),
                )
                for vulns, tokens, model_seconds, fuzz_seconds in zip(
                    group["eff_vulns"],
                    group["eff_total_tokens"],
                    group["eff_model_seconds"],
                    group["eff_fuzz_seconds"],
                )
            )
            kwargs["total_unique_crashes"] = rates.vulns
            kwargs["vulns_per_mtok"] = rates.vulns_per_mtok
            kwargs["vulns_per_fuzz_hour"] = rates.vulns_per_fuzz_hour
            kwargs["vulns_per_mtok_equiv"] = rates.vulns_per_mtok_equiv
            kwargs["token_rate"] = rates.token_rate

        results.append(ModelScore(**kwargs))

    return sorted(results, key=lambda m: m.mean_score, reverse=True)


def compute_cwe_breakdown(df: pd.DataFrame) -> list[CWEBreakdown]:
    if df.empty or "cwe" not in df.columns:
        return []
    results: list[CWEBreakdown] = []
    for (model, cwe), group in df.groupby(["model", "cwe"]):  # type: ignore[misc]
        if not cwe:
            continue
        results.append(
            CWEBreakdown(
                model=str(model),
                cwe=str(cwe),
                mean_score=float(group["score"].mean()),
                n_samples=len(group),
            )
        )
    return results


def compute_difficulty_curve(df: pd.DataFrame) -> list[DifficultyBreakdown]:
    if df.empty or "difficulty" not in df.columns:
        return []
    results: list[DifficultyBreakdown] = []
    for (model, diff), group in df.groupby(["model", "difficulty"]):  # type: ignore[misc]
        if not diff:
            continue
        results.append(
            DifficultyBreakdown(
                model=str(model),
                difficulty=str(diff),
                mean_score=float(group["score"].mean()),
                n_samples=len(group),
            )
        )
    return results


def compute_target_breakdown(df: pd.DataFrame) -> list[TargetBreakdown]:
    if df.empty or "target" not in df.columns:
        return []
    results: list[TargetBreakdown] = []
    for (model, target), group in df.groupby(["model", "target"]):  # type: ignore[misc]
        if not target:
            continue
        results.append(
            TargetBreakdown(
                model=str(model),
                target=str(target),
                mean_score=float(group["score"].mean()),
                n_samples=len(group),
            )
        )
    return results


def analyze_experiment(output_dir: Path) -> ExperimentAnalysis:
    """Load manifest, build DataFrame, compute all breakdowns."""
    manifest = load_manifest(output_dir)
    if manifest is None:
        msg = f"No manifest found in {output_dir}"
        raise FileNotFoundError(msg)

    task_type = manifest.config.task
    df = build_combined_dataframe(manifest)

    return ExperimentAnalysis(
        experiment_name=manifest.experiment_name,
        task_type=str(task_type),
        leaderboard=compute_model_leaderboard(df, str(task_type)),
        cwe_breakdown=compute_cwe_breakdown(df),
        difficulty_breakdown=compute_difficulty_curve(df),
        target_breakdown=compute_target_breakdown(df),
    )
