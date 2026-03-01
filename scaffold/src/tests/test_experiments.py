"""Tests for the experiments module — config parsing, grid expansion, manifest persistence, analysis."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from parser_security_eval.experiments.models import (
    ExperimentConfig,
    ExperimentDefaults,
    ExperimentGrid,
    ExperimentManifest,
    RunStatus,
    TaskType,
)
from parser_security_eval.experiments.runner import expand_grid, load_config
from parser_security_eval.experiments.state import (
    init_or_resume_manifest,
    load_manifest,
    mark_run_completed,
    mark_run_failed,
    mark_run_started,
    save_manifest,
)
from parser_security_eval.experiments.analysis import (
    compute_cwe_breakdown,
    compute_difficulty_curve,
    compute_model_leaderboard,
    compute_target_breakdown,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_config() -> ExperimentConfig:
    return ExperimentConfig(
        name="test-sweep",
        description="unit test config",
        task=TaskType.patching,
        output_dir="results/test-sweep",
        defaults=ExperimentDefaults(
            benchmark_dir="../benchmark",
            targets_root="../targets",
            ready_only=True,
            limit=5,
        ),
        grid=ExperimentGrid(
            model=["model-a", "model-b"],
            target=["libpng", "zlib"],
        ),
        repetitions=2,
    )


@pytest.fixture
def sample_toml(tmp_path: Path) -> Path:
    toml_content = """\
name = "toml-test"
description = "parsed from toml"
task = "patching"
output_dir = "{output_dir}"
repetitions = 1

[defaults]
benchmark_dir = "../benchmark"
ready_only = true
limit = 10

[grid]
model = ["model-x", "model-y"]
target = ["libpng"]
""".format(output_dir=str(tmp_path / "out"))
    p = tmp_path / "test.toml"
    p.write_text(toml_content)
    return p


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------


class TestConfigParsing:
    def test_load_config_from_toml(self, sample_toml: Path):
        config = load_config(sample_toml)
        assert config.name == "toml-test"
        assert config.task == TaskType.patching
        assert config.grid.model == ["model-x", "model-y"]
        assert config.defaults.ready_only is True
        assert config.defaults.limit == 10

    def test_config_round_trip(self, sample_config: ExperimentConfig):
        data = sample_config.model_dump()
        restored = ExperimentConfig.model_validate(data)
        assert restored.name == sample_config.name
        assert restored.grid.model == sample_config.grid.model
        assert restored.repetitions == sample_config.repetitions

    def test_default_values(self):
        config = ExperimentConfig(
            name="minimal",
            task=TaskType.triage,
            grid=ExperimentGrid(model=["m1"]),
        )
        assert config.output_dir == "results"
        assert config.repetitions == 1
        assert config.defaults.engine == "libfuzzer"
        assert config.grid.target == [None]


# ---------------------------------------------------------------------------
# Grid expansion
# ---------------------------------------------------------------------------


class TestGridExpansion:
    def test_basic_expansion(self, sample_config: ExperimentConfig):
        runs = expand_grid(sample_config)
        # 2 models x 2 targets x 2 reps = 8
        assert len(runs) == 8

    def test_deterministic_ids(self, sample_config: ExperimentConfig):
        runs1 = expand_grid(sample_config)
        runs2 = expand_grid(sample_config)
        ids1 = [r.run_id for r in runs1]
        ids2 = [r.run_id for r in runs2]
        assert ids1 == ids2

    def test_unique_ids(self, sample_config: ExperimentConfig):
        runs = expand_grid(sample_config)
        ids = [r.run_id for r in runs]
        assert len(ids) == len(set(ids))

    def test_extra_dimensions(self):
        config = ExperimentConfig(
            name="extra-test",
            task=TaskType.fuzzing,
            grid=ExperimentGrid(
                model=["m1"],
                target=["t1"],
                extra={"fuzz_duration": [60, 120, 300]},
            ),
            repetitions=1,
        )
        runs = expand_grid(config)
        # 1 model x 1 target x 3 durations x 1 rep = 3
        assert len(runs) == 3
        durations = {r.task_kwargs.get("fuzz_duration") for r in runs}
        assert durations == {60, 120, 300}

    def test_single_model_no_target(self):
        config = ExperimentConfig(
            name="single",
            task=TaskType.triage,
            grid=ExperimentGrid(model=["m1"]),
            repetitions=1,
        )
        runs = expand_grid(config)
        assert len(runs) == 1
        assert runs[0].target is None


# ---------------------------------------------------------------------------
# Manifest persistence
# ---------------------------------------------------------------------------


class TestManifestPersistence:
    def test_save_and_load(self, sample_config: ExperimentConfig, tmp_path: Path):
        sample_config.output_dir = str(tmp_path / "manifest-test")
        runs = expand_grid(sample_config)
        manifest = ExperimentManifest(
            experiment_name=sample_config.name,
            config=sample_config,
            runs={r.run_id: r for r in runs},
        )
        save_manifest(manifest)

        loaded = load_manifest(Path(sample_config.output_dir))
        assert loaded is not None
        assert loaded.experiment_name == "test-sweep"
        assert loaded.total_runs == 8

    def test_load_nonexistent(self, tmp_path: Path):
        assert load_manifest(tmp_path / "nonexistent") is None

    def test_init_creates_new(self, sample_config: ExperimentConfig, tmp_path: Path):
        sample_config.output_dir = str(tmp_path / "init-test")
        runs = expand_grid(sample_config)
        manifest = init_or_resume_manifest(sample_config, runs)
        assert manifest.total_runs == 8
        assert manifest.pending_runs == 8

    def test_resume_resets_stuck_running(
        self, sample_config: ExperimentConfig, tmp_path: Path
    ):
        sample_config.output_dir = str(tmp_path / "resume-test")
        runs = expand_grid(sample_config)
        manifest = init_or_resume_manifest(sample_config, runs)

        # Mark one as running (simulating a crash)
        first_id = list(manifest.runs.keys())[0]
        manifest.runs[first_id].status = RunStatus.running
        save_manifest(manifest)

        # Resume should reset it to pending
        resumed = init_or_resume_manifest(sample_config, runs)
        assert resumed.runs[first_id].status == RunStatus.pending

    def test_resume_keeps_completed(
        self, sample_config: ExperimentConfig, tmp_path: Path
    ):
        sample_config.output_dir = str(tmp_path / "keep-test")
        runs = expand_grid(sample_config)
        manifest = init_or_resume_manifest(sample_config, runs)

        first_id = list(manifest.runs.keys())[0]
        mark_run_started(manifest, first_id)
        mark_run_completed(manifest, first_id, "/some/log.eval")

        resumed = init_or_resume_manifest(sample_config, runs)
        assert resumed.runs[first_id].status == RunStatus.completed
        assert resumed.runs[first_id].eval_log_path == "/some/log.eval"

    def test_resume_adds_new_grid_cells(
        self, sample_config: ExperimentConfig, tmp_path: Path
    ):
        sample_config.output_dir = str(tmp_path / "add-cells-test")
        runs = expand_grid(sample_config)
        manifest = init_or_resume_manifest(sample_config, runs)
        assert manifest.total_runs == 8

        # Expand grid with a new model
        sample_config.grid.model = ["model-a", "model-b", "model-c"]
        new_runs = expand_grid(sample_config)
        resumed = init_or_resume_manifest(sample_config, new_runs)
        assert resumed.total_runs == 12  # 3 models x 2 targets x 2 reps

    def test_mark_run_failed(self, sample_config: ExperimentConfig, tmp_path: Path):
        sample_config.output_dir = str(tmp_path / "fail-test")
        runs = expand_grid(sample_config)
        manifest = init_or_resume_manifest(sample_config, runs)

        first_id = list(manifest.runs.keys())[0]
        mark_run_started(manifest, first_id)
        mark_run_failed(manifest, first_id, "something broke")

        loaded = load_manifest(Path(sample_config.output_dir))
        assert loaded is not None
        assert loaded.runs[first_id].status == RunStatus.failed
        assert loaded.runs[first_id].error == "something broke"


# ---------------------------------------------------------------------------
# Analysis with mock DataFrames
# ---------------------------------------------------------------------------


class TestAnalysis:
    @pytest.fixture
    def patching_df(self) -> pd.DataFrame:
        return pd.DataFrame(
            [
                {
                    "model": "model-a",
                    "sample_id": "s1",
                    "target": "libpng",
                    "difficulty": "easy",
                    "cwe": "CWE-787",
                    "score": 1.0,
                    "patch_applies": True,
                    "compiles": True,
                    "crash_eliminated": True,
                    "tests_pass": True,
                    "input_tokens": 1000,
                    "output_tokens": 500,
                    "total_time": 10.0,
                },
                {
                    "model": "model-a",
                    "sample_id": "s2",
                    "target": "zlib",
                    "difficulty": "hard",
                    "cwe": "CWE-787",
                    "score": 0.5,
                    "patch_applies": True,
                    "compiles": True,
                    "crash_eliminated": False,
                    "tests_pass": False,
                    "input_tokens": 1200,
                    "output_tokens": 600,
                    "total_time": 15.0,
                },
                {
                    "model": "model-b",
                    "sample_id": "s1",
                    "target": "libpng",
                    "difficulty": "easy",
                    "cwe": "CWE-787",
                    "score": 0.0,
                    "patch_applies": False,
                    "compiles": False,
                    "crash_eliminated": False,
                    "tests_pass": False,
                    "input_tokens": 800,
                    "output_tokens": 400,
                    "total_time": 8.0,
                },
                {
                    "model": "model-b",
                    "sample_id": "s2",
                    "target": "zlib",
                    "difficulty": "hard",
                    "cwe": "CWE-125",
                    "score": 0.75,
                    "patch_applies": True,
                    "compiles": True,
                    "crash_eliminated": True,
                    "tests_pass": False,
                    "input_tokens": 900,
                    "output_tokens": 450,
                    "total_time": 12.0,
                },
            ]
        )

    def test_leaderboard_patching(self, patching_df: pd.DataFrame):
        lb = compute_model_leaderboard(patching_df, "patching")
        assert len(lb) == 2
        # model-a has higher mean score (0.75 vs 0.375)
        assert lb[0].model == "model-a"
        assert lb[0].mean_score == pytest.approx(0.75)
        assert lb[0].n_samples == 2
        assert lb[0].patch_applies_rate == pytest.approx(1.0)

    def test_leaderboard_empty(self):
        lb = compute_model_leaderboard(pd.DataFrame(), "patching")
        assert lb == []

    def test_cwe_breakdown(self, patching_df: pd.DataFrame):
        cwe = compute_cwe_breakdown(patching_df)
        assert len(cwe) > 0
        # model-a has 2 samples with CWE-787
        ma_787 = [c for c in cwe if c.model == "model-a" and c.cwe == "CWE-787"]
        assert len(ma_787) == 1
        assert ma_787[0].n_samples == 2

    def test_difficulty_breakdown(self, patching_df: pd.DataFrame):
        diff = compute_difficulty_curve(patching_df)
        assert len(diff) > 0
        easy_a = [d for d in diff if d.model == "model-a" and d.difficulty == "easy"]
        assert len(easy_a) == 1
        assert easy_a[0].mean_score == pytest.approx(1.0)

    def test_target_breakdown(self, patching_df: pd.DataFrame):
        tb = compute_target_breakdown(patching_df)
        assert len(tb) > 0
        libpng_a = [t for t in tb if t.model == "model-a" and t.target == "libpng"]
        assert len(libpng_a) == 1
        assert libpng_a[0].mean_score == pytest.approx(1.0)
