# parser-security-eval (scaffold)

Python package for the parser security evaluation framework. See the [root README](../README.md) for full setup and usage instructions.

```bash
uv sync
uv run parser-security-eval --help
```

## Visualizer

A Streamlit dashboard for exploring `.eval` log files produced by the eval pipeline. Supports crash-triage and vulnerability-patching logs.

```bash
uv run streamlit run src/viz/app.py
```

Opens at `http://localhost:8501`. Select log files from the sidebar, then navigate between pages:

| Page | Description |
|------|-------------|
| Overview | Sample counts, accuracy metrics, and timing at a glance |
| Score Breakdown | Accuracy bar charts sliced by target, difficulty, and crash type; CWE confusion heatmap |
| Sample Browser | Filterable table; click a row to load the full model output |
| Patching Funnel | 5-stage pipeline funnel (applies → compiles → crash eliminated → tests pass), score histogram |
| Patch Diff Viewer | Per-sample vulnerability description, ground-truth patch, and model-proposed patch side-by-side |
| Model Usage | Token totals and estimated cost |
