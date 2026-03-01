# Parser Security Eval — Results Site

Static site generator for experiment results from [issue #53](https://github.com/for-all-dev/parser-security-eval/issues/53) and future experiments.

## Quick start

```sh
cd comms/site
uv run python build.py          # builds to dist/
open dist/index.html            # view locally
```

## Adding real experiment data

Drop one or more `.json` or `.toml` files into `comms/site/data/`. The build
script merges them all in sorted filename order:

- `experiment` keys are merged (later files win)
- `runs` arrays are concatenated

See [`data/schema.md`](data/schema.md) for the full data format.

`data/example.json` ships with mock data so you can preview the site before
real results are in. It is auto-detected as example data (via the `notes`
field) and a banner is shown. To suppress the banner, remove or clear the
`notes` field from your real data.

## Adding prose content

Add `.md` files to `comms/site/content/`. Use YAML frontmatter to set the
title and display order:

```markdown
---
title: My Analysis
order: 4
---

# My Analysis

Regular Markdown content here...
```

Content pages appear on the Overview page in order.

## Output

The generator writes three HTML files to `comms/site/dist/`:

| File | Contents |
|------|----------|
| `index.html` | Hero, key stats, overview charts, content prose |
| `results.html` | Crash-rate bar charts, cycle comparison, full data table |
| `coverage.html` | Per-target coverage timelines, time-to-first-crash chart |

All pages are self-contained (no server required). Charts use Chart.js loaded
from a CDN, so a network connection is needed to render them.

## CLI options

```
uv run python build.py --help
```

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `data/` | JSON/TOML data directory |
| `--content-dir` | `content/` | Markdown content directory |
| `--output-dir` | `dist/` | Output directory |
| `--templates-dir` | `templates/` | Jinja2 templates directory |
