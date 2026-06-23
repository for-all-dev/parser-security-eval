# Logfire research dashboard (issue #114)

Per the resolution of [#114](https://github.com/for-all-dev/parser-security-eval/issues/114),
**Logfire is the primary research dashboard.** We do not build a bespoke Next.js
app or rebuild the Streamlit `viz/`; instead the runner + campaign loop emit
structured attributes that Logfire charts natively (live tail = the "hot reload"
the issue asked for). This file is the saved set of queries that power the core
research views.

**Fastest path — import the whole dashboard:** in Logfire go to
**Dashboards → Custom → Import JSON** and upload
[`logfire-dashboard.json`](./logfire-dashboard.json) (next to this file). It
creates an editable dashboard with all the panels below pre-wired. The queries
in this doc are the same SQL, kept here for reference / hand-editing a single
panel (Logfire's per-panel editor uses this same SQL).

## Telemetry contract

Two record streams carry the research signal:

**`eval sample`** — one OTel span per fuzzing run (Inspect sample lifecycle,
bridged in `telemetry.py::_sample_attributes`). Attributes:

| attribute | meaning |
|---|---|
| `target` | parser target (libpng, libxml2, …) |
| `model` | **primary model** for the run (busiest `model_usage` key) — the core research axis |
| `run_id`, `sample.id`, `sample.epoch` | run identity |
| `sample.total_time`, `sample.working_time` | wall/working seconds |
| `tokens.total` | total tokens across the run |
| `error`, `error.message` | run-level failure |
| `score._live_fuzzing_scorer` | composite score 0–1 |
| `score._live_fuzzing_scorer.eff_vulns` | unique crashes (issue #135 numerator) |
| `score._live_fuzzing_scorer.eff_fuzz_seconds` | fuzzer wall-clock W (CPU-seconds proxy) |
| `score._live_fuzzing_scorer.eff_model_seconds` | model thinking time (κ denominator) |
| `score._live_fuzzing_scorer.eff_total_tokens` | tokens charged to the run |
| `score._live_fuzzing_scorer.coverage_pcs` | peak libFuzzer coverage PCs/edges |
| `score._live_fuzzing_scorer.unique_crashes`, `.total_cycles`, `.first_try_compile_rate`, … | run summary |

**`fuzz cycle complete`** — one record per 30-min fuzzing cycle (the live curves;
`tasks/fuzzing.py`). Attributes: `target`, **`model`**, **`sample_id`**, **`epoch`**,
`cycle`, `execs_per_sec`, `total_execs`, `crashes_total`, `crashes_new`,
`coverage_profiles`, `coverage_pcs`, `max_coverage_pcs`, `fuzz_seconds`,
`total_fuzz_seconds`.

> `model` / `sample_id` / `epoch` were added in #114 so the live curves separate
> by model and per run instead of collapsing into one tangled line per target —
> the prerequisite for Logfire owning the curves.

All queries below exclude test pollution with
`target not in ('testparser', 'unknown')`. (The pytest suite emits cycle records
to Logfire when creds are present — see "Known issue" below.)

---

## 1. Vulns-per-walltime leaderboard by model × target (the core crux)

> "Incidence of vulns per unit walltime of fuzzing, as a function of model and
> agent architecture." Needs the `model` attribute (#114).

```sql
select
  attributes->>'model'  as model,
  attributes->>'target' as target,
  count(*)              as runs,
  round(sum((attributes->>'score._live_fuzzing_scorer.eff_vulns')::float), 1)            as vulns,
  round(sum((attributes->>'score._live_fuzzing_scorer.eff_fuzz_seconds')::float)/3600, 2) as fuzz_hours,
  round(sum((attributes->>'score._live_fuzzing_scorer.eff_total_tokens')::float)/1e6, 2)  as mtok,
  round(
    sum((attributes->>'score._live_fuzzing_scorer.eff_vulns')::float)
    / nullif(sum((attributes->>'score._live_fuzzing_scorer.eff_fuzz_seconds')::float)/3600, 0)
  , 3) as vulns_per_fuzz_hour,
  round(
    sum((attributes->>'score._live_fuzzing_scorer.eff_vulns')::float)
    / nullif(sum((attributes->>'score._live_fuzzing_scorer.eff_total_tokens')::float)/1e6, 0)
  , 3) as vulns_per_mtok
from records
where message = 'eval sample'
  and attributes->>'sample.id' like 'live-fuzzing%'
  and attributes->>'error' = 'false'
  and attributes->>'target' not in ('testparser', 'unknown')
group by model, target
order by vulns_per_fuzz_hour desc nulls last;
```

## 2. Live exec/s curve, one line per run

Chart as a time series: X = `start_timestamp`, Y = `execs_per_sec`, grouped/colored
by `series`. `model` + `sample_id` + `epoch` keep concurrent runs distinct.

```sql
select
  start_timestamp,
  attributes->>'target'                                                as target,
  attributes->>'model'                                                 as model,
  concat(attributes->>'model', ' / ', attributes->>'sample_id',
         ' #', attributes->>'epoch')                                   as series,
  (attributes->>'execs_per_sec')::float                                as execs_per_sec
from records
where message = 'fuzz cycle complete'
  and attributes->>'target' not in ('testparser', 'unknown')
order by start_timestamp;
```

## 3. Cumulative unique crashes over time, by model

```sql
select
  start_timestamp,
  attributes->>'model'                  as model,
  attributes->>'target'                 as target,
  (attributes->>'crashes_total')::int   as crashes_total
from records
where message = 'fuzz cycle complete'
  and attributes->>'target' not in ('testparser', 'unknown')
order by start_timestamp;
```

## 4. Coverage growth (libFuzzer PCs) per run

Real coverage signal exists only since #152 (harnesses now link the real target
library); `coverage_pcs = 0` means the harness never exercised target code.

```sql
select
  start_timestamp,
  attributes->>'target'                    as target,
  concat(attributes->>'model', ' / ',
         attributes->>'sample_id')         as series,
  (attributes->>'coverage_pcs')::int       as coverage_pcs,
  (attributes->>'max_coverage_pcs')::int   as peak_coverage_pcs
from records
where message = 'fuzz cycle complete'
  and attributes->>'target' not in ('testparser', 'unknown')
order by start_timestamp;
```

## 5. Run failure rate by model × target

```sql
select
  attributes->>'model'  as model,
  attributes->>'target' as target,
  count(*)                                                          as runs,
  sum(case when attributes->>'error' = 'true' then 1 else 0 end)    as errored,
  round(100.0 * sum(case when attributes->>'error' = 'true' then 1 else 0 end)
        / nullif(count(*), 0), 1)                                   as error_pct
from records
where message = 'eval sample'
  and attributes->>'sample.id' like 'live-fuzzing%'
  and attributes->>'target' not in ('testparser', 'unknown')
group by model, target
order by error_pct desc;
```

---

## Reading results programmatically

Logfire's HTTP query API (`GET /v1/query?sql=…`, `Authorization: Bearer <read-token>`)
returns the same data as JSON/Arrow for ad-hoc analysis. Create a read token with
`logfire auth` + the project read-tokens API (the `logfire read-tokens create` CLI
is broken in 4.36.0). Read tokens are read-only and distinct from the write token
in `.logfire/logfire_credentials.json` (which is gitignored).

## Still bespoke (out of scope for Logfire)

Per #114's final stance, the only views Logfire can't express well — and that a
future bespoke surface would own — are CASR crash-cluster drill-downs and
`SwarmResult.marginal_crash_curve` (a derived shape, not a raw time series).
Everything above is a Logfire query.

## Known issue: test telemetry pollution

The pytest suite emits `fuzz cycle complete` records to the live Logfire project
when credentials are present (some tests exercise the real `log` facade with
`_LOGFIRE_ACTIVE` set). They show up as `target = 'testparser'` or `'unknown'`
with `model = 'anthropic/test-model'` — hence the `target not in (...)` filter in
every query above. Pre-existing; a proper fix is to force the facade off (or point
`LOGFIRE_TOKEN` at a throwaway project) under pytest.
