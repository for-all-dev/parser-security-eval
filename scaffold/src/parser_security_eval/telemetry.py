"""Logfire telemetry for the eval stack (issue #138).

We keep Inspect-AI as the agent/eval framework and bolt **Logfire** on for
observability.  Inspect calls the LLM provider SDKs (anthropic, openai, ...) and
``httpx`` under the hood, so instrumenting *those* libraries captures
token/latency/trace spans for every model call — with zero changes to tasks,
solvers, or scorers.  Those spans stream to Logfire live, feeding the job
dashboard (#114).

Design constraints
------------------
* **Idempotent** — ``configure_telemetry()`` may be called from several eval
  entrypoints (CLI ``evaluate``/``fuzzing``, the experiment runner, the swarm
  orchestrator); only the first call does work.
* **Never break an eval** — when Logfire is uninstalled, unconfigured, or a
  provider SDK is missing/version-skewed, this degrades to a no-op and logs at
  debug/warning level rather than raising.
* **Send only when credentialed** — ``send_to_logfire="if-token-present"`` means
  CI and local runs without ``.logfire`` creds (or ``LOGFIRE_TOKEN``) simply
  don't export, with no prompt and no failure.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from parser_security_eval import log as _log_facade

# telemetry.py is the bootstrap for the log facade, so it keeps its OWN stdlib
# logger to avoid a circular dependency (log.py must not import telemetry).
logger = logging.getLogger(__name__)

# Best-effort instrumenters (all no-arg). Inspect drives the provider SDKs; the
# tree-sitter fixer drives pydantic-ai (``instrument_pydantic_ai`` captures agent
# runs / structured output / token usage). Each is applied defensively: a missing
# package or version skew must not break a run. ``httpx`` is the catch-all for any
# provider not natively instrumented above.
_PROVIDER_INSTRUMENTERS: tuple[str, ...] = (
    "instrument_anthropic",
    "instrument_openai",
    "instrument_pydantic_ai",
)

_configured = False


def configure_telemetry(*, service_name: str = "parser-security-eval") -> bool:
    """Configure Logfire and instrument the LLM provider SDKs Inspect uses.

    Safe to call repeatedly and safe when Logfire is unavailable/unconfigured.
    Returns ``True`` if Logfire is configured (now or from a prior call),
    ``False`` if telemetry is disabled (e.g. logfire not installed or setup
    failed).
    """
    global _configured
    if _configured:
        return True

    try:
        import logfire
    except ImportError:
        logger.debug("logfire not installed; telemetry disabled")
        return False

    try:
        logfire.configure(
            service_name=service_name,
            # No-op export when there are no creds (CI, fresh checkout).
            send_to_logfire="if-token-present",
            # This is a backend/agent process; keep stdout clean for the CLI.
            console=False,
            # All our spans/logs pass fields as explicit kwargs (never bare
            # f-strings), so the source-introspection that extracts f-string vars
            # is pure overhead — and it warns noisily when source isn't available
            # (interactive shell, ``python -c``, exec, pyc-without-py). Disable it.
            inspect_arguments=False,
        )
    except Exception as exc:  # pragma: no cover - defensive; setup must not crash
        logger.warning("Logfire setup failed (continuing without telemetry): %s", exc)
        return False

    for name in _PROVIDER_INSTRUMENTERS:
        instrument = getattr(logfire, name, None)
        if instrument is None:
            continue
        try:
            instrument()
        except Exception as exc:  # provider SDK absent or incompatible
            logger.debug("logfire.%s() skipped: %s", name, exc)

    try:
        logfire.instrument_httpx()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("logfire.instrument_httpx() skipped: %s", exc)

    _register_inspect_hooks()

    # Route the log facade through Logfire only when credentials are actually
    # present (the relaxed #145 constraint is specifically about auth presence).
    # Without creds, send_to_logfire="if-token-present" exports nothing, so the
    # facade should stay on stdlib to keep logs visible on the console.
    if _logfire_credentialed():
        _log_facade.set_logfire_active(True)

    _configured = True
    logger.info("Logfire telemetry configured (service=%s)", service_name)
    return True


def _logfire_credentialed() -> bool:
    """Best-effort detection of Logfire credentials.

    True when ``LOGFIRE_TOKEN`` is set, or a logfire credentials file exists
    (logfire writes ``.logfire/logfire_credentials.json`` on auth). Detection is
    intentionally conservative: if unsure we return False so the facade stays on
    stdlib rather than silently swallowing logs into an unexported Logfire.
    """
    if os.environ.get("LOGFIRE_TOKEN"):
        return True
    creds = Path.cwd() / ".logfire" / "logfire_credentials.json"
    return creds.is_file()


# ---------------------------------------------------------------------------
# Route 2: Inspect hooks -> OTel span bridge (issue #138)
# ---------------------------------------------------------------------------
# The provider/httpx instrumentation above gives spans per LLM call but no eval
# semantics (which sample, which target, what was scored). Inspect exposes a
# ``hooks`` API with sample/task lifecycle callbacks; we bridge those into OTel
# spans carrying target/score/crash/usage attributes so the dashboard (#114) can
# query by run and target.
#
# Why detached spans (tracer.start_span) rather than ``logfire.span()``:
# the hook callbacks are async and samples run *interleaved* (sample B may start
# before sample A ends), so activating a span as the "current" context in
# on_sample_start would tangle OTel's context stack across concurrent samples,
# and provider spans run in a separate async task we cannot inject context into
# anyway. start_span() creates a span WITHOUT activating context: we hold it in a
# dict, enrich it on sample end, and end() it. These sample spans are therefore
# top-level (provider spans are correlated by run/timing, not parented) — an
# accepted limitation of bridging via hooks. Finer-grained per-cycle telemetry
# is the #114 event stream's job, not this bridge.

_HOOKS_REGISTERED = False


def _otel_tracer():
    """The OTel tracer backed by the Logfire-configured provider, or ``None``."""
    try:
        from opentelemetry import trace
    except ImportError:  # pragma: no cover - opentelemetry ships with logfire
        return None
    return trace.get_tracer("parser-security-eval")


class _SpanBridge:
    """Mirrors Inspect sample lifecycle into detached OTel spans.

    Holds spans started at sample-start, keyed by ``(eval_id, sample_id, epoch)``
    — the tuple available at *both* callbacks (the sample uuid is only populated
    at end). The tracer is resolved through ``tracer_factory`` at span-start so
    the active provider is honoured (and so tests can inject a local provider
    instead of fighting OTel's process-global, set-once tracer provider).
    """

    def __init__(self, tracer_factory=_otel_tracer) -> None:
        self._tracer_factory = tracer_factory
        self._spans: dict[str, object] = {}

    @staticmethod
    def _key(eval_id: object, sample_id: object, epoch: object) -> str:
        return f"{eval_id}/{sample_id}/{epoch}"

    def start(
        self, eval_id: object, run_id: object, sample_id: object, epoch: object
    ) -> None:
        tracer = self._tracer_factory()
        if tracer is None:  # pragma: no cover - provider torn down
            return
        span = tracer.start_span("eval sample")
        span.set_attribute("run_id", str(run_id))
        sid = _coerce_attr(sample_id)
        if sid is not None:
            span.set_attribute("sample.id", sid)
        self._spans[self._key(eval_id, sample_id, epoch)] = span

    def end(
        self, eval_id: object, sample_id: object, epoch: object, sample: object
    ) -> None:
        span = self._spans.pop(self._key(eval_id, sample_id, epoch), None)
        if span is None:
            return
        try:
            for attr, value in _sample_attributes(sample).items():
                span.set_attribute(attr, value)  # type: ignore[attr-defined]
        finally:
            span.end()  # type: ignore[attr-defined]


def _coerce_attr(value: object) -> str | int | float | bool | None:
    """Reduce a value to an OTel-legal attribute (or ``None`` to skip it)."""
    if isinstance(value, (bool, int, float, str)):
        return value
    return None


def _sample_attributes(sample: object) -> dict[str, str | int | float | bool]:
    """Flatten an Inspect ``EvalSample`` into OTel span attributes.

    Pulls target, timing, token usage, and every score (value + numeric score
    metadata, which includes the issue #135 efficiency counts: ``eff_vulns``,
    ``eff_fuzz_seconds`` and friends).
    """
    attrs: dict[str, str | int | float | bool] = {}

    sid = _coerce_attr(getattr(sample, "id", None))
    if sid is not None:
        attrs["sample.id"] = sid
    epoch = getattr(sample, "epoch", None)
    if isinstance(epoch, int):
        attrs["sample.epoch"] = epoch

    metadata = getattr(sample, "metadata", None) or {}
    target = metadata.get("target_name") or metadata.get("target")
    if isinstance(target, str):
        attrs["target"] = target

    for field in ("total_time", "working_time"):
        val = getattr(sample, field, None)
        if isinstance(val, (int, float)):
            attrs[f"sample.{field}"] = float(val)

    error = getattr(sample, "error", None)
    attrs["error"] = error is not None
    if error is not None:
        attrs["error.message"] = str(getattr(error, "message", error))[:500]

    model_usage = getattr(sample, "model_usage", None) or {}
    total_tokens = 0
    for usage in model_usage.values():
        tok = getattr(usage, "total_tokens", None)
        if isinstance(tok, int):
            total_tokens += tok
    if total_tokens:
        attrs["tokens.total"] = total_tokens

    # Record the model so dashboards can break results down by model — the core
    # research axis ("vulns per walltime as a function of model", issue #114).
    # ``model_usage`` is keyed by model name; pick the one that did the most work
    # (a sample is almost always a single model, but grader/critic calls can add
    # secondary keys we don't want to mislabel the run by).
    if model_usage:
        primary = max(
            model_usage,
            key=lambda m: getattr(model_usage[m], "total_tokens", 0) or 0,
        )
        attrs["model"] = primary

    scores = getattr(sample, "scores", None) or {}
    for name, score in scores.items():
        as_float = getattr(score, "as_float", None)
        if callable(as_float):
            try:
                attrs[f"score.{name}"] = float(as_float())
            except Exception:  # non-numeric score value
                pass
        for mk, mv in (getattr(score, "metadata", None) or {}).items():
            if isinstance(mv, (bool, int, float)):
                attrs[f"score.{name}.{mk}"] = mv

    return attrs


def _register_inspect_hooks() -> bool:
    """Register the Inspect hooks subscriber that mirrors samples into OTel.

    Idempotent and best-effort: a missing/changed Inspect hooks API disables the
    bridge rather than breaking telemetry setup. Returns whether the bridge is
    active.
    """
    global _HOOKS_REGISTERED
    if _HOOKS_REGISTERED:
        return True

    if _otel_tracer() is None:
        return False

    try:
        from inspect_ai.hooks import Hooks, SampleEnd, SampleStart, hooks
    except ImportError:  # pragma: no cover - Inspect missing/changed
        logger.debug("inspect_ai.hooks unavailable; span bridge disabled")
        return False

    @hooks(
        name="logfire_span_bridge",
        description="Mirror Inspect samples to OTel/Logfire spans",
    )
    class _LogfireSpanBridge(Hooks):
        def __init__(self) -> None:
            self._bridge = _SpanBridge()

        async def on_sample_start(self, data: SampleStart) -> None:
            self._bridge.start(
                data.eval_id,
                data.run_id,
                data.sample_id,
                getattr(data.summary, "epoch", 0),
            )

        async def on_sample_end(self, data: SampleEnd) -> None:
            self._bridge.end(
                data.eval_id,
                data.sample_id,
                getattr(data.sample, "epoch", 0),
                data.sample,
            )

    _HOOKS_REGISTERED = True
    logger.info("Logfire span bridge registered (Inspect hooks)")
    return True
