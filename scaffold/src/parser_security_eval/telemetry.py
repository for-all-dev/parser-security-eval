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

logger = logging.getLogger(__name__)

# Provider SDKs Inspect may drive. Each is instrumented best-effort: a missing
# package or version skew must not break the eval. ``httpx`` is the catch-all
# for any provider not natively instrumented above.
_PROVIDER_INSTRUMENTERS: tuple[str, ...] = (
    "instrument_anthropic",
    "instrument_openai",
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

    _configured = True
    logger.info("Logfire telemetry configured (service=%s)", service_name)
    return True
