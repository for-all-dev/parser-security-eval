"""Logfire-backed logging facade (issue #145).

Every module in this package logs through :func:`get_log` instead of the stdlib
``logging`` module directly. The facade dispatches **per call**:

* When Logfire is installed *and* credentialed (see ``telemetry.py``), the
  message is rendered and forwarded to Logfire so logs land in the observability
  backend alongside the LLM/span telemetry from #138.
* Otherwise it degrades to vanilla stdlib :mod:`logging` so logs still reach the
  console. The facade itself *is* the degrade mechanism.

Design notes
------------
* **Dispatch at call time, not import time.** Modules build their ``log`` object
  at import (``log = get_log(__name__)``), which happens *before*
  ``configure_telemetry()`` runs. So whether Logfire is active is read fresh on
  every call via the module-level ``_LOGFIRE_ACTIVE`` flag (flipped by
  ``telemetry.set_logfire_active``).
* **Minimal-diff migration.** Methods keep the stdlib ``(msg, *args)``
  ``%s``-style signature, so the ~141 existing call sites need only a mechanical
  ``logger.`` -> ``log.`` rename (plus ``warning`` -> ``warn``, ``critical`` ->
  ``fatal``). Converting to ``{}``/structured kwargs is a deliberate follow-up.
* **Never break a caller.** The Logfire path is wrapped in ``try/except`` and
  falls through to stdlib on any failure.
* **Logs stay visible.** Because we removed the CLI ``logging.basicConfig``
  calls, the stdlib fallback path installs a sensible default handler once
  (lazily, idempotently) matching the old ``"%(levelname)s: %(message)s"`` /
  INFO behaviour.
"""

from __future__ import annotations

import logging

# Flipped to True by ``telemetry.set_logfire_active`` once Logfire is configured
# AND credentials are present. Read fresh on every log call (see module docstring).
_LOGFIRE_ACTIVE = False

# Guard so the default stdlib handler is installed at most once.
_STDLIB_CONFIGURED = False


def set_logfire_active(active: bool) -> None:
    """Toggle whether the facade routes log calls to Logfire.

    Called by ``telemetry.configure_telemetry`` after a successful
    ``logfire.configure(...)`` *and* when credentials are detected.
    """
    global _LOGFIRE_ACTIVE
    _LOGFIRE_ACTIVE = active


def _ensure_stdlib_configured() -> None:
    """Install a default root handler once, matching the old basicConfig.

    The CLI used to call ``logging.basicConfig(level=INFO,
    format="%(levelname)s: %(message)s")``. Those calls were removed with this
    facade; we reproduce that default lazily so stdlib-fallback logs still print.
    Idempotent and a no-op if logging is already configured by the host app.
    """
    global _STDLIB_CONFIGURED
    if _STDLIB_CONFIGURED:
        return
    _STDLIB_CONFIGURED = True
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def _render(msg: str, args: tuple[object, ...]) -> str:
    """Render a ``%s``-style message + positional args to a plain string."""
    if not args:
        return msg
    try:
        return msg % args
    except Exception:  # mismatched/invalid format spec; fall back to repr
        return f"{msg} {args}"


class _Log:
    """A logger facade wrapping a stdlib logger and an optional Logfire route.

    Holds a stdlib ``logging.Logger`` for the fallback path. Whether calls are
    routed to Logfire is decided per call against the module-level
    ``_LOGFIRE_ACTIVE`` flag.
    """

    __slots__ = ("_stdlib",)

    def __init__(self, name: str) -> None:
        self._stdlib = logging.getLogger(name)

    # -- public API: mirrors stdlib logger method names (warn/fatal aliases) --

    def debug(self, msg: str, *args: object, **kwargs: object) -> None:
        self._dispatch(logging.DEBUG, "debug", msg, args, kwargs)

    def info(self, msg: str, *args: object, **kwargs: object) -> None:
        self._dispatch(logging.INFO, "info", msg, args, kwargs)

    def warn(self, msg: str, *args: object, **kwargs: object) -> None:
        self._dispatch(logging.WARNING, "warn", msg, args, kwargs)

    def error(self, msg: str, *args: object, **kwargs: object) -> None:
        self._dispatch(logging.ERROR, "error", msg, args, kwargs)

    def fatal(self, msg: str, *args: object, **kwargs: object) -> None:
        self._dispatch(logging.CRITICAL, "fatal", msg, args, kwargs)

    def exception(self, msg: str, *args: object, **kwargs: object) -> None:
        """Like ``error`` but includes the active exception's traceback."""
        if _LOGFIRE_ACTIVE and self._to_logfire("exception", msg, args):
            return
        _ensure_stdlib_configured()
        self._stdlib.exception(msg, *args, **kwargs)  # type: ignore[arg-type]

    # -- dispatch ---------------------------------------------------------

    def _dispatch(
        self,
        level: int,
        method: str,
        msg: str,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> None:
        if _LOGFIRE_ACTIVE and self._to_logfire(method, msg, args):
            return
        _ensure_stdlib_configured()
        self._stdlib.log(level, msg, *args, **kwargs)  # type: ignore[arg-type]

    @staticmethod
    def _to_logfire(method: str, msg: str, args: tuple[object, ...]) -> bool:
        """Forward a rendered message to Logfire. Returns False on any failure.

        The rendered text is passed as the ``message`` attribute of a fixed
        ``"{message}"`` template so Logfire never tries to interpret literal
        braces in the rendered text as a span template (which warns/raises).
        """
        try:
            import logfire
        except Exception:
            return False
        fn = getattr(logfire, method, None)
        if fn is None:
            return False
        try:
            fn("{message}", message=_render(msg, args))
        except Exception:
            return False
        return True


def get_log(name: str) -> _Log:
    """Return a logging facade for ``name`` (use ``__name__`` per module)."""
    return _Log(name)
