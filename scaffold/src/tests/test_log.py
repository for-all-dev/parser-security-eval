"""Tests for the Logfire-backed logging facade (issue #145).

Two paths must hold:

* **Logfire-active** — calls render the ``%s`` message and forward it to Logfire
  as a plain ``{message}`` template (literal braces in the text never get
  treated as a span template). A fake recording logfire captures the calls.
* **Stdlib fallback** — when Logfire is inactive (or fails), calls go through
  stdlib ``logging`` with positional ``%s`` args preserved exactly.
"""

from __future__ import annotations

import logging

import pytest

from parser_security_eval import log as logmod


@pytest.fixture
def facade():
    """Reset the module-level active flag around each test."""
    logmod.set_logfire_active(False)
    yield logmod
    logmod.set_logfire_active(False)


def test_get_log_returns_facade(facade):
    log = facade.get_log("x.y")
    assert isinstance(log, facade._Log)


def test_stdlib_fallback_renders_percent_args(facade, caplog):
    """Inactive Logfire -> stdlib logger, %s args rendered by stdlib."""
    log = facade.get_log("test.fallback")
    with caplog.at_level(logging.INFO, logger="test.fallback"):
        log.info("found %d crashes in %s", 3, "libpng")
    assert "found 3 crashes in libpng" in caplog.text


def test_warn_and_fatal_map_to_stdlib_levels(facade, caplog):
    log = facade.get_log("test.levels")
    with caplog.at_level(logging.DEBUG, logger="test.levels"):
        log.warn("a warning")
        log.fatal("a fatal")
    records = {r.levelno: r.getMessage() for r in caplog.records}
    assert records[logging.WARNING] == "a warning"
    assert records[logging.CRITICAL] == "a fatal"


def test_exception_includes_traceback(facade, caplog):
    log = facade.get_log("test.exc")
    with caplog.at_level(logging.ERROR, logger="test.exc"):
        try:
            raise ValueError("boom")
        except ValueError:
            log.exception("handling %s", "failure")
    rec = caplog.records[-1]
    assert rec.getMessage() == "handling failure"
    assert rec.exc_info is not None  # traceback captured


def test_render_helper(facade):
    assert facade._render("plain", ()) == "plain"
    assert facade._render("%d-%s", (1, "a")) == "1-a"
    # mismatched format spec degrades instead of raising
    degraded = facade._render("%d", ("not-an-int",))
    assert "not-an-int" in degraded


def test_logfire_active_routes_rendered_message(facade, monkeypatch):
    """Active Logfire path renders args and sends a plain {message} template."""
    calls: list[tuple[str, str, dict]] = []

    class FakeLogfire:
        def info(self, template, **kwargs):
            calls.append(("info", template, kwargs))

        def warn(self, template, **kwargs):
            calls.append(("warn", template, kwargs))

        def fatal(self, template, **kwargs):
            calls.append(("fatal", template, kwargs))

        def exception(self, template, **kwargs):
            calls.append(("exception", template, kwargs))

    monkeypatch.setitem(__import__("sys").modules, "logfire", FakeLogfire())
    facade.set_logfire_active(True)

    log = facade.get_log("test.lf")
    log.info("found %d in %s", 2, "zlib")
    log.warn("careful")

    assert ("info", "{message}", {"message": "found 2 in zlib"}) in calls
    assert ("warn", "{message}", {"message": "careful"}) in calls


def test_logfire_braces_in_text_are_not_a_template(facade, monkeypatch):
    """Literal braces in the rendered text must be sent as data, not a template,
    so Logfire never tries to interpret them."""
    captured: dict[str, object] = {}

    class FakeLogfire:
        def info(self, template, **kwargs):
            captured["template"] = template
            captured["kwargs"] = kwargs

    monkeypatch.setitem(__import__("sys").modules, "logfire", FakeLogfire())
    facade.set_logfire_active(True)

    facade.get_log("test.braces").info("json was {not a template}")
    assert captured["template"] == "{message}"
    assert captured["kwargs"] == {"message": "json was {not a template}"}


def test_logfire_failure_falls_back_to_stdlib(facade, monkeypatch, caplog):
    """If the Logfire call raises, the facade falls through to stdlib."""

    class ExplodingLogfire:
        def info(self, template, **kwargs):
            raise RuntimeError("logfire down")

    monkeypatch.setitem(__import__("sys").modules, "logfire", ExplodingLogfire())
    facade.set_logfire_active(True)

    log = facade.get_log("test.lffail")
    with caplog.at_level(logging.INFO, logger="test.lffail"):
        log.info("still %s", "logged")
    assert "still logged" in caplog.text
