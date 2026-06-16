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


def test_logfire_structured_kwargs_become_attributes(facade, monkeypatch):
    """Structured kwargs reach Logfire as real attributes alongside the message."""
    captured: dict[str, object] = {}

    class FakeLogfire:
        def info(self, template, **kwargs):
            captured["template"] = template
            captured["kwargs"] = kwargs

    monkeypatch.setitem(__import__("sys").modules, "logfire", FakeLogfire())
    facade.set_logfire_active(True)

    facade.get_log("test.kw").info("fuzzer exited", exit_code=139, target="libpng")
    assert captured["template"] == "{message}"
    assert captured["kwargs"] == {
        "message": "fuzzer exited",
        "exit_code": 139,
        "target": "libpng",
    }


def test_logfire_caller_message_kwarg_does_not_shadow(facade, monkeypatch):
    """A caller kwarg named ``message`` must not overwrite the rendered message."""
    captured: dict[str, object] = {}

    class FakeLogfire:
        def info(self, template, **kwargs):
            captured["kwargs"] = kwargs

    monkeypatch.setitem(__import__("sys").modules, "logfire", FakeLogfire())
    facade.set_logfire_active(True)

    facade.get_log("test.collide").info("real message", message="injected")
    assert captured["kwargs"] == {"message": "real message"}


def test_logfire_no_kwargs_unchanged(facade, monkeypatch):
    """No-kwargs Logfire path is byte-for-byte unchanged (only the message attr)."""
    captured: dict[str, object] = {}

    class FakeLogfire:
        def info(self, template, **kwargs):
            captured["template"] = template
            captured["kwargs"] = kwargs

    monkeypatch.setitem(__import__("sys").modules, "logfire", FakeLogfire())
    facade.set_logfire_active(True)

    facade.get_log("test.nokw").info("found %d in %s", 2, "zlib")
    assert captured["template"] == "{message}"
    assert captured["kwargs"] == {"message": "found 2 in zlib"}


def test_stdlib_fallback_structured_kwargs_preserved(facade, caplog):
    """Structured kwargs must NOT raise on the stdlib path and ARE appended."""
    log = facade.get_log("test.kwfallback")
    with caplog.at_level(logging.INFO, logger="test.kwfallback"):
        log.info("fuzzer exited", exit_code=139, target="libpng")
    msg = caplog.records[-1].getMessage()
    assert "fuzzer exited" in msg
    assert "exit_code=139" in msg
    assert "target=libpng" in msg


def test_stdlib_fallback_mixes_args_and_kwargs(facade, caplog):
    """%s args render and attribute kwargs append on the stdlib path."""
    log = facade.get_log("test.mix")
    with caplog.at_level(logging.INFO, logger="test.mix"):
        log.info("collected %d crashes", 3, target="zlib")
    msg = caplog.records[-1].getMessage()
    assert "collected 3 crashes" in msg
    assert "target=zlib" in msg


def test_stdlib_fallback_passes_real_logging_kwargs(facade, caplog):
    """Genuine stdlib log kwargs (exc_info) pass through, attrs still append."""
    log = facade.get_log("test.exckw")
    with caplog.at_level(logging.ERROR, logger="test.exckw"):
        try:
            raise ValueError("boom")
        except ValueError:
            log.error("op failed", exc_info=True, target="libxml2")
    rec = caplog.records[-1]
    assert "op failed" in rec.getMessage()
    assert "target=libxml2" in rec.getMessage()
    assert rec.exc_info is not None


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
