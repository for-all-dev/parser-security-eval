"""Tests for Logfire telemetry wiring (issue #138).

These assert the *contract* — idempotency and graceful degradation — without
requiring real Logfire credentials or network. ``configure_telemetry()`` must
never raise and must never export when uncredentialed.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def telemetry():
    """Fresh telemetry module with its module-level guard reset per test."""
    mod = importlib.import_module("parser_security_eval.telemetry")
    mod._configured = False
    yield mod
    mod._configured = False


def test_configure_is_idempotent(telemetry, monkeypatch):
    """Only the first call does work; subsequent calls short-circuit to True."""
    calls: list[str] = []

    class FakeLogfire:
        def configure(self, **kwargs):
            calls.append("configure")

        def instrument_anthropic(self):
            calls.append("anthropic")

        def instrument_openai(self):
            calls.append("openai")

        def instrument_httpx(self):
            calls.append("httpx")

    monkeypatch.setitem(
        __import__("sys").modules,
        "logfire",
        FakeLogfire(),
    )

    assert telemetry.configure_telemetry() is True
    assert telemetry.configure_telemetry() is True
    # configure() ran exactly once despite two calls.
    assert calls.count("configure") == 1


def test_send_to_logfire_is_if_token_present(telemetry, monkeypatch):
    """We must pass send_to_logfire='if-token-present' so uncredentialed runs
    (CI, fresh checkout) never export and never prompt."""
    captured: dict[str, object] = {}

    class FakeLogfire:
        def configure(self, **kwargs):
            captured.update(kwargs)

        def instrument_anthropic(self):
            pass

        def instrument_openai(self):
            pass

        def instrument_httpx(self):
            pass

    monkeypatch.setitem(__import__("sys").modules, "logfire", FakeLogfire())

    telemetry.configure_telemetry()
    assert captured["send_to_logfire"] == "if-token-present"
    assert captured["console"] is False


def test_missing_logfire_is_noop(telemetry, monkeypatch):
    """If logfire isn't importable, telemetry disables cleanly (returns False)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "logfire":
            raise ImportError("no logfire")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert telemetry.configure_telemetry() is False
    assert telemetry._configured is False


def test_setup_failure_does_not_raise(telemetry, monkeypatch):
    """A failure inside logfire.configure() must not bubble up and break an eval."""

    class ExplodingLogfire:
        def configure(self, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setitem(__import__("sys").modules, "logfire", ExplodingLogfire())

    assert telemetry.configure_telemetry() is False


def test_provider_instrument_failure_is_tolerated(telemetry, monkeypatch):
    """A missing/incompatible provider SDK is skipped; configuration still
    succeeds and httpx still gets instrumented."""
    calls: list[str] = []

    class PartialLogfire:
        def configure(self, **kwargs):
            calls.append("configure")

        def instrument_anthropic(self):
            raise RuntimeError("anthropic sdk missing")

        # no instrument_openai attribute at all -> getattr returns None, skipped

        def instrument_httpx(self):
            calls.append("httpx")

    monkeypatch.setitem(__import__("sys").modules, "logfire", PartialLogfire())

    assert telemetry.configure_telemetry() is True
    assert "configure" in calls
    assert "httpx" in calls
