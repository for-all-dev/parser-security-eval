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


# ---------------------------------------------------------------------------
# Route 2: Inspect hooks -> OTel span bridge
# ---------------------------------------------------------------------------


def test_coerce_attr(telemetry):
    c = telemetry._coerce_attr
    assert c(3) == 3
    assert c(1.5) == 1.5
    assert c("x") == "x"
    assert c(True) is True
    assert c(None) is None
    assert c([1, 2]) is None  # sequences/objects are dropped
    assert c({"a": 1}) is None


def test_sample_attributes_extracts_target_scores_and_eff_metadata(telemetry):
    from types import SimpleNamespace

    class FakeScore:
        def __init__(self, value, metadata):
            self._value = value
            self.metadata = metadata

        def as_float(self):
            return self._value

    sample = SimpleNamespace(
        id=7,
        epoch=1,
        metadata={"target_name": "libpng"},
        total_time=12.5,
        working_time=9.0,
        error=None,
        model_usage={
            "anthropic/x": SimpleNamespace(total_tokens=100),
            "anthropic/y": SimpleNamespace(total_tokens=50),
        },
        scores={
            "live_fuzzing": FakeScore(
                0.4, {"unique_crashes": 3, "eff_vulns": 3.0, "note": "skip-me"}
            )
        },
    )

    attrs = telemetry._sample_attributes(sample)
    assert attrs["sample.id"] == 7
    assert attrs["sample.epoch"] == 1
    assert attrs["target"] == "libpng"
    assert attrs["sample.total_time"] == 12.5
    assert attrs["error"] is False
    assert attrs["tokens.total"] == 150  # summed across model usages
    # model = the busiest model_usage key (the run's primary model), so dashboards
    # can break results down by model (issue #114).
    assert attrs["model"] == "anthropic/x"
    assert attrs["score.live_fuzzing"] == 0.4
    assert attrs["score.live_fuzzing.unique_crashes"] == 3
    assert attrs["score.live_fuzzing.eff_vulns"] == 3.0
    # non-numeric score metadata is dropped (OTel attrs must be scalars)
    assert "score.live_fuzzing.note" not in attrs


def test_sample_attributes_target_fallback_and_error(telemetry):
    from types import SimpleNamespace

    sample = SimpleNamespace(
        id="s1",
        epoch=2,
        metadata={"target": "zlib"},  # no target_name -> falls back to target
        error=SimpleNamespace(message="boom"),
        scores={},
    )
    attrs = telemetry._sample_attributes(sample)
    assert attrs["target"] == "zlib"
    assert attrs["error"] is True
    assert attrs["error.message"] == "boom"


def test_register_hooks_disabled_without_tracer(telemetry, monkeypatch):
    monkeypatch.setattr(telemetry, "_otel_tracer", lambda: None)
    monkeypatch.setattr(telemetry, "_HOOKS_REGISTERED", False)
    assert telemetry._register_inspect_hooks() is False


def test_span_bridge_starts_enriches_and_exports(telemetry):
    """_SpanBridge starts a span, enriches it from the sample on end, and the
    finished span carries the eval semantics.

    Uses a *local* TracerProvider + in-memory exporter (injected via the bridge's
    tracer_factory) so the test never touches OTel's process-global, set-once
    provider — making it deterministic regardless of test ordering.
    """
    from types import SimpleNamespace

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    provider = TracerProvider()  # local, not registered globally
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    bridge = telemetry._SpanBridge(tracer_factory=lambda: tracer)

    class FakeScore:
        metadata = {"unique_crashes": 2, "eff_vulns": 2.0}

        def as_float(self):
            return 1.0

    sample = SimpleNamespace(
        id=1,
        epoch=1,
        metadata={"target_name": "libpng"},
        error=None,
        scores={"live_fuzzing": FakeScore()},
    )

    bridge.start(eval_id="e1", run_id="r1", sample_id=1, epoch=1)
    # nothing exported until the span ends
    assert exporter.get_finished_spans() == ()
    bridge.end(eval_id="e1", sample_id=1, epoch=1, sample=sample)

    spans = [s for s in exporter.get_finished_spans() if s.name == "eval sample"]
    assert len(spans) == 1
    attrs = dict(spans[0].attributes or {})
    assert attrs["run_id"] == "r1"
    assert attrs["target"] == "libpng"
    assert attrs["score.live_fuzzing.unique_crashes"] == 2
    assert attrs["score.live_fuzzing.eff_vulns"] == 2.0


def test_span_bridge_end_without_start_is_noop(telemetry):
    """An end with no matching start (lost/crashed sample) must not raise."""
    bridge = telemetry._SpanBridge(tracer_factory=lambda: None)
    bridge.end(eval_id="e", sample_id=1, epoch=1, sample=object())
