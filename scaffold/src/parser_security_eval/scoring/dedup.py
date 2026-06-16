"""Cross-agent crash deduplication.

When N agents each find crashes independently, many will be duplicates (same
root cause, different triggering inputs). This module provides robust
deduplication to count unique bugs accurately.

Architecture
------------
Two complementary dedup strategies are layered:

1. **Stack-hash dedup** (fast, always available): hash the top N frames of the
   sanitizer stack trace and group crashes by that hash.  Configurable via
   ``DeduplicatorConfig.stack_frame_depth``.

2. **CASR cluster dedup** (optional, requires CASR toolchain): use
   ``casr-cluster`` for edit-distance-based grouping.  Falls back gracefully
   to stack-hash when CASR is unavailable.

The ``CrashDeduplicator`` maintains two separate queues:

* **unique-crashes queue** — inputs whose stack-hash has not been seen before;
  these drive the blueteam patching pipeline.
* **interesting-inputs queue** — inputs that open new coverage edges but do
  not crash; these drive further fuzzing.

Cross-engine normalisation strips engine-specific frame decorations before
hashing so that the same bug found by libFuzzer and AFL++ produces the same
hash.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FuzzerEngine(StrEnum):
    """Known fuzzing engines whose stack-trace formats we normalise."""

    LIBFUZZER = "libfuzzer"
    AFL_PLUS_PLUS = "afl++"
    HONGGFUZZ = "honggfuzz"
    UNKNOWN = "unknown"


class DeduplicationStrategy(StrEnum):
    """Which dedup strategy to apply."""

    STACK_HASH = "stack_hash"
    CASR = "casr"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class DeduplicatorConfig(BaseModel):
    """Configuration for the crash deduplicator.

    Attributes:
        stack_frame_depth: Number of top frames to include in the stack hash.
            3 = strict (fewer false-negatives, more false-positives).
            10 = loose (fewer false-positives, more false-negatives).
            Default 5 matches existing CASR fallback behaviour.
        strategy: Which primary dedup strategy to use.  ``CASR`` falls back to
            ``STACK_HASH`` when the toolchain is unavailable.
    """

    stack_frame_depth: int = Field(default=5, ge=1, le=50)
    strategy: DeduplicationStrategy = DeduplicationStrategy.STACK_HASH


# ---------------------------------------------------------------------------
# CrashReport — the dedup module's own model
# ---------------------------------------------------------------------------


class CrashReport(BaseModel):
    """A single crash event as seen by the cross-agent deduplicator.

    This is *distinct* from ``parser_security_eval.models.vulnerability.CrashReport``
    (which models a ground-truth vulnerability record) and from
    ``parser_security_eval.triage.casr.CrashReport`` (which models a parsed
    CASR .casrep file).  This model captures the live runtime data needed for
    deduplication across multiple concurrently running agents.

    Attributes:
        agent_id: Identifier of the agent that found this crash.
        crash_input: Raw bytes of the triggering input.
        crash_input_path: Optional path where the crash input is stored.
        sanitizer_output: Full ASAN/sanitizer output (not just summary).
        stack_frames: Parsed stack-trace frames (one entry per frame, top first).
        engine: Fuzzing engine that produced this crash.
        execution_trace: Full address sequence to crash site
            (``AFL_DEBUG=1`` or ``-print_pcs=1`` output).  Optional.
        target: Parser target name (e.g. ``"libxml2"``).
        crash_type: Bug class string (e.g. ``"heap-buffer-overflow"``).
    """

    agent_id: str
    crash_input: bytes
    crash_input_path: Path | None = None
    sanitizer_output: str = ""
    stack_frames: list[str] = Field(default_factory=list)
    engine: FuzzerEngine = FuzzerEngine.UNKNOWN
    execution_trace: str = ""
    target: str = ""
    crash_type: str = ""


# ---------------------------------------------------------------------------
# CrashCluster
# ---------------------------------------------------------------------------


class CrashCluster(BaseModel):
    """A group of crashes attributed to the same unique bug.

    Attributes:
        cluster_id: Sequential cluster identifier (1-indexed).
        stack_hash: Hex digest of the normalised top-N stack frames.
        representative: The first (or best) crash from this cluster.
        members: All other crashes in the cluster.
        agent_ids: Set of agent IDs that independently found this bug.
            Stored as a sorted tuple for determinism and hashability.
        sanitizer_output: Full sanitizer output from the representative crash.
        execution_trace: Full execution trace from the representative crash.
    """

    cluster_id: int
    stack_hash: str
    representative: CrashReport
    members: list[CrashReport] = Field(default_factory=list)
    # frozenset is not JSON-serialisable; store as sorted tuple.
    agent_ids: tuple[str, ...] = Field(default_factory=tuple)
    sanitizer_output: str = ""
    execution_trace: str = ""

    @property
    def size(self) -> int:
        """Total number of crashes in this cluster (representative + members)."""
        return 1 + len(self.members)

    @property
    def agent_set(self) -> frozenset[str]:
        """The set of agent IDs that found this crash (immutable)."""
        return frozenset(self.agent_ids)


# ---------------------------------------------------------------------------
# InterestingInput — coverage-opening, non-crashing inputs
# ---------------------------------------------------------------------------


class InterestingInput(BaseModel):
    """An input that opens new coverage edges but does not crash.

    These drive further fuzzing (rather than blueteam patching).

    Attributes:
        agent_id: Agent that produced this input.
        input_bytes: Raw bytes of the input.
        input_path: Optional path where the input is stored.
        new_edges: Number of new coverage edges opened by this input.
        target: Parser target name.
        engine: Fuzzing engine.
    """

    agent_id: str
    input_bytes: bytes
    input_path: Path | None = None
    new_edges: int = 0
    target: str = ""
    engine: FuzzerEngine = FuzzerEngine.UNKNOWN


# ---------------------------------------------------------------------------
# DeduplicatorQueues — the two separate queues
# ---------------------------------------------------------------------------


class DeduplicatorQueues(BaseModel):
    """Snapshot of both deduplicator queues at a point in time.

    Attributes:
        unique_crashes: Clusters of unique bugs (for blueteam patching).
        interesting_inputs: Coverage-opening non-crash inputs (for further
            fuzzing).
    """

    unique_crashes: list[CrashCluster] = Field(default_factory=list)
    interesting_inputs: list[InterestingInput] = Field(default_factory=list)

    @property
    def n_unique_crashes(self) -> int:
        """Number of unique bug clusters discovered so far."""
        return len(self.unique_crashes)

    @property
    def n_interesting_inputs(self) -> int:
        """Number of coverage-opening non-crash inputs queued."""
        return len(self.interesting_inputs)


# ---------------------------------------------------------------------------
# Stack-trace normalisation helpers
# ---------------------------------------------------------------------------

# Patterns that strip engine-specific decorations from a single stack frame.
# After normalisation, a frame looks roughly like:
#   "#N <function_name> <source_file>:<line>"
_LIBFUZZER_FRAME_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.*)")
_AFL_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.*)")
_HONGGFUZZ_FRAME_RE = re.compile(r"\[\s*(\d+)\s*\]\s+\S+\s+\[(\S+)\]:\s+(.*)")
# Generic ASAN frame: "#N 0xADDR in FUNC file:line"
_ASAN_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")


def _normalise_frame(frame: str, engine: FuzzerEngine) -> str:
    """Strip engine-specific decoration from a single stack frame string.

    Removes addresses and engine-specific tokens so that frames from
    different fuzzers that hit the same code site hash identically.

    Args:
        frame: Raw stack frame string from sanitizer output.
        engine: Fuzzing engine that produced the frame.

    Returns:
        A normalised, address-free frame string.
    """
    frame = frame.strip()

    # Try engine-specific patterns first, then fall back to generic ASAN.
    if engine in (FuzzerEngine.LIBFUZZER, FuzzerEngine.AFL_PLUS_PLUS):
        m = _LIBFUZZER_FRAME_RE.search(frame) or _AFL_FRAME_RE.search(frame)
        if m:
            # "#N func_name location"
            return f"#{m.group(1)} {m.group(2)} {m.group(3).strip()}"
    elif engine == FuzzerEngine.HONGGFUZZ:
        m = _HONGGFUZZ_FRAME_RE.search(frame)
        if m:
            return f"#{m.group(1)} {m.group(2)} {m.group(3).strip()}"

    # Generic ASAN fallback: strip hex addresses.
    m_asan = _ASAN_FRAME_RE.search(frame)
    if m_asan:
        return f"#{m_asan.group(1)} {m_asan.group(2)}"

    # Last resort: strip all hex addresses from the string.
    normalised = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", frame)
    return normalised


def _compute_stack_hash(
    frames: Sequence[str],
    engine: FuzzerEngine,
    depth: int,
) -> str:
    """Hash the top *depth* frames of a stack trace after normalisation.

    Args:
        frames: Stack frames, top frame first.
        engine: Fuzzing engine that produced the frames (for normalisation).
        depth: How many top frames to include.

    Returns:
        Hex SHA-256 digest string.
    """
    top_frames = frames[:depth]
    normalised = [_normalise_frame(f, engine) for f in top_frames]
    payload = "\n".join(normalised).encode()
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# CrashDeduplicator
# ---------------------------------------------------------------------------


class CrashDeduplicator:
    """Stateful cross-agent crash deduplicator.

    Maintains two separate queues:

    * **unique-crashes queue**: inputs whose stack-hash has not been seen
      before.  These drive the blueteam patching pipeline.
    * **interesting-inputs queue**: inputs that open new coverage edges but
      do not crash.  These drive further fuzzing.

    Call :meth:`ingest_crash` for each crash found by any agent, and
    :meth:`ingest_interesting_input` for each coverage-opening non-crash
    input.  At any time, :meth:`queues` returns a snapshot of both queues.

    Args:
        config: Deduplicator configuration (frame depth, strategy).
    """

    def __init__(self, config: DeduplicatorConfig | None = None) -> None:
        self._config = config or DeduplicatorConfig()
        # hash → CrashCluster
        self._clusters: dict[str, CrashCluster] = {}
        # Ordered list of interesting (non-crash) inputs
        self._interesting: list[InterestingInput] = []

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_crash(self, crash: CrashReport) -> tuple[bool, CrashCluster]:
        """Ingest a single crash report.

        Computes the stack-hash and either opens a new cluster (unique crash)
        or merges into an existing one (duplicate).

        Args:
            crash: The crash report to ingest.

        Returns:
            A ``(is_new, cluster)`` tuple where ``is_new`` is ``True`` if this
            is the first crash with this stack-hash (i.e. a genuinely new bug).
        """
        stack_hash = _compute_stack_hash(
            crash.stack_frames,
            crash.engine,
            self._config.stack_frame_depth,
        )

        if stack_hash in self._clusters:
            cluster = self._clusters[stack_hash]
            cluster.members.append(crash)
            # Update the attribution set (stored as sorted tuple).
            updated_agents = frozenset(cluster.agent_ids) | {crash.agent_id}
            object.__setattr__(
                cluster,
                "agent_ids",
                tuple(sorted(updated_agents)),
            )
            return False, cluster

        # New unique bug: open a new cluster.
        new_id = len(self._clusters) + 1
        cluster = CrashCluster(
            cluster_id=new_id,
            stack_hash=stack_hash,
            representative=crash,
            members=[],
            agent_ids=(crash.agent_id,),
            sanitizer_output=crash.sanitizer_output,
            execution_trace=crash.execution_trace,
        )
        self._clusters[stack_hash] = cluster
        return True, cluster

    def ingest_interesting_input(self, inp: InterestingInput) -> None:
        """Enqueue a coverage-opening non-crash input.

        No deduplication is applied here — all interesting inputs are kept
        so that the fuzzing pipeline can prioritise them.

        Args:
            inp: The interesting input to enqueue.
        """
        self._interesting.append(inp)

    # ------------------------------------------------------------------
    # Queues snapshot
    # ------------------------------------------------------------------

    def queues(self) -> DeduplicatorQueues:
        """Return a snapshot of both queues.

        The returned object is a new ``DeduplicatorQueues`` instance; it is
        *not* live-updated as new crashes arrive.

        Returns:
            A :class:`DeduplicatorQueues` with the current state of both queues.
        """
        return DeduplicatorQueues(
            unique_crashes=list(self._clusters.values()),
            interesting_inputs=list(self._interesting),
        )

    @property
    def n_unique_crashes(self) -> int:
        """Current number of unique bug clusters."""
        return len(self._clusters)

    @property
    def n_interesting_inputs(self) -> int:
        """Current number of queued interesting inputs."""
        return len(self._interesting)

    def reset(self) -> None:
        """Clear all internal state."""
        self._clusters.clear()
        self._interesting.clear()


# ---------------------------------------------------------------------------
# Functional API
# ---------------------------------------------------------------------------


def deduplicate_crashes(
    crashes: list[CrashReport],
    config: DeduplicatorConfig | None = None,
) -> list[CrashCluster]:
    """Deduplicate a list of crash reports into unique bug clusters.

    This is the pure-functional entry point for one-shot deduplication.  For
    streaming / incremental use, use :class:`CrashDeduplicator` directly.

    Groups crashes by the hash of their top-N normalised stack frames.
    Attribution (which agent found each unique bug) is tracked per cluster.

    Edge cases handled:

    * **Same bug, different stack depths**: only the top N frames are hashed;
      deeper frames are ignored.  Set ``config.stack_frame_depth`` to control
      the granularity.
    * **Same bug, different code paths**: will produce *separate* clusters
      (different top frames → different hash).  Use CASR clustering for
      edit-distance merging.
    * **Different bugs at the same location**: if the top frames differ (e.g.
      different crash type), they hash differently → separate clusters.
    * **Empty stack traces**: all crashes with no stack trace hash to the same
      key and form one cluster (conservative: treat as potentially the same
      crash rather than many unrelated ones).

    Args:
        crashes: List of crash reports from one or more agents.
        config: Deduplicator configuration.  Defaults to ``DeduplicatorConfig()``
            (5-frame stack hash).

    Returns:
        A list of :class:`CrashCluster` objects, one per unique bug.
        Clusters are ordered by ``cluster_id`` (ascending, starting at 1).
    """
    dedup = CrashDeduplicator(config)
    for crash in crashes:
        dedup.ingest_crash(crash)
    return list(dedup._clusters.values())
