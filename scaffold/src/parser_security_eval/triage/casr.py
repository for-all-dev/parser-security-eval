"""CASR crash triage integration.

CASR (Crash Analysis and Severity Report) is a tool for analyzing and
deduplicating crash reports produced by sanitizer-instrumented binaries.

This module provides:
- Pydantic models for CASR JSON output
- CASRTriager: runs CASR inside a Docker container or locally
- Fallback stack-hash deduplication when CASR is not available
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import tempfile
from enum import Enum
from pathlib import Path
from typing import cast

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class Exploitability(str, Enum):
    """CASR exploitability classification."""

    EXPLOITABLE = "EXPLOITABLE"
    PROBABLY_EXPLOITABLE = "PROBABLY_EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    UNKNOWN = "UNKNOWN"


class CrashSeverity(BaseModel):
    """Severity information from a CASR report."""

    short_description: str
    exploitability: Exploitability
    description: str = ""


class CrashReport(BaseModel):
    """Parsed CASR report for a single crash."""

    crash_file: Path
    casr_report_file: Path | None = None
    crash_line: str = ""
    severity: CrashSeverity | None = None
    stacktrace: list[str] = []
    title: str = ""

    @classmethod
    def from_casr_json(
        cls,
        data: dict[str, object],
        crash_file: Path,
        report_file: Path | None = None,
    ) -> "CrashReport":
        """Build a CrashReport from a parsed CASR JSON dict.

        Parameters
        ----------
        data:
            Parsed JSON from a .casrep file.
        crash_file:
            Path to the original crash input file.
        report_file:
            Optional path to the .casrep file itself.
        """
        crash_line = str(data.get("CrashLine", ""))
        title = str(data.get("Title", ""))

        stacktrace_raw = data.get("Stacktrace", [])
        stacktrace: list[str] = (
            [str(frame) for frame in stacktrace_raw]
            if isinstance(stacktrace_raw, list)
            else []
        )

        severity: CrashSeverity | None = None
        severity_raw = data.get("CrashSeverity")
        if isinstance(severity_raw, dict):
            sev_dict = cast("dict[str, object]", severity_raw)
            short_desc = str(sev_dict.get("ShortDescription", ""))
            description = str(sev_dict.get("Description", ""))
            exploit_str = str(
                sev_dict.get("Exploitability", Exploitability.UNKNOWN.value)
            )
            try:
                exploitability = Exploitability(exploit_str)
            except ValueError:
                exploitability = Exploitability.UNKNOWN
            severity = CrashSeverity(
                short_description=short_desc,
                exploitability=exploitability,
                description=description,
            )

        return cls(
            crash_file=crash_file,
            casr_report_file=report_file,
            crash_line=crash_line,
            severity=severity,
            stacktrace=stacktrace,
            title=title,
        )


class CrashCluster(BaseModel):
    """A group of crashes with the same root cause."""

    cluster_id: int
    representative: CrashReport
    members: list[CrashReport] = []

    @property
    def size(self) -> int:
        """Total number of crashes in this cluster (representative + members)."""
        return 1 + len(self.members)


class TriageResult(BaseModel):
    """Complete triage result for a fuzzing campaign's crashes."""

    target_name: str
    total_crashes: int
    clusters: list[CrashCluster]
    exploitable_count: int = 0
    probably_exploitable_count: int = 0
    not_exploitable_count: int = 0
    unknown_count: int = 0

    def summary(self) -> str:
        """Return a human-readable triage summary."""
        lines: list[str] = [
            f"Triage result for: {self.target_name}",
            f"  Total crashes:          {self.total_crashes}",
            f"  Unique clusters:        {len(self.clusters)}",
            f"  Exploitable:            {self.exploitable_count}",
            f"  Probably exploitable:   {self.probably_exploitable_count}",
            f"  Not exploitable:        {self.not_exploitable_count}",
            f"  Unknown:                {self.unknown_count}",
        ]
        if self.clusters:
            lines.append("")
            lines.append("Clusters:")
            for cluster in self.clusters:
                rep = cluster.representative
                exploit_label = ""
                if rep.severity:
                    exploit_label = f" [{rep.severity.exploitability.value}]"
                title_label = f" — {rep.title}" if rep.title else ""
                lines.append(
                    f"  #{cluster.cluster_id} (size={cluster.size}){exploit_label}"
                    f"{title_label}"
                )
                if rep.crash_line:
                    lines.append(f"    crash_line: {rep.crash_line}")
        return "\n".join(lines)


class CASRTriager:
    """Runs CASR triage inside a Docker container or locally."""

    def __init__(
        self,
        container_id: str | None = None,
        work_dir: Path | None = None,
    ) -> None:
        """
        Parameters
        ----------
        container_id:
            If set, runs CASR commands via ``docker exec <container_id>``.
        work_dir:
            Local temp dir for output files. Defaults to a fresh tempdir.
        """
        self.container_id = container_id
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="casr-triage-"))

    async def triage_crashes(
        self,
        crashes_dir: Path,
        target_name: str,
        binary_path: str | None = None,
    ) -> TriageResult:
        """Triage all crash files in *crashes_dir*.

        If CASR is available (``casr-san`` binary found), uses it to produce
        .casrep files and then deduplicates with ``casr-cluster``.  Otherwise
        falls back to stack-hash deduplication of any existing .casrep files,
        or groups every crash into its own cluster.

        Parameters
        ----------
        crashes_dir:
            Directory containing crash input files.
        target_name:
            Human-readable name for the fuzzing target.
        binary_path:
            Path to the sanitized binary (required for ``casr-san``).
        """
        crash_files = sorted(crashes_dir.iterdir()) if crashes_dir.exists() else []
        crash_files = [f for f in crash_files if f.is_file()]

        if not crash_files:
            return TriageResult(
                target_name=target_name,
                total_crashes=0,
                clusters=[],
            )

        reports: list[CrashReport] = []
        casr_ok = await self._casr_available()

        if casr_ok and binary_path:
            reports_dir = self.work_dir / "casrep"
            reports_dir.mkdir(parents=True, exist_ok=True)

            for crash_file in crash_files:
                casrep_path = reports_dir / f"{crash_file.name}.casrep"
                raw = await self._run_casr_san(crash_file, binary_path)
                if raw is not None:
                    casrep_path.write_text(json.dumps(raw))
                    report = CrashReport.from_casr_json(
                        raw, crash_file, report_file=casrep_path
                    )
                else:
                    report = CrashReport(crash_file=crash_file)
                reports.append(report)

            clusters = await self._run_casr_cluster(reports_dir)
            if not clusters:
                clusters = self._stack_hash_dedup(reports)
        else:
            # Fallback: build minimal reports and use stack-hash dedup
            for crash_file in crash_files:
                reports.append(CrashReport(crash_file=crash_file))
            clusters = self._stack_hash_dedup(reports)

        # Count exploitability
        exploitable = 0
        probably_exploitable = 0
        not_exploitable = 0
        unknown = 0
        for cluster in clusters:
            sev = cluster.representative.severity
            if sev is None:
                unknown += 1
            elif sev.exploitability == Exploitability.EXPLOITABLE:
                exploitable += 1
            elif sev.exploitability == Exploitability.PROBABLY_EXPLOITABLE:
                probably_exploitable += 1
            elif sev.exploitability == Exploitability.NOT_EXPLOITABLE:
                not_exploitable += 1
            else:
                unknown += 1

        return TriageResult(
            target_name=target_name,
            total_crashes=len(crash_files),
            clusters=clusters,
            exploitable_count=exploitable,
            probably_exploitable_count=probably_exploitable,
            not_exploitable_count=not_exploitable,
            unknown_count=unknown,
        )

    async def _casr_available(self) -> bool:
        """Check if casr-san is available (locally or in container)."""
        rc, _out, _err = await self._exec("which casr-san")
        return rc == 0

    async def _run_casr_san(
        self, crash_file: Path, binary_path: str
    ) -> dict[str, object] | None:
        """Run casr-san on a single crash file, return parsed JSON or None.

        casr-san writes a .casrep JSON file; we capture stdout for the JSON.
        """
        casrep_out = str(self.work_dir / f"{crash_file.name}.casrep")
        cmd = f"casr-san --output {casrep_out} -- {binary_path} {crash_file}"
        rc, stdout, stderr = await self._exec(cmd)
        if rc != 0:
            logger.debug("casr-san failed (rc=%d) for %s: %s", rc, crash_file, stderr)
            return None

        # Try reading the output file first, then stdout
        out_path = Path(casrep_out)
        if out_path.exists():
            try:
                raw = json.loads(out_path.read_text())
                if isinstance(raw, dict):
                    return cast("dict[str, object]", raw)
            except json.JSONDecodeError:
                pass

        if stdout.strip():
            try:
                raw = json.loads(stdout)
                if isinstance(raw, dict):
                    return cast("dict[str, object]", raw)
            except json.JSONDecodeError:
                pass

        return None

    async def _run_casr_cluster(self, reports_dir: Path) -> list[CrashCluster]:
        """Run casr-cluster on a directory of .casrep files.

        casr-cluster groups similar crashes and writes them into numbered
        subdirectories.  We parse those subdirectories to reconstruct clusters.
        """
        cluster_out = str(self.work_dir / "clusters")
        cmd = f"casr-cluster -c {reports_dir} {cluster_out}"
        rc, _stdout, stderr = await self._exec(cmd)
        if rc != 0:
            logger.debug("casr-cluster failed (rc=%d): %s", rc, stderr)
            return []

        clusters: list[CrashCluster] = []
        cluster_root = Path(cluster_out)
        if not cluster_root.exists():
            return []

        for subdir in sorted(cluster_root.iterdir()):
            if not subdir.is_dir():
                continue
            casrep_files = sorted(subdir.glob("*.casrep"))
            if not casrep_files:
                continue

            member_reports: list[CrashReport] = []
            for casrep_file in casrep_files:
                try:
                    parsed = json.loads(casrep_file.read_text())
                except json.JSONDecodeError, OSError:
                    continue
                if not isinstance(parsed, dict):
                    continue
                raw_dict = cast("dict[str, object]", parsed)
                # Recover original crash file path from stem
                crash_file = casrep_file.with_suffix("")
                report = CrashReport.from_casr_json(
                    raw_dict, crash_file, report_file=casrep_file
                )
                member_reports.append(report)

            if not member_reports:
                continue

            try:
                cluster_id = int(subdir.name)
            except ValueError:
                cluster_id = len(clusters) + 1

            clusters.append(
                CrashCluster(
                    cluster_id=cluster_id,
                    representative=member_reports[0],
                    members=member_reports[1:],
                )
            )

        return clusters

    def _stack_hash_dedup(self, reports: list[CrashReport]) -> list[CrashCluster]:
        """Fallback deduplication: hash top-5 stack frames.

        Groups crashes by the hash of their top-5 stack frames into clusters.
        Reports with no stack trace each become their own singleton cluster.
        """
        hash_to_reports: dict[str, list[CrashReport]] = {}

        for report in reports:
            top5 = report.stacktrace[:5]
            key = hashlib.sha256("\n".join(top5).encode()).hexdigest()
            hash_to_reports.setdefault(key, []).append(report)

        clusters: list[CrashCluster] = []
        for cluster_id, (_, group) in enumerate(
            sorted(hash_to_reports.items()), start=1
        ):
            clusters.append(
                CrashCluster(
                    cluster_id=cluster_id,
                    representative=group[0],
                    members=group[1:],
                )
            )

        return clusters

    async def _exec(self, cmd: str) -> tuple[int, str, str]:
        """Run a shell command locally or via docker exec.

        Returns (exit_code, stdout, stderr).
        """
        if self.container_id:
            args = ["docker", "exec", self.container_id, "bash", "-c", cmd]
        else:
            args = ["bash", "-c", cmd]

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        return (
            proc.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )
