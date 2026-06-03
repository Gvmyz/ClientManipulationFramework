"""Load experiment runs from disk into normalized pandas DataFrames.

A run is a directory under experiments/runs/<run_id>/ containing:
  - manifest.json   the resolved orchestration manifest written by Run-Experiment.ps1
  - telemetry.jsonl one JSON object per line, each with {experiment, event} keys

The loader produces two DataFrames:
  - runs:   one row per run (technique, label, attack_start_time, ...)
  - events: one row per event (run_id, timestamp, task, properties_*)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd


# The C++ telemetry writer formats utc_time like "2026-5-26 11:35:38.551" without
# zero-padding on month/day. Parse it permissively rather than constraining the C++ side.
_UTC_TIME_PATTERN = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{1,2})-(?P<d>\d{1,2})\s+"
    r"(?P<h>\d{1,2}):(?P<mi>\d{1,2}):(?P<s>\d{1,2})\.(?P<ms>\d+)$"
)


@dataclass
class RunPaths:
    run_id: str
    directory: Path
    manifest: Path
    telemetry: Path

    @property
    def has_telemetry(self) -> bool:
        return self.telemetry.is_file()


def discover_runs(runs_root: Path) -> list[RunPaths]:
    """Return every run directory under ``runs_root`` that has a manifest."""
    out: list[RunPaths] = []
    for entry in sorted(runs_root.iterdir()):
        if not entry.is_dir():
            continue
        manifest = entry / "manifest.json"
        if not manifest.is_file():
            continue
        out.append(RunPaths(
            run_id=entry.name,
            directory=entry,
            manifest=manifest,
            telemetry=entry / "telemetry.jsonl",
        ))
    return out


def _parse_utc_time(value: str) -> datetime | None:
    m = _UTC_TIME_PATTERN.match(value.strip()) if value else None
    if m is None:
        return None
    # Milliseconds may be 1-3 digits depending on the wall-clock value.
    ms_raw = m.group("ms")
    micro = int(ms_raw.ljust(3, "0")[:3]) * 1000
    return datetime(
        int(m.group("y")), int(m.group("mo")), int(m.group("d")),
        int(m.group("h")), int(m.group("mi")), int(m.group("s")),
        micro, tzinfo=timezone.utc,
    )


def _parse_iso_utc(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_run_metadata(run: RunPaths) -> dict:
    """Read manifest.json and project a flat dict of the fields we care about.

    Extend the returned dict to surface new manifest fields. The new key
    becomes a column on the runs DataFrame and is then available to every
    feature function via the run_meta Series.
    """
    raw = json.loads(run.manifest.read_text(encoding="utf-8-sig"))
    experiment = raw.get("experiment") or {}
    metadata = experiment.get("metadata") or {}
    timings = experiment.get("timings") or {}
    execution = raw.get("execution") or {}

    started_at = _parse_iso_utc(execution.get("startedAt") or "")
    warmup = int(timings.get("warmupSeconds") or 0)
    attack_started_at = started_at + timedelta(seconds=warmup) if started_at else None

    return {
        "run_id": run.run_id,
        "experiment_name": experiment.get("name"),
        "technique": metadata.get("technique"),
        "label": metadata.get("label"),
        "target": metadata.get("target"),
        "warmup_seconds": warmup,
        "cooldown_seconds": int(timings.get("cooldownSeconds") or 0),
        "status": execution.get("status"),
        "target_pid": execution.get("targetPid"),
        "manipulation_pid": execution.get("manipulationPid"),
        # Exit code of the manipulation tool, as recorded by Run-Experiment.ps1.
        # Surfaced as its own column so techniques whose ETW signature is empty by
        # design (e.g. external memory patching) can still be validated as
        # "tool ran cleanly" vs "tool crashed" — see features.py:compute_run_features.
        "manipulation_exit_code": execution.get("manipulationExitCode"),
        "started_at": started_at,
        "attack_started_at": attack_started_at,
        "manifest_path": str(run.manifest),
        "telemetry_path": str(run.telemetry),
        "has_telemetry": run.has_telemetry,
    }


def _iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_events(run: RunPaths) -> pd.DataFrame:
    """Flatten telemetry.jsonl into a DataFrame keyed by run_id + event ordinal.

    To surface a new property field from the ETW collector, add one more entry
    to the row dict below. Use _parse_hex for hex-string values (ImageBase,
    addresses) and _maybe_int for decimal integers (TIDs, PIDs).
    """
    rows: list[dict] = []
    for record in _iter_jsonl(run.telemetry):
        event = record.get("event") or {}
        props = event.get("properties") or {}
        rows.append({
            # Identity + envelope (stable; rarely needs extending)
            "run_id": run.run_id,
            "timestamp": _parse_utc_time(event.get("utc_time") or ""),
            "task": (event.get("task") or "").strip(),
            "opcode": (event.get("opcode") or "").strip(),
            "name": (event.get("name") or "").strip(),
            "keywords": (event.get("keywords") or "").strip(),
            "pid": event.get("pid"),
            "tid": event.get("tid"),
            "image_path": event.get("image_path") or "",
            # ----- Property bag (extend here) -----
            # ImageLoad
            "image_base": _parse_hex(props.get("ImageBase")),
            "image_size": _parse_hex(props.get("ImageSize")),
            "image_name": props.get("ImageName") or "",
            # ThreadStart / ThreadStop
            "win32_start_addr": _parse_hex(props.get("Win32StartAddr")),
            "start_addr": _parse_hex(props.get("StartAddr")),
            "thread_pid": _maybe_int(props.get("ProcessID")),
            "thread_id": _maybe_int(props.get("ThreadID")),
        })
    if not rows:
        return pd.DataFrame(columns=[
            "run_id", "timestamp", "task", "opcode", "name", "keywords",
            "pid", "tid", "image_path", "image_base", "image_size", "image_name",
            "win32_start_addr", "start_addr", "thread_pid", "thread_id",
        ])
    return pd.DataFrame(rows)


def _parse_hex(value) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16) if str(value).lower().startswith("0x") else int(str(value))
    except (TypeError, ValueError):
        return None


def _maybe_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_all(runs_root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load every run under ``runs_root`` and return (runs_df, events_df)."""
    runs = discover_runs(runs_root)
    meta_rows = [load_run_metadata(r) for r in runs]
    runs_df = pd.DataFrame(meta_rows)

    event_frames: list[pd.DataFrame] = []
    for r in runs:
        if not r.has_telemetry:
            continue
        df = load_events(r)
        if not df.empty:
            event_frames.append(df)

    if event_frames:
        events_df = pd.concat(event_frames, ignore_index=True)
    else:
        events_df = load_events(runs[0]) if runs else pd.DataFrame()

    return runs_df, events_df
