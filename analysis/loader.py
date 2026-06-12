"""Load experiment runs from disk into pandas DataFrames.

A run is a directory under experiments/runs/<run_id>/ containing:
  - manifest.json    written by Run-Experiment.ps1
  - telemetry.jsonl  one JSON object per line: {experiment, event}

load_all() returns (runs_df, events_df).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd


# Telemetry's C++ writer formats utc_time without zero-padding on month/day.
_UTC_TIME_PATTERN = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{1,2})-(?P<d>\d{1,2})\s+"
    r"(?P<h>\d{1,2}):(?P<mi>\d{1,2}):(?P<s>\d{1,2})\.(?P<ms>\d+)$"
)


# ---- Run discovery ----

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
    # Walk the runs root; a directory counts as a run iff it contains manifest.json.
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


# ---- Timestamp parsing ----


def _parse_utc_time(value: str) -> datetime | None:
    m = _UTC_TIME_PATTERN.match(value.strip()) if value else None
    if m is None:
        return None
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


# ---- Manifest loading ----

def _derive_provider_set(experiment: dict) -> str:
    """Sorted comma-joined provider-name set, e.g. "KernelProcess,Sysmon"."""
    providers = experiment.get("providers")
    if isinstance(providers, list) and providers:
        names = sorted({(p.get("name") or "").strip() for p in providers if p.get("name")})
        return ",".join(n for n in names if n)
    # Legacy single-provider manifests only ever used kernel-process.
    if experiment.get("providerGuid"):
        return "KernelProcess"
    return ""


def load_run_metadata(run: RunPaths) -> dict:
    # Read manifest.json and project the fields we care about into a flat dict.
    raw = json.loads(run.manifest.read_text(encoding="utf-8-sig"))
    experiment = raw.get("experiment") or {}
    metadata = experiment.get("metadata") or {}
    timings = experiment.get("timings") or {}
    execution = raw.get("execution") or {}

    # Wall-clock start + warmup gives us the moment the attack actually fired.
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
        "manipulation_exit_code": execution.get("manipulationExitCode"),
        "provider_set": _derive_provider_set(experiment),
        "started_at": started_at,
        "attack_started_at": attack_started_at,
        "manifest_path": str(run.manifest),
        "telemetry_path": str(run.telemetry),
        "has_telemetry": run.has_telemetry,
    }


# ---- Telemetry JSONL parsing ----

def _iter_jsonl(path: Path) -> Iterable[dict]:
    # std::wofstream defaults to the system codepage (cp1252 on Windows-en).
    # Sysmon vendor strings contain bytes like 0xAE (®) that aren't valid UTF-8.
    # Try UTF-8 first so future UTF-8-clean output works, then fall back.
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        text = path.read_text(encoding="cp1252")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


_EVENT_COLUMNS = [
    "run_id", "timestamp", "provider_name",
    "task", "opcode", "name", "keywords",
    "pid", "tid", "image_path",
    "image_base", "image_size", "image_name",
    "win32_start_addr", "start_addr", "thread_pid", "thread_id",
    "source_process_id", "target_process_id",
    "source_image", "target_image",
    "granted_access", "rule_name",
]


def load_events(run: RunPaths) -> pd.DataFrame:
    """One row per event. Defaults provider_name to "KernelProcess" for older
    runs that predate the multi-provider Telemetry build."""
    rows: list[dict] = []
    for record in _iter_jsonl(run.telemetry):
        event = record.get("event") or {}
        props = event.get("properties") or {}
        provider_name = (event.get("provider_name") or "").strip() or "KernelProcess"
        rows.append({
            # Envelope: run identity, when, who emitted, what kind of event.
            "run_id": run.run_id,
            "timestamp": _parse_utc_time(event.get("utc_time") or ""),
            "provider_name": provider_name,
            "task": (event.get("task") or "").strip(),
            "opcode": (event.get("opcode") or "").strip(),
            "name": (event.get("name") or "").strip(),
            "keywords": (event.get("keywords") or "").strip(),
            "pid": event.get("pid"),
            "tid": event.get("tid"),
            "image_path": event.get("image_path") or "",
            # KernelProcess ImageLoad properties.
            "image_base": _parse_hex(props.get("ImageBase")),
            "image_size": _parse_hex(props.get("ImageSize")),
            "image_name": props.get("ImageName") or "",
            # KernelProcess Thread{Start,Stop} properties.
            "win32_start_addr": _parse_hex(props.get("Win32StartAddr")),
            "start_addr": _parse_hex(props.get("StartAddr")),
            "thread_pid": _maybe_int(props.get("ProcessID")),
            "thread_id": _maybe_int(props.get("ThreadID")),
            # Sysmon ProcessAccess / ProcessCreate / CreateRemoteThread properties.
            # PIDs arrive as strings from TDH-formatted output.
            "source_process_id": _maybe_int(props.get("SourceProcessId")),
            "target_process_id": _maybe_int(props.get("TargetProcessId")),
            "source_image": props.get("SourceImage") or "",
            "target_image": props.get("TargetImage") or "",
            "granted_access": _parse_hex(props.get("GrantedAccess")),
            "rule_name": props.get("RuleName") or "",
        })
    if not rows:
        return pd.DataFrame(columns=_EVENT_COLUMNS)
    return pd.DataFrame(rows)


# ---- Type-tolerant helpers (Sysmon arrives as strings, kernel-process as ints) ----


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


# ---- Top-level entry point ----

def load_all(runs_root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    # Discover, load manifests, then load events. Runs with empty telemetry
    # still surface in runs_df so completeness / dropped-run counts are honest.
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
        # No events anywhere — use any run's empty schema so column types stay stable.
        events_df = load_events(runs[0]) if runs else pd.DataFrame()

    return runs_df, events_df
