"""Per-run feature extraction: each feature reduces one run's events to a
single number or boolean for comparison across techniques and provider sets."""

from __future__ import annotations

import pandas as pd

from . import detectors


def _split_at_attack(events: pd.DataFrame, attack_started_at) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split a run's events into (before_attack, after_attack) by wall-clock time."""
    if attack_started_at is None or events.empty:
        return events.iloc[0:0], events
    has_ts = events["timestamp"].notna()
    before = events[has_ts & (events["timestamp"] < attack_started_at)]
    after = events[has_ts & (events["timestamp"] >= attack_started_at)]
    return before, after


# Techniques whose kernel-process ETW signature is empty by design. For these
# we judge completeness by the manipulation tool's exit code instead of by
# event counts — the empty trace is the measurement.
EMPTY_TRACE_TECHNIQUES = frozenset({"memorypatch"})


def _classify_completeness(
    technique: str,
    image_loads_total: int,
    manipulation_exit_code,
    n_events: int,
) -> tuple[bool, bool]:
    """Return (is_valid_run, is_complete_run).

    Three technique classes, three validity rules:
      - baseline (``none``): any event captured.
      - empty-trace techniques: manipulation tool exited with code 0.
      - injection techniques: ≥10 ImageLoad events (the DLL dependency
        cascade an injection drags in).
    """
    is_valid_event_based = n_events > 0
    is_valid_exit_based = manipulation_exit_code == 0

    if technique in ("none", ""):
        return is_valid_event_based, is_valid_event_based

    if technique in EMPTY_TRACE_TECHNIQUES:
        return is_valid_exit_based, is_valid_exit_based

    return is_valid_event_based, bool(image_loads_total >= 10)


def _kernel_process_events(events: pd.DataFrame) -> pd.DataFrame:
    """Subset of events from the kernel-process provider only.

    Used to scope kernel-process features so they don't double-count Sysmon's
    Event 7 (ImageLoad) when both providers are active in the same session.
    """
    if "provider_name" not in events.columns or events.empty:
        return events
    return events[events["provider_name"] == "KernelProcess"]


def compute_run_features(
    run_meta: pd.Series,
    events: pd.DataFrame,
) -> dict:
    # Scope kernel-process counts to that provider and split into pre/post-attack.
    attack_started_at = run_meta.get("attack_started_at")
    kp_events = _kernel_process_events(events)
    _, kp_post = _split_at_attack(kp_events, attack_started_at)

    # PIDs used by every scoped detector; declared up here so kernel-process
    # detectors can consume ``target_pid`` too.
    target_pid = run_meta.get("target_pid")
    attacker_pid = run_meta.get("manipulation_pid")

    # Kernel-process event counts.
    image_loads_total = int((kp_events["task"] == "ImageLoad").sum())
    image_loads_post = int((kp_post["task"] == "ImageLoad").sum())
    thread_starts_post = int((kp_post["task"] == "ThreadStart").sum())
    thread_stops_post = int((kp_post["task"] == "ThreadStop").sum())

    # Kernel-process behavioral detectors. injected_dll_observed is scoped to
    # the target PID so the injector's own local LoadLibrary (from --call
    # export-offset resolution) does not fire a false positive on manualmap.
    dll_observed = detectors.injected_dll_observed(kp_events, target_pid=target_pid)
    orphan_count = int(len(detectors.orphan_threads(kp_events)))

    # Sysmon detectors (no-op when Sysmon was not subscribed for this run).
    sysmon_access_count = detectors.sysmon_process_access_count(events, target_pid)
    sysmon_access_observed = detectors.sysmon_process_access_observed(events, target_pid)
    sysmon_hostile = detectors.sysmon_attacker_hostile_handle(events, target_pid, attacker_pid)
    sysmon_hostile_strict = detectors.sysmon_attacker_hostile_handle_strict(events, target_pid, attacker_pid)
    sysmon_max_grant = detectors.sysmon_max_granted_access(events, target_pid)
    sysmon_crt = detectors.sysmon_create_remote_thread_observed(events, target_pid)
    sysmon_crt_loadlib_count = detectors.sysmon_create_remote_thread_load_library_count(events, target_pid)
    sysmon_crt_orphan_count = detectors.sysmon_create_remote_thread_orphan_count(events, target_pid)

    # ThreatIntelligence (ETW-TI) detectors. No-op (False/0) when TI was not
    # subscribed; populated when the run was captured via the PPL consumer.
    ti_cross_observed = detectors.threatint_cross_process_observed(events, target_pid)
    ti_cross_count = detectors.threatint_cross_process_count(events, target_pid)
    ti_cross_write_count = detectors.threatint_cross_process_write_count(events, target_pid)
    ti_cross_alloc_count = detectors.threatint_cross_process_alloc_count(events, target_pid)
    ti_remote_alloc = detectors.threatint_remote_alloc_observed(events, target_pid)
    ti_exec_alloc = detectors.threatint_remote_executable_alloc_observed(events, target_pid)
    ti_remote_write = detectors.threatint_remote_write_observed(events, target_pid)
    ti_remote_protect = detectors.threatint_remote_protect_observed(events, target_pid)
    ti_thread_hijack = detectors.threatint_thread_hijack_observed(events, target_pid)

    # Validity tier (rule depends on technique class — see _classify_completeness).
    technique = (run_meta.get("technique") or "").lower().strip()
    manipulation_exit_code = run_meta.get("manipulation_exit_code")
    is_valid, is_complete = _classify_completeness(
        technique=technique,
        image_loads_total=image_loads_total,
        manipulation_exit_code=manipulation_exit_code,
        n_events=len(events),
    )

    # Assemble the feature row (run identity + validity flags + features).
    return {
        "run_id": run_meta["run_id"],
        "technique": run_meta.get("technique"),
        "label": run_meta.get("label"),
        "provider_set": run_meta.get("provider_set") or "",
        "is_valid_run": is_valid,
        "is_complete_run": is_complete,
        "manipulation_exit_code": manipulation_exit_code,
        "manipulation_succeeded": bool(manipulation_exit_code == 0),
        "n_events_total": int(len(events)),
        "n_image_loads_total": image_loads_total,
        "n_image_loads_post_attack": image_loads_post,
        "injected_dll_observed": dll_observed,
        "n_thread_starts_post_attack": thread_starts_post,
        "n_thread_stops_post_attack": thread_stops_post,
        "n_orphan_threads": orphan_count,
        "sysmon_process_access_count": sysmon_access_count,
        "sysmon_process_access_observed": sysmon_access_observed,
        "sysmon_attacker_hostile_handle": sysmon_hostile,
        "sysmon_attacker_hostile_handle_strict": sysmon_hostile_strict,
        "sysmon_max_granted_access": sysmon_max_grant,
        "sysmon_create_remote_thread_observed": sysmon_crt,
        "sysmon_crt_load_library_count": sysmon_crt_loadlib_count,
        "sysmon_crt_orphan_count": sysmon_crt_orphan_count,
        "threatint_cross_process_count": ti_cross_count,
        "threatint_cross_process_write_count": ti_cross_write_count,
        "threatint_cross_process_alloc_count": ti_cross_alloc_count,
        "threatint_cross_process_observed": ti_cross_observed,
        "threatint_remote_alloc_observed": ti_remote_alloc,
        "threatint_remote_executable_alloc_observed": ti_exec_alloc,
        "threatint_remote_write_observed": ti_remote_write,
        "threatint_remote_protect_observed": ti_remote_protect,
        "threatint_thread_hijack_observed": ti_thread_hijack,
    }


def compute_all_features(runs_df: pd.DataFrame, events_df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    for _, run_meta in runs_df.iterrows():
        run_events = events_df[events_df["run_id"] == run_meta["run_id"]]
        rows.append(compute_run_features(run_meta, run_events))
    return pd.DataFrame(rows)


# Feature names published for reports.py to iterate over. To add a feature:
# compute it in compute_run_features and append its key here.
NUMERIC_FEATURES = [
    "n_image_loads_total",
    "n_image_loads_post_attack",
    "n_thread_starts_post_attack",
    "n_thread_stops_post_attack",
    "n_orphan_threads",
    "sysmon_process_access_count",
    "sysmon_max_granted_access",
    "sysmon_crt_load_library_count",
    "sysmon_crt_orphan_count",
    "threatint_cross_process_count",
    "threatint_cross_process_write_count",
    "threatint_cross_process_alloc_count",
]

BOOLEAN_FEATURES = [
    "injected_dll_observed",
    "sysmon_process_access_observed",
    "sysmon_attacker_hostile_handle",
    "sysmon_attacker_hostile_handle_strict",
    "sysmon_create_remote_thread_observed",
    "threatint_cross_process_observed",
    "threatint_remote_alloc_observed",
    "threatint_remote_executable_alloc_observed",
    "threatint_remote_write_observed",
    "threatint_remote_protect_observed",
    "threatint_thread_hijack_observed",
]
