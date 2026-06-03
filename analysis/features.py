"""Per-run feature extraction.

Each feature is a single number (or boolean) summarizing one aspect of a run's
telemetry. The feature set is intentionally small for the MVP; each entry is
chosen because it is expected to discriminate between techniques or between
attack and benign execution.
"""

from __future__ import annotations

import pandas as pd

from . import detectors


def _split_at_attack(events: pd.DataFrame, attack_started_at) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split a run's events into (before_attack, after_attack) by wall-clock time.

    If we have no attack timestamp (e.g. a malformed manifest), treat everything
    as "after" so feature counts are not silently zero.
    """
    if attack_started_at is None or events.empty:
        return events.iloc[0:0], events
    has_ts = events["timestamp"].notna()
    before = events[has_ts & (events["timestamp"] < attack_started_at)]
    after = events[has_ts & (events["timestamp"] >= attack_started_at)]
    return before, after


# Techniques whose ETW signature under the kernel-process provider is expected
# to be empty by design. For these, completeness is judged by the manipulation
# tool's exit code, not by event counts — the empty trace IS the measurement,
# and we need a way to distinguish "tool ran cleanly, telemetry blind" from
# "tool crashed before doing anything." Extend this set when adding the next
# technique class whose effect lives below the current provider's visibility
# (e.g. read-only memory inspection, named-pipe IPC).
EMPTY_TRACE_TECHNIQUES = frozenset({"memorypatch"})


def _classify_completeness(
    technique: str,
    image_loads_total: int,
    manipulation_exit_code,
    n_events: int,
) -> tuple[bool, bool]:
    """Return (is_valid_run, is_complete_run) for one run.

    Validity tiers:
      is_valid_run    - the experiment produced *some* signal we can reason about.
                        For event-producing techniques: at least one event landed.
                        For empty-trace techniques:    the manipulation tool exited cleanly.
      is_complete_run - the experiment captured enough to be reported as a
                        finished data point of its technique class.

    The three technique classes:

    1. ``none`` (baseline) — TestTarget runs untouched. Few events are expected
       (the ETW session usually misses startup DLL loads), so a single rundown
       event is enough to confirm the trace window was open and flushed.

    2. ``memorypatch`` and other ``EMPTY_TRACE_TECHNIQUES`` — the technique is
       invisible to the kernel-process provider on purpose. The empty trace is
       the finding. Completeness is "the tool we ran exited with code 0."
       A non-zero exit means the patch failed (bad address, permission denied,
       process gone) and we can't claim the empty trace as evidence.

    3. Everything else (injection techniques: loadlibrary, threadhijack,
       manualmap) — a successful injection drags in TestDll.dll plus its
       20+ DLL dependency cascade, so ImageLoad count is a reliable proxy.
       The ≥10 threshold sits in the gap between failed runs (0-6 loads) and
       successful ones (20+).
    """
    is_valid_event_based = n_events > 0
    is_valid_exit_based = manipulation_exit_code == 0

    if technique in ("none", ""):
        return is_valid_event_based, is_valid_event_based

    if technique in EMPTY_TRACE_TECHNIQUES:
        # For an empty-trace technique, both tiers are exit-code-driven: a
        # successful tool run IS a complete experiment, regardless of whether
        # any events were recorded.
        return is_valid_exit_based, is_valid_exit_based

    # Injection techniques: event-count based.
    return is_valid_event_based, bool(image_loads_total >= 10)


def compute_run_features(
    run_meta: pd.Series,
    events: pd.DataFrame,
) -> dict:
    """Compute the MVP feature vector for one run."""
    attack_started_at = run_meta.get("attack_started_at")
    _, post = _split_at_attack(events, attack_started_at)

    image_loads_total = int((events["task"] == "ImageLoad").sum())
    image_loads_post = int((post["task"] == "ImageLoad").sum())
    thread_starts_post = int((post["task"] == "ThreadStart").sum())
    thread_stops_post = int((post["task"] == "ThreadStop").sum())

    dll_observed = detectors.injected_dll_observed(events)
    orphans = detectors.orphan_threads(events)
    orphan_count = int(len(orphans))

    technique = (run_meta.get("technique") or "").lower().strip()
    manipulation_exit_code = run_meta.get("manipulation_exit_code")
    is_valid, is_complete = _classify_completeness(
        technique=technique,
        image_loads_total=image_loads_total,
        manipulation_exit_code=manipulation_exit_code,
        n_events=len(events),
    )

    return {
        "run_id": run_meta["run_id"],
        "technique": run_meta.get("technique"),
        "label": run_meta.get("label"),
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
    }


def compute_all_features(runs_df: pd.DataFrame, events_df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    for _, run_meta in runs_df.iterrows():
        run_events = events_df[events_df["run_id"] == run_meta["run_id"]]
        rows.append(compute_run_features(run_meta, run_events))
    return pd.DataFrame(rows)


# Public list of the boolean and numeric feature names, for use by reports.
#
# To add a feature: compute it in compute_run_features() above and append its
# key here. Every plot and summary table iterates over these two lists, so the
# new feature shows up everywhere without further changes.
NUMERIC_FEATURES = [
    "n_image_loads_total",
    "n_image_loads_post_attack",
    "n_thread_starts_post_attack",
    "n_thread_stops_post_attack",
    "n_orphan_threads",
]

BOOLEAN_FEATURES = [
    "injected_dll_observed",
]
