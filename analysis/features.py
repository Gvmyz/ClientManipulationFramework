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

    # Two-tier validity:
    #   is_valid_run    - produced any events at all (excludes pure failures)
    #   is_complete_run - captured enough data to represent a complete experiment
    #
    # For attack techniques the completeness threshold is ≥10 ImageLoad events.
    # A successful injection loads TestDll.dll and its dependency cascade (20+
    # DLLs); a failed or partial trace captures 0-6. The threshold sits cleanly
    # in the gap between those two populations.
    #
    # For baseline (technique == "none") there is no injection and therefore no
    # DLL cascade. TestTarget.exe itself loads only a handful of DLLs at startup,
    # and the ETW session often misses those because it starts slightly after the
    # process. A baseline run is considered complete when it produced any events
    # at all — even a few ThreadStart/ThreadStop rundown events confirm the trace
    # window was open and the telemetry buffer was flushed correctly.
    technique = (run_meta.get("technique") or "").lower().strip()
    is_valid = bool(len(events) > 0)
    if technique in ("none", ""):
        is_complete = is_valid
    else:
        is_complete = bool(image_loads_total >= 10)

    return {
        "run_id": run_meta["run_id"],
        "technique": run_meta.get("technique"),
        "label": run_meta.get("label"),
        "is_valid_run": is_valid,
        "is_complete_run": is_complete,
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
