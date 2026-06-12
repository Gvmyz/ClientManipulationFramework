"""Analysis pipeline entry point.

    python -m analysis.analyze [--runs-root ...] [--reports-root ...]

Reads every run under runs-root, computes per-run features, and writes a fresh
timestamped folder under reports-root containing CSV tables and PNG figures.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import features, loader, reports


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Run the analysis pipeline.")
    parser.add_argument(
        "--runs-root",
        type=Path,
        default=repo_root / "experiments" / "runs",
    )
    parser.add_argument(
        "--reports-root",
        type=Path,
        default=Path(__file__).resolve().parent / "reports",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # 1. Load every run on disk into DataFrames.
    print(f"Loading runs from {args.runs_root}")
    runs_df, events_df = loader.load_all(args.runs_root)
    print(f"  runs:   {len(runs_df)} (with telemetry: {int(runs_df['has_telemetry'].sum())})")
    print(f"  events: {len(events_df)}")

    if runs_df.empty:
        print("No runs found; aborting.")
        return 1

    # 2. Reduce each run to a feature vector.
    features_df = features.compute_all_features(runs_df, events_df)
    print(f"  features computed for {len(features_df)} runs")

    # 3. Write the report folder (CSVs, markdown, and the visibility-matrix PNG).
    out_dir = reports.make_report_dir(args.reports_root)
    print(f"Writing report to {out_dir}")

    paths = [
        reports.write_per_run_features(features_df, out_dir),
        reports.write_per_technique_summary(features_df, out_dir),
        reports.write_run_validity_table(features_df, out_dir),
        reports.write_findings_markdown(features_df, out_dir),
        reports.plot_provider_visibility_matrix(features_df, out_dir),
    ]
    for p in paths:
        print(f"  wrote {p.name}")

    complete = features_df[features_df["is_complete_run"]]

    # 4. Echo the validity table and per-technique means so the run is self-describing.
    print()
    print("Run validity (attempted -> validated -> complete):")
    print(
        features_df.groupby(["provider_set", "technique"])
        .agg(
            attempted=("run_id", "count"),
            validated=("is_valid_run", "sum"),
            complete=("is_complete_run", "sum"),
        )
        .to_string()
    )

    print()
    print("Per-technique mean features (complete runs only):")
    print(
        complete.groupby(["provider_set", "technique"])[
            features.NUMERIC_FEATURES + features.BOOLEAN_FEATURES
        ]
        .mean()
        .round(2)
        .to_string()
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
