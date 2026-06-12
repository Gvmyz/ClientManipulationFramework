# Analysis

Turns the per-run telemetry traces under `experiments/runs/` into tables and
plots.

## What it does

For every run on disk, the pipeline:

1. Reads the manifest and the ETW trace (`telemetry.jsonl`).
2. Walks the events and computes one feature vector per run.
3. Aggregates the features by `(provider_set, technique)`.
4. Writes the results into a timestamped folder under `analysis/reports/`.

## Run it

From the repository root:

```powershell
python -m analysis.analyze
```

First time only:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r analysis/requirements.txt
```

## Captured events and features

| Provider | Event | Properties read |
|---|---|---|
| KernelProcess | `ImageLoad` (and `ImageDCStart` rundown) | `ImageBase`, `ImageSize`, `ImageName` |
| KernelProcess | `ThreadStart`, `ThreadStop` (and DC variants) | `Win32StartAddr`, `StartAddr`, `ThreadID` |
| Sysmon | `ProcessAccess` (Event 10) | `SourceProcessId`, `TargetProcessId`, `GrantedAccess`, `RuleName`, source/target image paths |
| Sysmon | `CreateRemoteThread` (Event 8) | same as above |
| Sysmon | `ProcessCreate` (Event 1), `ProcessTerminate` (Event 5) | basic process metadata |

Features computed per run:

- `n_image_loads_total` / `n_image_loads_post_attack`
- `n_thread_starts_post_attack`, `n_thread_stops_post_attack`
- `n_orphan_threads` — threads whose start address is outside every observed image range
- `injected_dll_observed` — `TestDll.dll` appeared as a kernel-process ImageLoad
- `sysmon_process_access_observed` — any Sysmon Event 10 targeted TestTarget
- `sysmon_attacker_hostile_handle` — the manipulation tool opened a handle with `PROCESS_VM_WRITE`, `VM_OPERATION`, or `CREATE_THREAD`
- `sysmon_max_granted_access` — max GrantedAccess mask observed
- `sysmon_create_remote_thread_observed` — Sysmon Event 8 fired for TestTarget

## Extending it

- **New manifest field** → add to `load_run_metadata()` in `loader.py`.
- **New event property** → add to the row dict in `load_events()`.
- **New feature** → write a function in `detectors.py` or compute inline in `features.py:compute_run_features`, then append the key to `NUMERIC_FEATURES` or `BOOLEAN_FEATURES`. All tables and plots iterate over those lists.

## Files

```
loader.py     read manifests + telemetry into pandas DataFrames
detectors.py  reusable predicates over the events DataFrame
features.py   one feature vector per run
reports.py    write CSVs, markdown, and plots
analyze.py    CLI entry point
```
