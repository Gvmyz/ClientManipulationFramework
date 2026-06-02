# Analysis

Turns the per-run telemetry traces under `experiments/runs/` into tables and
plots that the thesis can cite directly.

## What it does

For every run on disk, the pipeline:

1. Reads the manifest and the ETW trace (`telemetry.jsonl`).
2. Walks the events and computes a small feature vector per run.
3. Aggregates those features by technique.
4. Writes the results into a timestamped folder under `analysis/reports/`.

That folder is the only place artefacts land. Nothing is mutated outside it.

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

## What is currently captured

The telemetry collector is intentionally minimal at this stage. The loader
parses four ETW event types and the following property keys:

| Event        | Properties read                                  |
|--------------|--------------------------------------------------|
| `ImageLoad`  | `ImageBase`, `ImageSize`, `ImageName`            |
| `ThreadStart`| `Win32StartAddr`, `StartAddr`, `ThreadID`        |
| `ThreadStop` | `Win32StartAddr`, `StartAddr`, `ThreadID`        |
| `ProcessStart` | (recorded but not used by current detectors)  |

From the manifest, the loader reads `technique`, `label`, `target`, the warmup
and cooldown durations, the resolved PIDs, and `execution.startedAt` (used to
locate the moment the manipulation step began).

The MVP feature set:

- `n_image_loads_total` / `n_image_loads_post_attack`
- `n_thread_starts_post_attack`, `n_thread_stops_post_attack`
- `n_orphan_threads` — threads whose start address lies outside every observed
  image range and below the system-DLL region. Picks up shellcode/manual-map.
- `injected_dll_observed` — boolean: did `TestDll.dll` appear as an
  `ImageLoad`? The cleanest single discriminator we have for manual mapping.

The `findings.md` produced by each run discusses what these features show.

## Extending it

Telemetry and manifests will grow. The pipeline is structured so that adding
new fields, detectors, or features is a localized change. Three recipes:

**Adding a new manifest field** — extend the dict returned by
`load_run_metadata()` in `loader.py`. The new column flows through to the runs
DataFrame automatically.

**Adding a new telemetry property** — add one more entry to the row dict built
in `load_events()` in `loader.py`. Use the `_parse_hex` / `_maybe_int` helpers
for typed parsing. The new column is then available to every detector and
feature function.

**Adding a new feature** — write a function in `detectors.py` (if it is a
reusable predicate) or compute it inline in `features.py:compute_run_features`,
then append its name to `NUMERIC_FEATURES` or `BOOLEAN_FEATURES`. All reports
and plots iterate over those lists, so the new feature appears in the CSVs,
the per-technique summary, and the comparison plot without further changes.

If a new event type appears (e.g. `VirtualAllocEx`, `NtCreateThreadEx`), no
loader change is needed to *see* it — it lands in the events DataFrame with
its `task` field. You only need to touch the loader to pull additional
properties out of its property bag.

## Files

```
loader.py     read manifests + telemetry into pandas DataFrames
detectors.py  reusable predicates over the events DataFrame
features.py   one feature vector per run
reports.py    write CSVs, markdown, and plots
analyze.py    CLI entry point
```
