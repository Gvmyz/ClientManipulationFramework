# Experiments

This folder contains small orchestration assets for thesis runs.

## Layout

- `manifests/` stores reusable experiment descriptions.
- `runs/` stores generated run output, manifests, and telemetry logs.
- `Run-Experiment.ps1` executes one manifest end to end.

## Flow

1. Start the target process.
2. Start telemetry with a run-specific output path and metadata.
3. Wait for warmup.
4. Run the manipulation command.
5. Wait for cooldown.
6. Stop telemetry.
7. Write `manifest.json` for the run.

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\experiments\Run-Experiment.ps1 -ManifestPath .\experiments\manifests\basic-loadlibrary.json [-KeepWindowsOpen]
```

The runner expects the referenced binaries to exist and resolves relative paths from the repository root.
