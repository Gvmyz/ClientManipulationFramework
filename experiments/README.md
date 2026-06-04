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

## Providers

A manifest declares which ETW providers Telemetry subscribes to. Two forms are supported:

```jsonc
// Single provider (legacy form, still works):
"providerGuid": "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"

// Multiple providers on the same session (preferred):
"providers": [
  { "guid": "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", "name": "KernelProcess" },
  { "guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", "name": "Sysmon" }
]
```

Each event in `telemetry.jsonl` carries a `provider_name` field so the analysis pipeline can group events by source. The names `KernelProcess` and `Sysmon` are recognized automatically when omitted.

### Sysmon (one-time install)

Manifests that include the Sysmon provider require the Sysinternals Sysmon service to be installed with our config. From an elevated PowerShell, from the repo root:

```powershell
# Download Sysmon (one-time, if not already present):
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

sysmon64.exe -accepteula -i experiments\sysmon-config.xml

# To update the config later without reinstalling:
sysmon64.exe -c experiments\sysmon-config.xml

# To verify Sysmon is running:
Get-Service Sysmon64
```

The config (`experiments/sysmon-config.xml`) filters at the source so Sysmon only emits events involving `TestTarget.exe` (and `ProcessToolkit.exe` for ProcessCreate). System-wide noise is dropped before it ever reaches the Telemetry consumer.

If you run a `+sysmon` manifest without Sysmon installed, Telemetry's `EnableTraceEx2` call for the Sysmon provider GUID returns success (the GUID is reserved by Sysmon either way) but no events fire — the trace will look identical to the kernel-process-only variant.
