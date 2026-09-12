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

## Resuming an automated campaign

Keep the original campaign `plan.json` and its frozen `manifests/` directory.
The order printed as `[44/90]` is the `order` in that plan, not the repetition
number or a freshly generated schedule.

Normal continuation uses `attempts.json` beside the plan and skips recorded
attempts, including failures and interrupted attempts. It does not require
the old run folders to remain on the VM:

```powershell
.\experiments\Run-AutomatedCampaign.ps1 -Plan (Join-Path $campaign 'plan.json') -Resume
```

After losing the journal, or to explicitly retry from order 44, use:

```powershell
.\experiments\Run-AutomatedCampaign.ps1 -Plan (Join-Path $campaign 'plan.json') -Resume -StartAt 44
```

`-StartAt` is an explicit restart boundary: order 44 and all later orders
are scheduled again, even if the old journal records an attempt there.
An existing journal is first archived as `attempts.before-start-44.*.json`.
Earlier records are retained when readable; missing earlier records receive
`skipped_before_start` with unknown verification, not invented success.
This records the scheduling decision without claiming deleted results were
recovered. The captured data and frozen plan are not deleted or regenerated.

Add `-PreflightOnly` to preview the next order without modifying the journal,
bootstrapping telemetry, or running captures. Subsequent ordinary `-Resume`
calls retain the skipped prefix; omit `-StartAt` unless you intend another
explicit restart. A missing or malformed journal now stops ordinary resume
instead of silently starting over.

If a restart reports `PPLRunner is currently Running`, the protected service
has not stopped. Bootstrap checks its configuration but does not stop a
capture. If the previous capture was interrupted and no other capture is
intentionally running, request shutdown from an Administrator PowerShell:

```powershell
New-Item -ItemType File -Path 'C:\elam\stop.flag' -Force | Out-Null
(Get-Service -Name PPLRunner).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
Get-Service -Name PPLRunner
```

The service polls this flag and requests that its ETW session stop before
waiting for the telemetry child to exit. Once the status is `Stopped`, retry
the blocked order using `-Resume -StartAt 44` (substitute its actual order).
Plain `-Resume` skips that recorded failure even when no capture was launched.
If the wait times out, inspect `C:\elam\pplrunner.log` and
`C:\elam\ti_test.json.log` before retrying. The service clears the old stop
flag at its next start; no binary rebuild is needed for this recovery.

The runner supports both Windows PowerShell 5.1 and PowerShell 7, including
recovery of the nested `value`/`Count` journal wrapper produced by the old
5.1 reader. Checkpoints are written to a temporary file and replaced only
after writing succeeds; `attempts.json.bak` holds the previous checkpoint.
`Run-ExternalCampaign.ps1` forwards the same recovery option.

The regression check uses isolated stub captures and never starts games,
telemetry, or protected services:

```powershell
powershell.exe -NoProfile -File .\experiments\tests\Test-CampaignResume.ps1
pwsh.exe -NoProfile -File .\experiments\tests\Test-CampaignResume.ps1
```

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
