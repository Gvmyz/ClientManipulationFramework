# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

Research-oriented Windows security framework for a Master's thesis on behavioral analysis of client-side manipulation techniques (DLL injection, memory manipulation). The goal is to produce repeatable manipulation runs and compare the OS-level telemetry they generate — so changes to the manipulation tools and the telemetry collector must keep producing comparable JSONL output across runs.

All code is C++23 / Win32 / x64, built with MSVC (Platform Toolset v143) via the Visual Studio solution. There is no CMake build despite the README mentioning it as optional.

## Build

Open `ClientManipulationFramework.sln` in Visual Studio 2022 and build the `x64` configuration (Debug or Release). The four projects build into `ProcessToolkit/x64/{Debug,Release}/`:

- `ProcessToolkit.exe` — manipulation CLI
- `Telemetry.exe` — ETW collector
- `TestDll.dll` — payload DLL with exported `RunTest`
- `TestTarget.exe` — victim process

Note the layout: every project's build output lands under `ProcessToolkit/x64/` (not in each project's own folder). Experiment manifests hardcode this path.

From the command line:

```powershell
msbuild ClientManipulationFramework.sln /p:Configuration=Debug /p:Platform=x64
msbuild ClientManipulationFramework.sln /p:Configuration=Release /p:Platform=x64
```

Win32 configurations exist in the solution but are not used — the manipulation code assumes a 64-bit target process.

There are no tests and no lint configuration.

## Running an Experiment

Experiments are the primary way to exercise the system end-to-end. They are orchestrated by `experiments/Run-Experiment.ps1`, which takes a manifest from `experiments/manifests/` and runs target → telemetry → manipulation → cooldown, then writes a per-run `manifest.json` (plus `telemetry.jsonl`) under `experiments/runs/<timestamp>-<name>/`.

```powershell
powershell -ExecutionPolicy Bypass -File .\experiments\Run-Experiment.ps1 -ManifestPath .\experiments\manifests\basic-loadlibrary.json
```

Existing manifests: `baseline.json` (no manipulation), `basic-loadlibrary.json` (LoadLibraryW injection), `basic-manualmap.json` (manual PE mapping).

The runner resolves all manifest paths relative to the repo root and substitutes `{targetPid}`, `{runId}`, `{runDirectory}`, `{telemetryOutput}` into the manipulation command line. ETW collection requires the runner to be launched **as Administrator**.

## Running the CLIs Directly

`ProcessToolkit.exe` is a multi-command CLI (see [main.cpp](ProcessToolkit/src/main.cpp)):

```
ProcessToolkit.exe list-processes
ProcessToolkit.exe inspect-memory --pid <pid> [--committed] [--private] [--executable]
ProcessToolkit.exe inject-loadlibrary --pid <pid> --dll <path> [--module <name>] [--call <export>]
ProcessToolkit.exe inject-manualmap  --pid <pid> --dll <path> [--call <export>]
```

`Telemetry.exe` consumes an ETW provider GUID followed by optional filters and metadata:

```
Telemetry.exe <ProviderGuid> [--pid PID] [--name proc.exe] [--output path] [--session name]
              [--run-id id] [--label l] [--technique t] [--target t] [--meta key=value]
```

Default provider used by manifests is `Microsoft-Windows-Kernel-Process` (`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` — see [docs/Provider_GUIDS.txt](docs/Provider_GUIDS.txt)).

## Architecture

Four binaries that compose into one experiment:

```
TestTarget.exe  ← victim (loops on Sleep/GetAsyncKeyState)
Telemetry.exe   ← opens an ETW real-time session, filters events, writes JSONL
ProcessToolkit.exe → performs the manipulation against TestTarget
TestDll.dll     ← payload, exports RunTest (MessageBox stub)
```

### ProcessToolkit (manipulation)

All code under `PT::` namespace. The CLI in [main.cpp](ProcessToolkit/src/main.cpp) is a thin dispatcher over a layered library:

- [WinHandle](ProcessToolkit/include/WinHandle.h) — RAII wrapper passed everywhere a `HANDLE` is needed; `process.valid()` is the standard liveness check.
- [Process](ProcessToolkit/include/Process.h) — process enumeration, image-path lookup, `open_process` with safe-default access rights.
- [ProcessMemory](ProcessToolkit/include/ProcessMemory.h) / [Memory](ProcessToolkit/include/Memory.h) — `VirtualAllocEx`/`WriteProcessMemory`/`VirtualQueryEx` wrappers and region filters (committed / private / executable). `Memory::find_module_base` walks the remote loader list.
- [ProcessThread](ProcessToolkit/include/ProcessThread.h) — `CreateRemoteThread` helpers.
- [ModuleResolver](ProcessToolkit/include/ModuleResolver.h) — resolves remote function addresses (used to find `LoadLibraryW`, `GetProcAddress`, etc. in the victim).
- [DllInjection](ProcessToolkit/include/DllInjection.h) — the two techniques exposed by the CLI:
  - `inject_dll_loadlibrary` — writes the DLL path into the remote process and starts a thread on `LoadLibraryW`.
  - `inject_dll_manualmap` — reads the PE locally, allocates remote image, applies relocations, resolves imports, runs TLS callbacks, calls `DllMain` via a loader stub written into the target. Returns the remote image base.
  - `call_exported_function` — given a remote module base and the *local* DLL on disk, resolves the export's RVA locally and starts a remote thread at `remote_base + RVA`.
- [Privileges](ProcessToolkit/include/Privileges.h) — token privilege adjustments (e.g. `SeDebugPrivilege`).
- [Utils](ProcessToolkit/include/Utils.h) — the `PT::Cli` helpers (`print_section`, `run_step`, `to_hex`, `print_named_hex`, ANSI colors). The CLI uses these consistently; new commands should follow the same `print_section → run_step` rhythm so output stays uniform across runs.
- `inspector`, `window`, `Injector` (+ ImGui under `external/`) — older / WIP GUI scaffolding. The current CLI flow does not depend on ImGui, but the project compiles and links it.

Adding a new manipulation technique generally means: add a free function under `PT::DllInjection` (or a new namespace), wire a sub-command into `main.cpp` following the existing `inject_*` pattern, and create a manifest under `experiments/manifests/` that points at it.

### Telemetry (ETW collector)

Single-binary collector in `Telemetry/`:

- [main.cpp](Telemetry/main.cpp) drives a real-time ETW session (`StartTraceW` → `EnableTraceEx2` → `OpenTraceW` → `ProcessTrace`) and an `OnEvent` callback that parses each `EVENT_RECORD` via TDH.
- Currently only events matching `is_process_start_event || is_thread_event || is_image_event` are logged. Adjust `should_log_event` to widen coverage.
- A `--pid` filter is applied in the callback (against `event.pid`). The runner always passes the target's PID, so by default the JSONL only contains events for that process.
- [JsonLogger.h](Telemetry/JsonLogger.h) is a thread-safe singleton that emits one JSON object per line — each line embeds both an `experiment` block (metadata from CLI flags) and the `event` itself. This is the schema downstream analysis depends on.
- `ETWSession.h` / `.cpp` is older session-wrapper code not currently used by `main.cpp`.

If `StartTraceW` returns `ERROR_ALREADY_EXISTS`, the code stops the prior session with the same name and retries — relevant when a previous run was killed mid-flight.

### Experiment runner

[Run-Experiment.ps1](experiments/Run-Experiment.ps1) is the only orchestration layer. It:

1. Loads the manifest, computes a `runId` and run directory.
2. Starts the target → captures its PID.
3. Starts telemetry with `--pid <targetPid>` plus metadata from `manifest.metadata`.
4. Waits `warmupSeconds`, then runs the manipulation command (template substitution above).
5. Waits for the manipulation to exit, sleeps `cooldownSeconds`, stops telemetry and target.
6. Writes a final `manifest.json` that records resolved paths, PIDs, exit codes, and timing — this is what downstream analysis joins against `telemetry.jsonl`.

The manifest schema (see existing files) is the source of truth for what's configurable; treat it as a stable contract — analysis tooling will key off `metadata.label` / `metadata.technique`.

## Conventions

- **C++ namespace:** all manipulation code lives under `PT::` (`PT::Process`, `PT::Memory`, `PT::DllInjection`, `PT::Cli`).
- **Error reporting:** functions return `std::optional<T>` / `bool` rather than throwing; CLI surfaces results via `PT::Cli::run_step`. Don't introduce exceptions in the manipulation layer.
- **Handles:** always pass `const WinHandle&`, never raw `HANDLE`. Open with the minimum access right needed (`Process::open_process` defaults to `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`; `ProcessMemory::open_process` opens with the broader set required for injection).
- **Strings:** wide strings (`std::wstring` / `wchar_t`) throughout — `wmain`, `CharacterSet=Unicode`. ASCII-only inputs (export names) go through `narrow_ascii`.
- **C++ standard:** `stdcpp23` (`<format>`, `<optional>`, `<filesystem>`, structured bindings used freely).
- **Telemetry schema stability:** the JSONL structure in `JsonLogger::build_record` is read by downstream analysis. If you change field names or nesting, every prior run becomes incomparable — make schema changes deliberately and version them.
