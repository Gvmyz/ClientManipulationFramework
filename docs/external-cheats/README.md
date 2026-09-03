# External Cheats and Injectors — Provenance Manifest

This document records every third-party cheat, trainer, and injector
exercised through the ProcessToolkit capture pipeline as an external
validator. The source and binaries themselves are **not committed** to
this repository (see `.gitignore`); they live under `External_Cheats/`
on each lab machine and are reproduced from the upstream sources listed
below.

The thesis's Chapter 5 (§5.1.5 for injection-class externals) and
Chapter 7 (external-validation results) cite this document as the
provenance source.

## Reproduction

Clone each source at the recorded commit / archive SHA-256 into the
matching subdirectory:

```
External_Cheats/
├── AC/
│   ├── AssaultHook/                    # matseee, injection+hook+patch
│   └── AssaultCubeExternalBobBuilder/  # BobBuilder, external patch/aimbot
├── Xonotic/
│   └── (no vetted community cheats — see notes below)
└── Injectors/
    ├── ExtremeInjector/                # master131, generic DLL injector
    └── Xenos/                          # DarthTon, manual mapping injector
```

All source is used **as-downloaded**, unmodified, unless a per-entry
"patch" section below documents an explicit change (e.g. an SDK version
bump for a modern Windows compile).

## Entries

### AC / AssaultHook (matseee)

| Field | Value |
|---|---|
| Upstream | https://github.com/matseee/AssaultHook |
| Commit (or archive SHA-256) | **TBD — record after clone** |
| Accessed | 2026-09-03 |
| License | See `LICENSE` in tree |
| Target | AssaultCube 1.3.0.2 (`ac_client.exe`) |
| Classes exercised | injection + hook + patch (compound cheat) |
| Delivery | Self-injecting DLL |
| Thesis role | Injection-class external validator; also exercises hook + patch (multi-class fingerprint) |
| Build | Visual Studio, opens `src/AssaultHook.sln` (Win32/x86) |
| Run | Launch AC first, then run the built cheat binary; it self-injects |
| Notes | Includes a `CheatEngine.CT` table and a `ReClass.rcnet` file — useful for reproducing the offset-discovery process too |

### AC / AssaultCubeExternalBobBuilder

| Field | Value |
|---|---|
| Upstream | **TBD — record URL** |
| Commit (or archive SHA-256) | **TBD** |
| Accessed | 2026-09-03 |
| License | See `LICENSE` in tree |
| Target | AssaultCube 1.3.0.2 (`ac_client.exe`) |
| Classes exercised | patch (external, does not inject a DLL) |
| Delivery | External process reads/writes AC memory via OpenProcess + WriteProcessMemory |
| Thesis role | Patch-class external validator; distinct fingerprint from AssaultHook because no injection |
| Build | Open `AssaultCubeAimbot.sln` in Visual Studio (Win32/x86) |
| Run | Launch AC first, then run built `AssaultCubeAimbot.exe` |
| Notes | Uses ImGui for its overlay; keep the overlay open during capture so the read/write pattern is representative of real use |

### Injectors / ExtremeInjector (master131)

| Field | Value |
|---|---|
| Upstream | https://github.com/master131/ExtremeInjector (or GuidedHacking mirror) |
| Commit (or archive SHA-256) | **TBD** |
| Accessed | 2026-09-03 |
| License | Not declared upstream (verify before citing) |
| Target | Any 32-bit or 64-bit Windows process |
| Classes exercised | injection (delivery mechanism only — payload DLL determines the specific variant) |
| Delivery | Standalone injector process; user picks DLL and target from a GUI |
| Thesis role | Externally-authored injection delivery; pair with a synthetic payload DLL to isolate the injector's own fingerprint |
| Build | Open `VC/ExtremeInjector.sln` (project uses older C++/CLI; may need retargeting to a modern toolset) |
| Run | Launch injector, select target PID + DLL path, click Inject |
| Notes | Supports multiple injection methods (LoadLibrary, manual map, thread hijack). Pick one per capture to keep fingerprints separable. |

### Injectors / Xenos (DarthTon)

| Field | Value |
|---|---|
| Upstream | https://github.com/DarthTon/Xenos |
| Commit (or archive SHA-256) | **TBD** |
| Accessed | 2026-09-03 |
| License | MIT (verify from `LICENSE` file in tree) |
| Target | Any 32-bit or 64-bit Windows process |
| Classes exercised | injection (delivery only) |
| Delivery | Standalone injector; GUI or CLI (`XenosCLI.exe`) |
| Thesis role | Manual-map external validator (Xenos is famous for reflective manual mapping) |
| Build | Open `Xenos.sln`. Requires WDK for driver-based methods; the user-mode-only build is sufficient for our purposes. |
| Run | GUI: select target + DLL + method. CLI: `XenosCLI.exe --process ac_client.exe --image path\\to\\payload.dll --mode ManualMap` |
| Notes | Prefer the CLI (`XenosCLI.exe`) for scripted captures — it plays nicely with our PowerShell runner |

## Xonotic — availability note

As of the accessed date, no vetted public cheat source exists for
Xonotic 0.8.6 that matches our reproducibility bar (open source,
documented, buildable). External Xonotic validators are therefore
sourced by retargeting existing tools:

- **Meterpreter migrate → xonotic.exe** (already in synthetic corpus,
  swap the manifest's target executable)
- **Sliver implant → xonotic.exe** (same treatment)
- **Xenos manual-mapping a small synthetic DLL into xonotic.exe** (the
  injector is the external component; the DLL is ours but the delivery
  path is not our code)

Chapter 8 (limitations) frames this honestly: "public cheat
availability is limited for Xonotic 0.8.6 due to the game's recency;
three external tools were exercised against it, complementing the six
against AssaultCube for a combined external corpus of nine cheats."

## Verification protocol per binary

For every external cheat or injector executed inside the lab VM:

1. Record its SHA-256 with `Get-FileHash -Algorithm SHA256` and paste
   into the entry above.
2. Look up the hash on VirusTotal (`https://www.virustotal.com/gui/file/<SHA-256>`)
   without uploading the file. If it is flagged as anything other than
   what its authors claim (i.e., a game cheat), pick a different one.
3. Run only inside the isolated Hyper-V VM. Never on a host or
   non-lab machine.
4. Capture the run through the standard ProcessToolkit manifest
   pipeline so the resulting features flow through the same detectors
   as every other run.

## Manifest template for capture

Each external cheat becomes a small manifest under
`experiments/manifests/external/`. Example for AssaultHook:

```json
{
  "name": "external_assaulthook_ac",
  "target": "ac_client.exe",
  "warmupSeconds": 6,
  "providers": ["KernelProcess", "Sysmon", "ThreatIntelligence"],
  "attackerBinary": "External_Cheats/AC/AssaultHook/bin/Release/AssaultHook.exe",
  "commandLineTemplate": "",
  "description": "matseee AssaultHook self-injecting DLL cheat against AssaultCube 1.3.0.2. External validator, injection + hook + patch classes."
}
```

Replicates: three per external cheat, using the same replicate mechanism
as the synthetic corpus.
