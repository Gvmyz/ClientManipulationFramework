"""Replace verbose manifest descriptions with one-liners.

Only edits the `description` field at the top of each manifest. Notes,
metadata, providers, and everything else are left untouched. The full
technique explanations belong in the thesis (Ch 5), not in JSON files.

Run once after either editing this table or after regenerating the RQ3
manifests; the script also picks up the *_ti_only siblings so they stay
in sync.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = REPO_ROOT / "experiments" / "manifests"

# Keyed by baseline stem. The _ti_only sibling inherits the same one-liner
# with an evasion suffix.
DESCRIPTIONS: dict[str, str] = {
    # --- TestTarget attacks
    "basic-loadlibrary":  "LoadLibraryW DLL injection against TestTarget (MITRE T1055.001).",
    "basic-manualmap":    "Manual-map DLL injection against TestTarget (MITRE T1055.002).",
    "basic-threadhijack": "Thread-hijack DLL injection against TestTarget (MITRE T1055.003).",
    "apc_classic":        "APC injection against TestTarget (MITRE T1055.004).",
    "basic-patch-data":   "One-shot WriteProcessMemory patch of a TestTarget global.",
    "patch_aob":          "Cheat-Engine-style AOB scan + one-shot patch against TestTarget.",
    "patch_tick":         "Freeze-loop patch: N writes to one TestTarget address at fixed interval.",
    "patch_rwxflip":      "Direct patch of a TestTarget global bracketed by VirtualProtectEx (RW->RWX->restore).",
    "hook_iat":           "Cross-process IAT hook of kernel32!SleepEx inside TestTarget.",
    "hook_inline":        "Cross-process inline hook of a TestTarget function via 14-byte JMP + trampoline.",

    # --- AssaultCube attacks
    "injection_loadlibrary_assaultcube":  "LoadLibraryW DLL injection into ac_client.exe (MITRE T1055.001).",
    "injection_manualmap_assaultcube":    "Manual-map DLL injection into ac_client.exe (MITRE T1055.002).",
    "injection_threadhijack_assaultcube": "Thread-hijack DLL injection into ac_client.exe (MITRE T1055.003).",
    "apc_classic_ac":                     "APC injection against ac_client.exe (install-only; AC's main thread never enters alertable wait).",
    "patch_aob_ac":                       "Cheat-Engine-style AOB scan + null-patch against ac_client.exe.",
    "patch_tick_ac":                      "Freeze-loop patch of AC LocalPlayer.Health at 20 Hz.",
    "hook_iat_ac":                        "Cross-process IAT hook of user32!GetAsyncKeyState inside ac_client.exe.",
    "hook_inline_ac":                     "Cross-process inline hook of an ac_client.exe function via 5-byte JMP + trampoline.",

    # --- Baselines and externals
    "baseline":              "Benign TestTarget trace; no manipulation.",
    "baseline_assaultcube":  "Benign ac_client.exe trace in a scripted bot match; no manipulation.",
    "meterpreter-migrate":   "External validator: Meterpreter `migrate` into TestTarget (operator-driven).",
    "sliver-migrate":        "External validator: Sliver implant `migrate` into TestTarget (operator-driven).",
}


def rewrite(path: Path, new_description: str) -> bool:
    text = path.read_text(encoding="utf-8")
    manifest = json.loads(text)
    if manifest.get("description") == new_description:
        return False
    manifest["description"] = new_description
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return True


def main() -> int:
    edited: list[str] = []
    missing: list[str] = []
    for stem, desc in DESCRIPTIONS.items():
        base = MANIFESTS / f"{stem}.json"
        if base.exists():
            if rewrite(base, desc):
                edited.append(base.name)
        else:
            missing.append(stem)

        ti_only = MANIFESTS / f"{stem}_ti_only.json"
        if ti_only.exists():
            ti_desc = f"{desc} RQ3 evasion: only ETW-TI subscribed."
            if rewrite(ti_only, ti_desc):
                edited.append(ti_only.name)

    for name in edited:
        print(f"trimmed {name}")
    if missing:
        print("\nno baseline found (skipped):")
        for m in missing:
            print(f"  - {m}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
