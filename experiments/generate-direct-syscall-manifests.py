"""Generate direct-syscall evasion manifest siblings from the baselines.

For each baseline manifest listed in BASELINE_MANIFESTS, produce a
sibling with:
  - the same three providers subscribed (this is a technique-level
    evasion, not a provider-level one)
  - `--via-direct-syscall` appended to the manipulation command line
  - `metadata.evasion` set to "direct_syscall"
  - `name` suffixed with "_direct_syscall"

Direct syscalls and provider subscription are independent factors. This
legacy generator only supports x64. Prefer New-AutomatedCampaignPlan.ps1
for matched normal/direct executions with the same probe and provider set.

Run from the repo root:
    python experiments\\generate-direct-syscall-manifests.py
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = REPO_ROOT / "experiments" / "manifests"

# Same list as generate-rq3-manifests.py. Kept as a separate constant
# rather than an import so this script is standalone.
BASELINE_MANIFESTS: list[str] = [
    "basic-loadlibrary",
    "basic-manualmap",
    "basic-threadhijack",
    "apc_classic",
    "basic-patch-data",
    "patch_aob",
    "patch_tick",
    "patch_rwxflip",
    "hook_iat",
    "hook_inline",
    "injection_loadlibrary_assaultcube",
    "injection_manualmap_assaultcube",
    "injection_threadhijack_assaultcube",
    "apc_classic_ac",
    "patch_aob_ac",
    "patch_tick_ac",
    "hook_iat_ac",
    "hook_inline_ac",
    "injection_loadlibrary_xonotic",
]


def transform(baseline: dict) -> dict:
    executable = (baseline.get("manipulation") or {}).get("executable", "")
    if "Win32" in executable or not executable:
        raise ValueError("Direct-syscall generation requires an x64 ProcessToolkit manifest")
    out = copy.deepcopy(baseline)
    out["name"] = f"{baseline['name']}_direct_syscall"

    # Append --via-direct-syscall to the manipulation command line so
    # ProcessToolkit's main.cpp initializes DirectSyscall and enables it
    # for the run. If a manifest has no manipulation.commandLineTemplate
    # (external-attacker manifests like meterpreter-migrate), we skip.
    manip = out.get("manipulation") or {}
    tpl = manip.get("commandLineTemplate")
    if not tpl:
        return out
    if "--via-direct-syscall" not in tpl:
        manip["commandLineTemplate"] = tpl + " --via-direct-syscall"
    out["manipulation"] = manip

    metadata = out.setdefault("metadata", {})
    metadata["evasion"] = "direct_syscall"
    return out


def main() -> int:
    written: list[Path] = []
    missing: list[str] = []
    for stem in BASELINE_MANIFESTS:
        src = MANIFESTS / f"{stem}.json"
        if not src.exists():
            missing.append(stem)
            continue
        baseline = json.loads(src.read_text(encoding="utf-8"))
        if "Win32" in baseline.get("manipulation", {}).get("executable", ""):
            print(f"unsupported x86 direct-syscall manifest skipped: {stem}")
            continue
        dst = MANIFESTS / f"{stem}_direct_syscall.json"
        dst.write_text(
            json.dumps(transform(baseline), indent=2) + "\n",
            encoding="utf-8",
        )
        written.append(dst)

    for p in written:
        print(f"wrote {p.relative_to(REPO_ROOT)}")
    if missing:
        print("\nno baseline found (skipped):")
        for m in missing:
            print(f"  - {m}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
