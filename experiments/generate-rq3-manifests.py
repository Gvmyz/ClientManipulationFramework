"""Generate RQ3 (ti_only) manifest variants from the baseline set.

For each baseline manifest listed in BASELINE_MANIFESTS, produce a sibling
manifest with:
  - `providers`  reduced to ETW-TI only (Sysmon + KernelProcess removed)
  - `name`       suffixed with "_ti_only"
  - `metadata.evasion` set to "ti_only"

Run from the repo root:
    python experiments\\generate-rq3-manifests.py

Rerun freely — overwrites existing _ti_only siblings, does not touch
baselines.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = REPO_ROOT / "experiments" / "manifests"

TI_PROVIDER = {
    "guid": "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}",
    "name": "ThreatIntelligence",
}

# Baselines that get an RQ3 sibling. TestTarget attacks first, AC second.
# Add new manifest names here to extend the RQ3 sweep.
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
    out = copy.deepcopy(baseline)
    out["name"] = f"{baseline['name']}_ti_only"
    out["providers"] = [TI_PROVIDER]
    metadata = out.setdefault("metadata", {})
    metadata["evasion"] = "ti_only"
    return out


def main() -> int:
    missing: list[str] = []
    written: list[Path] = []
    for stem in BASELINE_MANIFESTS:
        src = MANIFESTS / f"{stem}.json"
        if not src.exists():
            missing.append(stem)
            continue
        baseline = json.loads(src.read_text(encoding="utf-8"))
        dst = MANIFESTS / f"{stem}_ti_only.json"
        dst.write_text(
            json.dumps(transform(baseline), indent=2) + "\n",
            encoding="utf-8",
        )
        written.append(dst)

    for p in written:
        print(f"wrote {p.relative_to(REPO_ROOT)}")
    if missing:
        print("\nmissing baseline manifests (skipped):")
        for m in missing:
            print(f"  - {m}.json")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
