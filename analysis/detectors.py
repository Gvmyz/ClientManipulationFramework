"""Predicates over the events DataFrame that map raw ETW events to higher-level
observations (e.g. "the injected DLL was loaded", "a hostile handle was opened").
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath

import pandas as pd


# ---- Constants ----

INJECTED_DLL_FILENAME = "testdll.dll"

# Windows process-access rights, from winnt.h. Only the subset we discriminate on.
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Rights that imply intent to manipulate the target rather than merely observe it.
ACCESS_MASK_HOSTILE = (
    PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
)

# x64 user-mode system DLLs live in 0x00007FF8.. and above. Heap and
# VirtualAlloc-backed pages live well below this. Used to flag dynamic-memory
# addresses without needing an ImageLoad event for every system DLL.
SYSTEM_DLL_REGION_LOW = 0x00007FF000000000


# ---- Generic helpers ----


def decode_access_mask(mask: int) -> list[str]:
    """Return the human-readable rights set in ``mask``."""
    if not isinstance(mask, int):
        return []
    out: list[str] = []
    for bit, name in [
        (PROCESS_TERMINATE, "PROCESS_TERMINATE"),
        (PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"),
        (PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"),
        (PROCESS_VM_READ, "PROCESS_VM_READ"),
        (PROCESS_VM_WRITE, "PROCESS_VM_WRITE"),
        (PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"),
        (PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION"),
    ]:
        if mask & bit:
            out.append(name)
    return out


def basename_lower(path: str) -> str:
    if not path:
        return ""
    # PureWindowsPath handles \Device\HarddiskVolume3\... prefixes correctly.
    return PureWindowsPath(path).name.lower()


# ---- KernelProcess detectors ----

def injected_dll_observed(events: pd.DataFrame) -> bool:
    """True iff TestDll.dll appears as an ImageLoad event."""
    image_loads = events[events["task"] == "ImageLoad"]
    if image_loads.empty:
        return False
    names = image_loads["image_path"].map(basename_lower)
    return bool((names == INJECTED_DLL_FILENAME).any())


@dataclass
class ImageRange:
    base: int
    end: int   # exclusive
    name: str


def collect_image_ranges(events: pd.DataFrame) -> list[ImageRange]:
    # Each ImageLoad event gives us a [base, base+size) range and a module name.
    ranges: list[ImageRange] = []
    image_loads = events[events["task"] == "ImageLoad"]
    for _, row in image_loads.iterrows():
        base = row.get("image_base")
        size = row.get("image_size")
        if base is None or size is None or size <= 0:
            continue
        ranges.append(ImageRange(
            base=int(base),
            end=int(base) + int(size),
            name=basename_lower(row.get("image_path") or row.get("image_name") or ""),
        ))
    return ranges


def address_in_any_range(addr: int | None, ranges: list[ImageRange]) -> bool:
    if addr is None:
        return False
    for r in ranges:
        if r.base <= addr < r.end:
            return True
    return False


def unique_threads(events: pd.DataFrame) -> pd.DataFrame:
    """Return one row per observed TID, taking the earliest event for each.

    Combines ThreadStart and ThreadStop because short-lived injection threads
    can lose their Start event in ETW's real-time buffer when the provider was
    enabled only milliseconds before the thread ran.
    """
    thread_events = events[events["task"].isin(["ThreadStart", "ThreadStop"])].copy()
    if thread_events.empty:
        return thread_events

    # Win32StartAddr is the user-mode entry; StartAddr is the kernel-side address.
    thread_events["resolved_start_addr"] = thread_events["win32_start_addr"].fillna(
        thread_events["start_addr"]
    )
    thread_events = thread_events.dropna(subset=["thread_id"])
    # Earliest event per TID gives us first observation.
    thread_events = thread_events.sort_values("timestamp")
    return thread_events.drop_duplicates(subset=["thread_id"], keep="first")


def orphan_threads(events: pd.DataFrame, *, dynamic_memory_only: bool = True) -> pd.DataFrame:
    """Threads whose start address falls outside every observed image range.

    ``dynamic_memory_only`` restricts the result to addresses below the system
    DLL region, biasing toward precision: a pre-existing system thread whose
    owning DLL predates the trace won't be falsely flagged as orphan.
    """
    threads = unique_threads(events)
    if threads.empty:
        return threads

    # A thread is "orphan" if its start address sits outside every ImageLoad range.
    ranges = collect_image_ranges(events)
    orphan_mask = ~threads["resolved_start_addr"].map(
        lambda a: address_in_any_range(a, ranges)
    )
    has_addr = threads["resolved_start_addr"].notna()
    result = threads[orphan_mask & has_addr]

    if dynamic_memory_only:
        result = result[result["resolved_start_addr"] < SYSTEM_DLL_REGION_LOW]
    return result


# ---- Sysmon detectors ----
# All are no-ops on runs that did not subscribe to Sysmon (provider_name filter
# yields an empty DataFrame). Detectors targeting ``target_pid`` use the Sysmon
# ``TargetProcessId`` property, not the event header PID (which is Sysmon's worker).


def _sysmon_process_access_events(
    events: pd.DataFrame, target_pid: int | None
) -> pd.DataFrame:
    """Sysmon Event-10 rows where TestTarget was the target of the access."""
    if target_pid is None:
        return events.iloc[0:0]
    sysmon = events[events["provider_name"] == "Sysmon"]
    if sysmon.empty:
        return sysmon
    access = sysmon[sysmon["task"].str.startswith("Process accessed", na=False)]
    return access[access["target_process_id"] == target_pid]


def sysmon_process_access_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """Any Sysmon ProcessAccess event targeting the run's TestTarget process.

    Includes ambient sources (Discord, task manager). For the attacker-specific
    signal use ``sysmon_attacker_hostile_handle``.
    """
    return not _sysmon_process_access_events(events, target_pid).empty


def sysmon_process_access_count(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    return int(len(_sysmon_process_access_events(events, target_pid)))


def sysmon_attacker_hostile_handle(
    events: pd.DataFrame, target_pid: int | None, attacker_pid: int | None
) -> bool:
    """The manipulation tool opened a handle to the target with VM_WRITE,
    VM_OPERATION, or CREATE_THREAD in the granted mask."""
    if attacker_pid is None:
        return False
    rows = _sysmon_process_access_events(events, target_pid)
    if rows.empty:
        return False
    candidates = rows[
        (rows["source_process_id"] == attacker_pid)
        & rows["granted_access"].notna()
    ]
    if candidates.empty:
        return False
    # granted_access is float64 in the DataFrame (NaN-tolerant). Cast to int
    # before the bitwise AND or isinstance(m, int) returns False for numpy
    # floats and the detector never fires.
    masks = candidates["granted_access"].apply(
        lambda m: bool(int(m) & ACCESS_MASK_HOSTILE)
    )
    return bool(masks.any())


def sysmon_max_granted_access(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    """Maximum GrantedAccess value across the run's ProcessAccess events. Bit
    decoding belongs to the reader (see ``decode_access_mask``)."""
    rows = _sysmon_process_access_events(events, target_pid)
    if rows.empty:
        return 0
    masks = rows["granted_access"].dropna()
    return int(masks.max()) if not masks.empty else 0


def sysmon_create_remote_thread_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    if target_pid is None:
        return False
    sysmon = events[events["provider_name"] == "Sysmon"]
    if sysmon.empty:
        return False
    rows = sysmon[sysmon["task"].str.startswith("CreateRemoteThread", na=False)]
    return bool((rows["target_process_id"] == target_pid).any())
