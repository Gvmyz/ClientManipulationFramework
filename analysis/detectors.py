"""Behavioral indicators derived from raw events.

These are the "interesting" predicates that map low-level events to higher-level
observations the thesis cares about. Each detector documents both *what* it
measures and *why* it is expected to discriminate between techniques.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath

import pandas as pd


# The injected DLL filename used in our experiments. Comparison is case-insensitive
# because Windows ETW emits paths verbatim from the filesystem.
INJECTED_DLL_FILENAME = "testdll.dll"

# On Windows x64 the user-mode addressable space ends at 0x00007FFF_FFFFFFFF.
# System DLLs (ntdll, kernel32, user32, ...) are almost always loaded in the high
# region 0x00007FF8_00000000 .. 0x00007FFF_FFFFFFFF. Heap and VirtualAlloc-backed
# pages live well below that. We use this threshold to flag "definitely dynamic"
# memory addresses even when the loaded modules in that region were never
# observed via ImageLoad events (e.g. pre-existing system DLLs whose load
# predates the trace).
SYSTEM_DLL_REGION_LOW = 0x00007FF000000000


def basename_lower(path: str) -> str:
    """Return the lowercase filename portion of a Windows path-like string."""
    if not path:
        return ""
    # PureWindowsPath also handles \Device\HarddiskVolume3\... prefixes correctly.
    return PureWindowsPath(path).name.lower()


def injected_dll_observed(events: pd.DataFrame) -> bool:
    """True iff TestDll.dll appeared as an ImageLoad event.

    Discrimination expectation:
      - loadlibrary  -> True  (LoadLibraryW triggers the normal loader path)
      - threadhijack -> True  (also goes through LoadLibraryW)
      - manualmap    -> False (the defining property of manual mapping: the DLL
                               is never registered with the PEB loader and
                               therefore never emits an ImageLoad event)
    """
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
    """Build the list of (base, end, name) ranges for every observed ImageLoad."""
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

# Used as: is this address inside any known module?
def address_in_any_range(addr: int | None, ranges: list[ImageRange]) -> bool:
    if addr is None:
        return False
    for r in ranges:
        if r.base <= addr < r.end:
            return True
    return False


def unique_threads(events: pd.DataFrame) -> pd.DataFrame:
    """Return one row per observed TID with its start address.

    A thread may surface as a ThreadStart, a ThreadStop, or both. In particular,
    short-lived injection threads created shortly after the ETW session begins
    often emit only the ThreadStop (the Start fires before the provider is fully
    enabled). To avoid missing them we deduplicate by TID across both opcodes
    and pick the earliest timestamp at which we saw that thread.
    """
    thread_events = events[events["task"].isin(["ThreadStart", "ThreadStop"])].copy()
    if thread_events.empty:
        return thread_events

    # Prefer Win32StartAddr; fall back to StartAddr when only the latter is set.
    thread_events["resolved_start_addr"] = thread_events["win32_start_addr"].fillna(
        thread_events["start_addr"]
    )
    thread_events = thread_events.dropna(subset=["thread_id"])

    # Pick the earliest event per TID so the timestamp reflects first observation.
    thread_events = thread_events.sort_values("timestamp")
    return thread_events.drop_duplicates(subset=["thread_id"], keep="first")


# Note: Extremely short-lived threads can lose their ETW start event.
# unique_threads() combines ThreadStart and ThreadStop to reliably detect stub threads.
def orphan_threads(events: pd.DataFrame, *, dynamic_memory_only: bool = True) -> pd.DataFrame:
    """Return threads whose start address is outside every observed image range.

    Discrimination expectation:
      - manualmap    -> 1+ in the dynamic-memory region (stub + RunTest threads
                        live in VirtualAllocEx-backed pages that are never
                        registered as a loaded module)
      - loadlibrary  -> 0 in the dynamic-memory region (the inject thread starts
                        at LoadLibraryW in kernel32, which IS a loaded module)
      - threadhijack -> 0 in the dynamic-memory region (no new thread at all)
      - baseline     -> 0 in the dynamic-memory region

    ``dynamic_memory_only`` filters to addresses below SYSTEM_DLL_REGION_LOW so
    pre-existing system threads (whose owning DLLs predate the trace and thus
    have no captured ImageLoad event) are not falsely flagged as orphan. This
    biases toward precision at a small cost in recall: any injection that
    happens to allocate its stub above 0x7FF0_0000_0000 will be missed, but
    that range is reserved for system images in practice.
    """
    threads = unique_threads(events)
    if threads.empty:
        return threads

    ranges = collect_image_ranges(events)
    orphan_mask = ~threads["resolved_start_addr"].map(
        lambda a: address_in_any_range(a, ranges)
    )
    has_addr = threads["resolved_start_addr"].notna()
    result = threads[orphan_mask & has_addr]

    if dynamic_memory_only:
        result = result[result["resolved_start_addr"] < SYSTEM_DLL_REGION_LOW]
    return result
