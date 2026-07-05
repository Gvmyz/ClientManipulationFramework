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

# Sysmon-8 StartFunction values that indicate a "load a DLL" pattern. Manualmap
# drives one CreateRemoteThread(LoadLibraryA) per imported DLL, so counting
# these separates manualmap from loadlibrary (which contributes exactly 1).
LOADER_START_FUNCTIONS = frozenset({
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
})

# x64 user-mode system DLLs live in 0x00007FF8.. and above. Heap and
# VirtualAlloc-backed pages live well below this. Used to flag dynamic-memory
# addresses without needing an ImageLoad event for every system DLL.
SYSTEM_DLL_REGION_LOW = 0x00007FF000000000

# Memory-protection page flags (winnt.h), used by ETW-TI ProtectionMask. We
# only need the executable bits; any of these means the page can run code.
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTABLE_MASK = (
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)

# ETW-TI task names we discriminate on. Names match the provider's
# manifest exactly so a typo here is a silent miss.
TI_TASK_ALLOCVM = "KERNEL_THREATINT_TASK_ALLOCVM"
TI_TASK_WRITEVM = "KERNEL_THREATINT_TASK_WRITEVM"
TI_TASK_PROTECTVM = "KERNEL_THREATINT_TASK_PROTECTVM"
TI_TASK_MAPVIEW = "KERNEL_THREATINT_TASK_MAPVIEW"
TI_TASK_SETTHREADCONTEXT = "KERNEL_THREATINT_TASK_SETTHREADCONTEXT"
TI_TASK_QUEUEUSERAPC = "KERNEL_THREATINT_TASK_QUEUEUSERAPC"
TI_TASK_SUSPENDRESUME_THREAD = "KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD"


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

def injected_dll_observed(events: pd.DataFrame, target_pid: int | None = None) -> bool:
    """True iff TestDll.dll appears as an ImageLoad event *inside the target
    process*.

    Without the ``target_pid`` filter, this also fires when the injector loads
    TestDll locally — e.g. ``--call RunTest`` calls LoadLibraryW in
    ProcessToolkit's own address space to compute the RunTest offset — which
    makes the detector a false positive for manualmap. Scoping to the target's
    PID isolates the loader-visible signal to the victim process.
    """
    image_loads = events[events["task"] == "ImageLoad"]
    if target_pid is not None:
        image_loads = image_loads[image_loads["pid"] == target_pid]
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


def sysmon_attacker_hostile_handle_strict(
    events: pd.DataFrame, target_pid: int | None, attacker_pid: int | None
) -> bool:
    """Stricter variant of ``sysmon_attacker_hostile_handle``: requires
    PROCESS_CREATE_THREAD (0x0002) specifically.

    Ambient Windows services (svchost, MsMpEng) commonly hold handles with
    VM_WRITE and VM_OPERATION but never CREATE_THREAD. That single bit is the
    sharpest discriminator of injection intent from benign cross-process
    traffic in the current data.
    """
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
    return bool(
        candidates["granted_access"]
        .apply(lambda m: bool(int(m) & PROCESS_CREATE_THREAD))
        .any()
    )


def sysmon_create_remote_thread_load_library_count(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    """Count of Sysmon-8 events targeting TestTarget whose StartFunction is a
    LoadLibrary* export.

    Manualmap drives one such thread per imported DLL of the mapped image
    (typically 3-5). Loadlibrary contributes exactly 1 (the injection thread
    itself). Threadhijack contributes 0. This count is a strong discriminator
    for manualmap even when its ImageLoad signal is absent.
    """
    if target_pid is None:
        return 0
    sysmon = events[events["provider_name"] == "Sysmon"]
    if sysmon.empty:
        return 0
    rows = sysmon[
        sysmon["task"].str.startswith("CreateRemoteThread", na=False)
        & (sysmon["target_process_id"] == target_pid)
        & sysmon["start_function"].isin(LOADER_START_FUNCTIONS)
    ]
    return int(len(rows))


def sysmon_create_remote_thread_orphan_count(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    """Count of Sysmon-8 events targeting TestTarget whose StartFunction is "-"
    (unresolved to any module export).

    An unresolved start address means the target thread runs in memory that
    Sysmon cannot name — dynamically allocated shellcode or a manually-mapped
    image. Combined with an orphan KernelProcess ThreadStart at the same
    address, this is the loader-bypass signature.
    """
    if target_pid is None:
        return 0
    sysmon = events[events["provider_name"] == "Sysmon"]
    if sysmon.empty:
        return 0
    rows = sysmon[
        sysmon["task"].str.startswith("CreateRemoteThread", na=False)
        & (sysmon["target_process_id"] == target_pid)
        & (sysmon["start_function"] == "-")
    ]
    return int(len(rows))


# ---- ThreatIntelligence (ETW-TI) detectors ----
# Cross-process telemetry from the kernel: the actual NtAllocate/Write/Protect/
# SetContext syscalls behind the Win32 injection primitives. Each detector
# requires the run's TestTarget PID; cross-process means CallingProcessId
# (the injector) differs from TargetProcessId (the victim). Returns False/0
# when TI was not subscribed for this run.


def _ti_targeted_events(
    events: pd.DataFrame, target_pid: int | None
) -> pd.DataFrame:
    """ThreatIntelligence events that *targeted* the run's TestTarget. Drops
    self-operations (CallingProcessId == TargetProcessId), which are ambient
    same-process allocations not attributable to an injection."""
    if target_pid is None:
        return events.iloc[0:0]
    ti = events[events["provider_name"] == "ThreatIntelligence"]
    if ti.empty:
        return ti
    targeted = ti[ti["target_process_id"] == target_pid]
    return targeted[targeted["calling_process_id"] != targeted["target_process_id"]]


def threatint_cross_process_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """Any cross-process TI operation against the target. Coarse umbrella signal:
    if this is True the technique is *visible* to ETW-TI at all."""
    return not _ti_targeted_events(events, target_pid).empty


def threatint_cross_process_count(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    return int(len(_ti_targeted_events(events, target_pid)))


def _ti_task_observed(
    events: pd.DataFrame, target_pid: int | None, task_name: str
) -> bool:
    targeted = _ti_targeted_events(events, target_pid)
    if targeted.empty:
        return False
    return bool((targeted["task"] == task_name).any())


def threatint_remote_alloc_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """NtAllocateVirtualMemory into the target. Manual-map / shellcode injection
    light this up; LoadLibrary injection does not (it allocates only in the
    injector for the DLL-path string)."""
    return _ti_task_observed(events, target_pid, TI_TASK_ALLOCVM)


def threatint_remote_executable_alloc_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """Remote alloc with an executable page protection (PAGE_EXECUTE_*). The
    canonical "remote RWX" injection signal — far stronger than a plain
    remote alloc, which can be a read-write scratch buffer."""
    targeted = _ti_targeted_events(events, target_pid)
    if targeted.empty:
        return False
    allocs = targeted[targeted["task"] == TI_TASK_ALLOCVM]
    if allocs.empty:
        return False
    return bool(
        allocs["protection_mask"]
        .dropna()
        .map(lambda m: bool(int(m) & PAGE_EXECUTABLE_MASK))
        .any()
    )


def threatint_remote_write_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """NtWriteVirtualMemory into the target (code/data planted by the injector)."""
    return _ti_task_observed(events, target_pid, TI_TASK_WRITEVM)


def threatint_remote_protect_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """NtProtectVirtualMemory against the target — the RW→RX flip used by
    stagers and the protection change behind in-process patches."""
    return _ti_task_observed(events, target_pid, TI_TASK_PROTECTVM)


def threatint_thread_hijack_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """NtSetContextThread against a thread in the target. Inherently
    cross-process and the single highest-confidence injection signal — almost
    no benign software does this."""
    return _ti_task_observed(events, target_pid, TI_TASK_SETTHREADCONTEXT)


# ---- ThreatIntelligence (ETW-TI) detectors ----
# All no-ops on runs that did not subscribe to the ThreatIntelligence provider.
# TI attributes the *source* of a cross-process operation to CallingProcessId and
# the *victim* to TargetProcessId (both distinct from the event header pid). A
# genuine injection signal is a TI event where calling != target and target is the
# run's TestTarget. Self-operations (calling == target, e.g. a process allocating
# RWX in itself) are ambient noise and are deliberately excluded.

TI_PROVIDER = "ThreatIntelligence"

# Memory-protection bits (winnt.h) that grant execute. PAGE_EXECUTE 0x10,
# _READ 0x20, _READWRITE 0x40, _WRITECOPY 0x80.
PAGE_EXECUTE_ANY = 0x10 | 0x20 | 0x40 | 0x80


def _threatint_events(events: pd.DataFrame) -> pd.DataFrame:
    if "provider_name" not in events.columns or events.empty:
        return events.iloc[0:0]
    return events[events["provider_name"] == TI_PROVIDER]


def _threatint_cross_process(
    events: pd.DataFrame, target_pid: int | None
) -> pd.DataFrame:
    """TI events crossing a process boundary into the run's target:
    calling != target and target == target_pid."""
    if target_pid is None:
        return events.iloc[0:0]
    ti = _threatint_events(events)
    if ti.empty:
        return ti
    return ti[
        ti["target_process_id"].notna()
        & ti["calling_process_id"].notna()
        & (ti["target_process_id"] == target_pid)
        & (ti["calling_process_id"] != ti["target_process_id"])
    ]


def _ti_task(events: pd.DataFrame, target_pid: int | None, needle: str) -> pd.DataFrame:
    cross = _threatint_cross_process(events, target_pid)
    if cross.empty:
        return cross
    return cross[cross["task"].str.contains(needle, case=False, na=False)]


def threatint_cross_process_observed(events: pd.DataFrame, target_pid: int | None) -> bool:
    """Any cross-process TI operation against the target (broadest TI signal)."""
    return not _threatint_cross_process(events, target_pid).empty


def threatint_cross_process_count(events: pd.DataFrame, target_pid: int | None) -> int:
    return int(len(_threatint_cross_process(events, target_pid)))


def threatint_cross_process_write_count(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    """Cross-process WRITEVM events targeting TestTarget. Attributed to the
    injection primitive itself; excludes ambient READVM_REMOTE which dominates
    the raw ``threatint_cross_process_count``."""
    cross = _threatint_cross_process(events, target_pid)
    if cross.empty:
        return 0
    return int(cross["task"].str.contains("WRITEVM", case=False, na=False).sum())


def threatint_cross_process_alloc_count(
    events: pd.DataFrame, target_pid: int | None
) -> int:
    """Cross-process ALLOCVM events targeting TestTarget. Only fires for
    executable-protection allocs — a Windows kernel design decision that
    partially hides RW-only injectors (e.g. classic LoadLibraryW via a
    non-executable path buffer)."""
    cross = _threatint_cross_process(events, target_pid)
    if cross.empty:
        return 0
    return int(cross["task"].str.contains("ALLOCVM", case=False, na=False).sum())


def threatint_remote_alloc_observed(events: pd.DataFrame, target_pid: int | None) -> bool:
    """Remote VirtualAllocEx into the target (KERNEL_THREATINT_TASK_ALLOCVM)."""
    return not _ti_task(events, target_pid, "ALLOCVM").empty


def threatint_remote_executable_alloc_observed(
    events: pd.DataFrame, target_pid: int | None
) -> bool:
    """Remote allocation of *executable* memory in the target — the strongest
    classic injection signal (RWX/RX shellcode region)."""
    rows = _ti_task(events, target_pid, "ALLOCVM")
    if rows.empty or "protection_mask" not in rows.columns:
        return False
    masks = rows["protection_mask"].dropna()
    if masks.empty:
        return False
    return bool(masks.apply(lambda m: bool(int(m) & PAGE_EXECUTE_ANY)).any())


def threatint_remote_write_observed(events: pd.DataFrame, target_pid: int | None) -> bool:
    """Remote WriteProcessMemory into the target (WRITEVM)."""
    return not _ti_task(events, target_pid, "WRITEVM").empty


def threatint_remote_protect_observed(events: pd.DataFrame, target_pid: int | None) -> bool:
    """Remote VirtualProtect on the target (PROTECTVM) — the RX flip used by
    memory patching and by arming a written shellcode region."""
    return not _ti_task(events, target_pid, "PROTECTVM").empty


def threatint_thread_hijack_observed(events: pd.DataFrame, target_pid: int | None) -> bool:
    """SetThreadContext against a thread in the target (SETTHREADCONTEXT) —
    the defining primitive of thread-hijack injection."""
    return not _ti_task(events, target_pid, "SETTHREADCONTEXT").empty
