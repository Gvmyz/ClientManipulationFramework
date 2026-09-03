// ============================================================================
// UsermodeHookProbe — RQ3 empirical evidence for direct-syscall evasion.
// ============================================================================
//
// WHAT THIS IS
// ------------
// A small self-contained inline-hook framework that we install on our OWN
// process's ntdll before the attack runs. Every time an attack code path
// would call ntdll's Nt* export, our hook counts the invocation and logs
// it. At the end of the run, main.cpp prints the counters.
//
// WHY IT EXISTS
// -------------
// The thesis's RQ3 direct-syscall axis claims that direct-syscall dispatch
// bypasses user-mode API hooks — the mechanism commercial EDR products
// (CrowdStrike, SentinelOne, Carbon Black) use to observe attacker
// activity in user-mode. Our lab does not run any such EDR, so we cannot
// observe an EDR's hooks firing (or not firing) directly. This probe
// simulates ONE such hook, installed on ourselves, so we can measure the
// two paths side by side:
//
//   Win32 path       (baseline)           --> counters increment ≥ 4×
//   Direct-syscall path (--via-direct-syscall) --> counters stay at 0
//
// Combined with the observation that ETW-TI and Sysmon events fire
// identically in both cases (both are kernel-anchored, not user-mode-
// hooked), this yields the four-cell RQ3 evidence table:
//
//                        | probe | ETW-TI | Sysmon |
//   Win32 path           |  > 0  |  fires |  fires |
//   Direct-syscall path  |   0   |  fires |  fires |
//
// HOW IT WORKS
// ------------
// For each Nt* function we care about:
//   1) Look up the address in the loaded ntdll.
//   2) Save the first 14 bytes (for uninstall).
//   3) Overwrite the first 14 bytes with a 14-byte absolute JMP to our
//      probe function (FF 25 00 00 00 00 + 8-byte target).
//   4) Restore original page protection.
//
// Each probe function then:
//   a) Increments its per-function counter.
//   b) Logs the invocation to a plain-text log file.
//   c) Dispatches the syscall via PT::DirectSyscall's stubs directly,
//      which enter the kernel via the `syscall` instruction WITHOUT going
//      back through ntdll's export (avoids infinite recursion into our
//      own hook — this is why the probe requires DirectSyscall to be
//      initialized before it can be installed).
//
// PREREQUISITES
// -------------
// PT::DirectSyscall::Initialize() must have succeeded before Install()
// is called. The probe uses the resolved syscall numbers to dispatch its
// forwards. Install() will invoke Initialize() itself if it wasn't
// already done, and fail if that initialization fails.
//
// LIMITATIONS (name these in the thesis)
// --------------------------------------
// This probe simulates ONE style of user-mode hook (inline-JMP at the
// prologue) and hooks six Nt* functions. Real commercial EDRs may hook
// additional functions, use different techniques (import-address-table
// patching, ETW-Ti+, hardware breakpoints, kernel-callbacks-plus-user-
// mode-correlation), and can vary widely in implementation. The probe
// therefore demonstrates the DIRECTION of the effect (direct-syscall
// bypasses user-mode-prologue hooks) rather than any specific EDR's
// full behaviour. This limitation is intentional: the SysWhispers /
// HellsGate / TartarusGate literature we cite in ch 6.4 documents the
// same technique against a wider set of EDR products.
// ============================================================================

#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <string>

namespace PT::UsermodeHookProbe {

    // Per-function invocation counters. Atomic because Windows loaders
    // and threading can produce concurrent invocations from unrelated
    // parts of the process; correctness matters even at low volume.
    struct HitCounts {
        std::atomic<uint64_t> NtOpenProcess{0};
        std::atomic<uint64_t> NtAllocateVirtualMemory{0};
        std::atomic<uint64_t> NtProtectVirtualMemory{0};
        std::atomic<uint64_t> NtWriteVirtualMemory{0};
        std::atomic<uint64_t> NtReadVirtualMemory{0};
        std::atomic<uint64_t> NtCreateThreadEx{0};
    };

    // Install inline hooks on the six Nt* exports in ntdll.
    // Returns false if any function cannot be resolved or hooked.
    // Requires PT::DirectSyscall to be initialized (Install invokes it
    // if it wasn't already).
    //
    // log_path: file path for the per-invocation log. Empty string
    //           disables the per-call log; counters always work.
    bool Install(const std::wstring& log_path);

    // Restore all patched bytes and close the log. Safe to call even if
    // Install was never called or partially failed.
    void Uninstall();

    // Read-only access to the counters. Read lock-free.
    const HitCounts& GetCounts();

    // Path to the log file, if any.
    const std::wstring& GetLogPath();

    // Zero all counters. Useful right after Install() to discard any
    // ntdll invocations from process startup / loader activity, so the
    // counts reflect only the attack code that runs afterwards.
    void ResetCounts();

    // Diagnostics for the per-call log file: how many WriteFile calls
    // succeeded, and how many were dropped (composition failure, handle
    // invalid, or WriteFile returned an error). Useful when the log file
    // ends up empty despite non-zero hit counters — the ratio tells you
    // whether we even attempted to write.
    uint64_t GetLogLinesWritten();
    uint64_t GetLogLinesDropped();

}  // namespace PT::UsermodeHookProbe
