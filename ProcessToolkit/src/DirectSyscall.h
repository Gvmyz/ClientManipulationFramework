// ============================================================================
// DirectSyscall — user-mode-hook bypass via direct syscall instructions.
// ============================================================================
//
// PURPOSE
// -------
// Provides drop-in replacements for the Windows Nt* system-call wrappers
// that would normally live in ntdll.dll's exports. Instead of calling
// ntdll's exported function (which is where Sysmon, EDR agents, and any
// other user-mode telemetry install their hooks), we emit the `syscall`
// instruction ourselves with the correct syscall number in the `rax`
// register, entering the kernel directly.
//
// WHY THIS MATTERS FOR THE THESIS
// -------------------------------
// This is the "direct-syscall" evasion technique documented in threat
// literature (SysWhispers/HellsGate/TartarusGate family; MITRE ATT&CK
// T1106 Native API). It defeats every telemetry source that lives in
// user mode — Sysmon in particular — but does NOT defeat ETW-TI, whose
// events are emitted from the kernel-mode syscall handlers themselves.
//
// Comparing the classifier's output when the attacker uses the Win32
// API path vs. when it uses this direct-syscall path is one of the
// RQ3 evasion axes. It provides evidence for the design commitment
// stated in Chapter 3 (variant-level classification uses only
// ETW-TI-derived primitives) from an angle complementary to the
// provider-removal test.
//
// HOW IT WORKS
// ------------
// Windows exposes system calls to user-mode as functions in ntdll.dll
// (e.g. NtWriteVirtualMemory). Each of these functions is a thin stub
// that on x64 looks like:
//
//   mov r10, rcx          ; syscall convention places param1 in r10 not rcx
//   mov eax, <syscall#>   ; the 32-bit syscall number identifying the op
//   syscall               ; transition to kernel; the kernel dispatches
//   ret
//
// The syscall number is a small integer that changes across Windows
// builds. Rather than hardcoding it (which would break on any other
// Windows version), we resolve it at runtime by parsing ntdll's export
// directory, locating each Nt* function's stub, and reading the 4 bytes
// at offset 4 (the `mov eax, imm32` immediate). This is the technique
// introduced by am0nsec's HellsGate (2020). Cite HellsGate for the
// runtime-resolution pattern and SysWhispers3 for the current syscall-
// table maintenance.
//
// USAGE
// -----
// 1) Call Initialize() once at program start.
// 2) When --via-direct-syscall is set, cross-process primitives in
//    Memory.cpp route through these wrappers instead of Win32 APIs.
// 3) The classifier's per-run features + verdict then reveal whether
//    the direct-syscall path evades any Tier-1 discriminators.
// ============================================================================

#pragma once

#include <windows.h>
#include <winternl.h>   // NTSTATUS, OBJECT_ATTRIBUTES, PEB, LDR_DATA_TABLE_ENTRY, ...

// SDK versions vary widely in which NT structs winternl.h exposes.
// To avoid the game of "is CLIENT_ID / PCLIENT_ID / STATUS_* already
// declared?", we ship uniquely-named replacements. Their memory layout
// matches the SDK originals because the kernel reads them by ABI-fixed
// offsets, not by C type identity.
struct PtClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND ((NTSTATUS)0xC0000BC0L)
#endif

namespace PT::DirectSyscall {

    // Resolve every syscall number this module needs by parsing ntdll's
    // exports and disassembling the stub prologues. Returns false if any
    // required syscall could not be resolved (e.g. ntdll's stub was
    // hooked by an EDR — see HalosGate for a fallback strategy).
    // Call once at program start.
    bool Initialize();

    // Whether Initialize() succeeded. Wrappers below still work if this
    // returned false, but they'll fall through to the ntdll exports.
    bool IsResolved();

    // Toggle direct-syscall dispatch at runtime. When true, wrappers
    // emit `syscall` directly. When false, wrappers call ntdll's export
    // (useful for A/B testing without a rebuild).
    void SetEnabled(bool enabled);
    bool IsEnabled();

    // ---------------------------------------------------------------------
    // Direct-syscall wrappers. Signatures match the Nt* exports in ntdll
    // so callers can substitute one for the other.
    // ---------------------------------------------------------------------

    // Open a handle to a target process. Bypasses OpenProcess's kernel32
    // wrapper (which Sysmon's Event-10 ProcessAccess hook fires on).
    NTSTATUS NtOpenProcess(
        PHANDLE            ProcessHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PtClientId*        ClientId);

    // Allocate memory in the target. Bypasses VirtualAllocEx.
    NTSTATUS NtAllocateVirtualMemory(
        HANDLE   ProcessHandle,
        PVOID*   BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T  RegionSize,
        ULONG    AllocationType,
        ULONG    Protect);

    // Change protection of memory in the target. Bypasses VirtualProtectEx.
    NTSTATUS NtProtectVirtualMemory(
        HANDLE   ProcessHandle,
        PVOID*   BaseAddress,
        PSIZE_T  RegionSize,
        ULONG    NewProtect,
        PULONG   OldProtect);

    // Write bytes into the target. Bypasses WriteProcessMemory.
    NTSTATUS NtWriteVirtualMemory(
        HANDLE   ProcessHandle,
        PVOID    BaseAddress,
        PVOID    Buffer,
        SIZE_T   NumberOfBytesToWrite,
        PSIZE_T  NumberOfBytesWritten);

    // Read bytes from the target. Bypasses ReadProcessMemory.
    NTSTATUS NtReadVirtualMemory(
        HANDLE   ProcessHandle,
        PVOID    BaseAddress,
        PVOID    Buffer,
        SIZE_T   NumberOfBytesToRead,
        PSIZE_T  NumberOfBytesRead);

    // Create a remote thread. Bypasses CreateRemoteThread — a Sysmon
    // Event-8 firing point that also generates a KernelProcess ImageLoad
    // side effect through the loader.
    // NB: NtCreateThreadEx takes more arguments than CreateRemoteThread;
    // we expose a simplified surface for our injection primitive.
    NTSTATUS NtCreateThreadEx(
        PHANDLE            ThreadHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE             ProcessHandle,
        PVOID              StartRoutine,
        PVOID              Argument,
        ULONG              CreateFlags,
        SIZE_T             ZeroBits,
        SIZE_T             StackSize,
        SIZE_T             MaximumStackSize,
        PVOID              AttributeList);

}  // namespace PT::DirectSyscall
