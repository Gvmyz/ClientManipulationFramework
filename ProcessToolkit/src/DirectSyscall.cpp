// ============================================================================
// DirectSyscall.cpp
// ============================================================================
//
// Runtime resolver for syscall numbers, plus fallback dispatchers.
//
// RESOLVER STRATEGY (HellsGate, am0nsec 2020)
// -------------------------------------------
// For each Nt* function we care about:
//   1. Walk ntdll's Export Directory to find its address.
//   2. Read the first 8 bytes of the function's stub.
//   3. On x64, an unhooked stub begins with:
//        4C 8B D1              mov r10, rcx
//        B8 XX XX XX XX        mov eax, <syscall#>
//        F6 04 25 08 03 FE 7F  test byte ptr [0x7FFE0308], 1
//   4. The 4 bytes at offset 4 are the syscall number.
//
// If the stub has been hooked (typically an EDR replaces the prologue
// with a JMP to a monitoring routine), the first byte will be 0xE9 or
// 0xFF instead of 0x4C. In that case Initialize() returns false and
// callers can decide whether to abort or fall back to Win32 APIs.
//
// A more robust resolver (HalosGate / TartarusGate) walks neighbouring
// exports in ntdll to find an un-hooked stub and computes the target
// syscall number by subtracting the ordinal distance. We keep it simple
// here because our lab does not deploy EDR agents — the resilience story
// we test is about what defenders can see given ETW-TI, not about
// bypassing production EDR products.
// ============================================================================

#include "DirectSyscall.h"

#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <cstdint>
#include <cstring>

// ----------------------------------------------------------------------------
// Assembly stubs live in DirectSyscallStubs.asm. Each stub reads its
// per-function syscall number from a global variable (below) and emits
// the syscall instruction. The variables are declared as C linkage so
// the .asm file can EXTERN them.
// ----------------------------------------------------------------------------
extern "C" {
    // Filled in by Initialize(); the stubs read these at every call.
    // Init value 0xFFFFFFFF is deliberately invalid so an un-resolved
    // call fails loudly rather than silently invoking syscall 0.
    DWORD g_syscall_NtOpenProcess           = 0xFFFFFFFF;
    DWORD g_syscall_NtAllocateVirtualMemory = 0xFFFFFFFF;
    DWORD g_syscall_NtProtectVirtualMemory  = 0xFFFFFFFF;
    DWORD g_syscall_NtWriteVirtualMemory    = 0xFFFFFFFF;
    DWORD g_syscall_NtReadVirtualMemory     = 0xFFFFFFFF;
    DWORD g_syscall_NtCreateThreadEx        = 0xFFFFFFFF;

    // Stubs. Prototypes match the ntdll exports byte-for-byte.
    NTSTATUS Direct_NtOpenProcess(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PtClientId*);
    NTSTATUS Direct_NtAllocateVirtualMemory(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS Direct_NtProtectVirtualMemory(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS Direct_NtWriteVirtualMemory(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS Direct_NtReadVirtualMemory(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS Direct_NtCreateThreadEx(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID,
        PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
}

namespace {

    // Enable/disable + resolved state, updated by Initialize/SetEnabled.
    bool g_direct_syscall_enabled  = false;
    bool g_direct_syscall_resolved = false;

    // Locate ntdll.dll's base address. It's always the second entry in the
    // process's InMemoryOrder module list (first is the .exe itself). We
    // could also call GetModuleHandleW(L"ntdll.dll") but that goes through
    // kernel32, which some EDRs hook — reading the PEB directly is the
    // canonical stealthy approach.
    HMODULE find_ntdll() {
        // PEB access via TEB is the classic "no imports" technique. On
        // x64, TEB pointer is at gs:[0x30], PEB at TEB+0x60.
        PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
        if (!peb || !peb->Ldr) return nullptr;
        auto* head = &peb->Ldr->InMemoryOrderModuleList;
        // Skip the .exe entry (head->Flink), take the next one (ntdll).
        auto* ntdll_entry = CONTAINING_RECORD(
            head->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        return reinterpret_cast<HMODULE>(ntdll_entry->DllBase);
    }

    // Walk ntdll's export table to find a function by name. Returns the
    // export's virtual address (already relocated) or nullptr.
    void* get_export(HMODULE ntdll, const char* name) {
        if (!ntdll || !name) return nullptr;
        auto base = reinterpret_cast<std::uint8_t*>(ntdll);
        auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.Size == 0) return nullptr;
        auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
        auto names   = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
        auto funcs   = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
        auto ords    = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);

        // Linear scan is fine — ntdll has ~2500 exports and we resolve at
        // startup only.
        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            const char* export_name = reinterpret_cast<const char*>(base + names[i]);
            if (std::strcmp(name, export_name) == 0) {
                return base + funcs[ords[i]];
            }
        }
        return nullptr;
    }

    // Extract the syscall number from an ntdll stub. Returns 0xFFFFFFFF
    // if the stub has been hooked (prologue doesn't match the pattern).
    DWORD extract_syscall_number(void* stub_addr) {
        if (!stub_addr) return 0xFFFFFFFF;
        auto* bytes = reinterpret_cast<std::uint8_t*>(stub_addr);
        // Expected prologue: 4C 8B D1 B8 <imm32>
        //                    mov r10, rcx
        //                    mov eax, imm32
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
            return *reinterpret_cast<DWORD*>(bytes + 4);
        }
        // Common hook patterns:
        //   E9 <rel32>         JMP to detour (5 bytes)
        //   FF 25 <rel32>      indirect JMP (6 bytes)
        // Either indicates a user-mode hook we'd need to bypass with a
        // more advanced strategy (HalosGate). Report unresolved.
        return 0xFFFFFFFF;
    }

    // Resolve one syscall. Returns false if the stub was hooked.
    bool resolve_one(HMODULE ntdll, const char* export_name, DWORD& out) {
        void* addr = get_export(ntdll, export_name);
        DWORD n = extract_syscall_number(addr);
        out = n;
        return n != 0xFFFFFFFF;
    }

}  // anonymous namespace


namespace PT::DirectSyscall {

    bool Initialize() {
        HMODULE ntdll = find_ntdll();
        if (!ntdll) return false;

        // Every one of these needs to resolve. If any fails, we treat the
        // whole subsystem as unavailable rather than silently degrade —
        // partial coverage would produce mixed-evasion runs that muddle
        // the RQ3 comparison.
        bool ok = true;
        ok &= resolve_one(ntdll, "NtOpenProcess",           g_syscall_NtOpenProcess);
        ok &= resolve_one(ntdll, "NtAllocateVirtualMemory", g_syscall_NtAllocateVirtualMemory);
        ok &= resolve_one(ntdll, "NtProtectVirtualMemory",  g_syscall_NtProtectVirtualMemory);
        ok &= resolve_one(ntdll, "NtWriteVirtualMemory",    g_syscall_NtWriteVirtualMemory);
        ok &= resolve_one(ntdll, "NtReadVirtualMemory",     g_syscall_NtReadVirtualMemory);
        ok &= resolve_one(ntdll, "NtCreateThreadEx",        g_syscall_NtCreateThreadEx);

        g_direct_syscall_resolved = ok;
        return ok;
    }

    bool IsResolved() { return g_direct_syscall_resolved; }

    void SetEnabled(bool enabled) {
        g_direct_syscall_enabled = enabled && g_direct_syscall_resolved;
    }
    bool IsEnabled() { return g_direct_syscall_enabled; }

    // Wrapper dispatch: emit the direct-syscall stub when enabled and
    // resolved, otherwise fall through to the ntdll export via
    // GetProcAddress so a run without --via-direct-syscall behaves
    // identically to a build without this file at all.
    template <typename Fn>
    Fn* fallback(const char* name) {
        static Fn* cached = nullptr;
        if (!cached) {
            cached = reinterpret_cast<Fn*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name));
        }
        return cached;
    }

    NTSTATUS NtOpenProcess(
        PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, PtClientId* ClientId)
    {
        if (g_direct_syscall_enabled) {
            return Direct_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        }
        using Fn = NTSTATUS NTAPI (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PtClientId*);
        auto* fn = fallback<Fn>("NtOpenProcess");
        return fn ? fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId) : STATUS_ENTRYPOINT_NOT_FOUND;
    }

    NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        if (g_direct_syscall_enabled) {
            return Direct_NtAllocateVirtualMemory(
                ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
        }
        using Fn = NTSTATUS NTAPI (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        auto* fn = fallback<Fn>("NtAllocateVirtualMemory");
        return fn ? fn(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
                  : STATUS_ENTRYPOINT_NOT_FOUND;
    }

    NTSTATUS NtProtectVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect)
    {
        if (g_direct_syscall_enabled) {
            return Direct_NtProtectVirtualMemory(
                ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }
        using Fn = NTSTATUS NTAPI (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        auto* fn = fallback<Fn>("NtProtectVirtualMemory");
        return fn ? fn(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)
                  : STATUS_ENTRYPOINT_NOT_FOUND;
    }

    NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
    {
        if (g_direct_syscall_enabled) {
            return Direct_NtWriteVirtualMemory(
                ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
        }
        using Fn = NTSTATUS NTAPI (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        auto* fn = fallback<Fn>("NtWriteVirtualMemory");
        return fn ? fn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
                  : STATUS_ENTRYPOINT_NOT_FOUND;
    }

    NTSTATUS NtReadVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
    {
        if (g_direct_syscall_enabled) {
            return Direct_NtReadVirtualMemory(
                ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
        }
        using Fn = NTSTATUS NTAPI (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        auto* fn = fallback<Fn>("NtReadVirtualMemory");
        return fn ? fn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead)
                  : STATUS_ENTRYPOINT_NOT_FOUND;
    }

    NTSTATUS NtCreateThreadEx(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
        PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
        SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
        PVOID AttributeList)
    {
        if (g_direct_syscall_enabled) {
            return Direct_NtCreateThreadEx(
                ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                MaximumStackSize, AttributeList);
        }
        using Fn = NTSTATUS NTAPI (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                   PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        auto* fn = fallback<Fn>("NtCreateThreadEx");
        return fn ? fn(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                       StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                       MaximumStackSize, AttributeList)
                  : STATUS_ENTRYPOINT_NOT_FOUND;
    }

}  // namespace PT::DirectSyscall
