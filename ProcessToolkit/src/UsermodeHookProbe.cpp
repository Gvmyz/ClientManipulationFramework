// ============================================================================
// UsermodeHookProbe.cpp — implementation of the RQ3 direct-syscall probe.
// ============================================================================
//
// See UsermodeHookProbe.h for the "what and why" — this file is the "how".
//
// PATCH LAYOUT
// ------------
// We overwrite the first 14 bytes of each Nt* stub in the loaded ntdll
// with the following opcode sequence:
//
//   FF 25 00 00 00 00        ; JMP QWORD PTR [RIP+0]
//   <8-byte absolute address of Probe_Nt*>
//
// This is the standard x64 absolute-JMP idiom. The 8-byte address is
// placed immediately after the 6-byte JMP opcode, so [RIP+0] resolves
// to that address at execution time.
//
// We deliberately do NOT try to preserve the original ntdll code (i.e.
// no trampoline back to ntdll+14). Our probe forwards to the direct-
// syscall stubs (Direct_Nt*) directly, entering the kernel via `syscall`
// without going back through ntdll's export. This has two nice
// properties:
//   1) No risk of self-recursion (Direct_Nt* bypasses our own hooks).
//   2) The forwarded call takes the exact same code path as if
//      --via-direct-syscall had been set for the attack itself, which
//      means the observable side effects (kernel-level events) are
//      identical to the direct-syscall attack path. The ONLY difference
//      between Win32-attack-with-probe and direct-syscall-attack-with-
//      probe is whether ntdll's export was invoked at all — which is
//      exactly what the counters measure.
//
// HOOK FUNCTION SIGNATURES
// ------------------------
// Signatures MUST match the ntdll exports byte-for-byte. If they don't,
// the arguments arrive in the wrong registers/stack slots when the
// caller (e.g. kernel32!WriteProcessMemory) JMPs into our probe, and
// the syscall parameters end up garbage. Every signature below is
// cross-checked against ntdll's exported prototype.
//
// LOG FILE FORMAT
// ---------------
// Plain UTF-16 text, one line per invocation, function name only. This
// is enough to prove which functions fired and how many times, without
// spending output-buffer bandwidth per call (relevant when the probe
// might see hundreds of hook fires under a manualmap attack).
// ============================================================================

#include "UsermodeHookProbe.h"
#include "DirectSyscall.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>

// ----------------------------------------------------------------------------
// External refs to DirectSyscall's assembly stubs. Declared with C linkage
// because they live in DirectSyscallStubs.asm and are exposed with C names
// via `extern "C"` in DirectSyscall.cpp. We forward to these directly so
// that our own hooks don't recurse into themselves.
// ----------------------------------------------------------------------------
extern "C" {
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
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
        PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
}

namespace {

    // 6 bytes JMP opcode + 8 bytes absolute target = 14.
    constexpr size_t JMP_PATCH_SIZE = 14;

    struct HookRecord {
        void*  target;                            // ntdll export address
        BYTE   saved_bytes[JMP_PATCH_SIZE]{};     // original bytes (for uninstall)
        DWORD  saved_protection{0};               // page protection before we changed it
        bool   installed{false};
    };

    // Fixed-size array; six functions. Indices are the natural order:
    // Open, Alloc, Protect, Write, Read, CreateThreadEx.
    HookRecord g_records[6]{};

    PT::UsermodeHookProbe::HitCounts g_counts;
    std::wstring   g_log_path;
    std::wofstream g_log;
    std::mutex     g_log_mutex;

    void log_hit(const wchar_t* name) {
        if (g_log_path.empty()) return;
        std::lock_guard<std::mutex> lock(g_log_mutex);
        if (g_log.is_open()) {
            g_log << name << L'\n';
            g_log.flush();
        }
    }

    // ------------------------------------------------------------------------
    // The six probe functions. Each is what a user-mode-hooked EDR would
    // effectively install at this API surface. On invocation:
    //   1) bump the counter
    //   2) log the name
    //   3) dispatch to Direct_Nt* (which enters the kernel directly)
    //
    // The `NTAPI` calling convention is __stdcall on x86 and the standard
    // x64 calling convention on x64 — matching ntdll's own convention.
    // ------------------------------------------------------------------------

    NTSTATUS NTAPI Probe_NtOpenProcess(
        PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, PtClientId* ClientId)
    {
        g_counts.NtOpenProcess.fetch_add(1, std::memory_order_relaxed);
        log_hit(L"NtOpenProcess");
        return Direct_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    NTSTATUS NTAPI Probe_NtAllocateVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        g_counts.NtAllocateVirtualMemory.fetch_add(1, std::memory_order_relaxed);
        log_hit(L"NtAllocateVirtualMemory");
        return Direct_NtAllocateVirtualMemory(
            ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    NTSTATUS NTAPI Probe_NtProtectVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect)
    {
        g_counts.NtProtectVirtualMemory.fetch_add(1, std::memory_order_relaxed);
        log_hit(L"NtProtectVirtualMemory");
        return Direct_NtProtectVirtualMemory(
            ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }

    NTSTATUS NTAPI Probe_NtWriteVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
    {
        g_counts.NtWriteVirtualMemory.fetch_add(1, std::memory_order_relaxed);
        log_hit(L"NtWriteVirtualMemory");
        return Direct_NtWriteVirtualMemory(
            ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }

    NTSTATUS NTAPI Probe_NtReadVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
    {
        g_counts.NtReadVirtualMemory.fetch_add(1, std::memory_order_relaxed);
        log_hit(L"NtReadVirtualMemory");
        return Direct_NtReadVirtualMemory(
            ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    }

    NTSTATUS NTAPI Probe_NtCreateThreadEx(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
        PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
        SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
        PVOID AttributeList)
    {
        g_counts.NtCreateThreadEx.fetch_add(1, std::memory_order_relaxed);
        log_hit(L"NtCreateThreadEx");
        return Direct_NtCreateThreadEx(
            ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
            StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
            MaximumStackSize, AttributeList);
    }

    // ------------------------------------------------------------------------
    // Emit the 14-byte JMP-to-absolute pattern into `dst`.
    // ------------------------------------------------------------------------
    void build_jmp(BYTE* dst, void* target) {
        // FF 25 00 00 00 00 = JMP QWORD PTR [RIP+0]
        dst[0] = 0xFF;
        dst[1] = 0x25;
        dst[2] = 0x00; dst[3] = 0x00; dst[4] = 0x00; dst[5] = 0x00;
        // Absolute target immediately follows.
        std::memcpy(dst + 6, &target, sizeof(target));
    }

    bool install_one(size_t slot, const char* name, void* probe_fn) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        void* target = reinterpret_cast<void*>(GetProcAddress(ntdll, name));
        if (!target) return false;

        HookRecord& rec = g_records[slot];
        rec.target = target;

        // Make the page writable so we can patch its first 14 bytes.
        if (!VirtualProtect(target, JMP_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &rec.saved_protection)) {
            return false;
        }

        // Save originals (for Uninstall).
        std::memcpy(rec.saved_bytes, target, JMP_PATCH_SIZE);

        // Overwrite with the JMP.
        BYTE patch[JMP_PATCH_SIZE];
        build_jmp(patch, probe_fn);
        std::memcpy(target, patch, JMP_PATCH_SIZE);

        // Restore original page protection. We deliberately do NOT keep the
        // page writable — a real EDR wouldn't, and leaving it writable would
        // itself be a fingerprint if the target process ever queried its own
        // ntdll's memory map.
        DWORD dummy;
        VirtualProtect(target, JMP_PATCH_SIZE, rec.saved_protection, &dummy);

        // Force the instruction cache to pick up the change. Not strictly
        // required on x64 (Intel handles self-modifying code coherently for
        // most cases), but standard practice.
        FlushInstructionCache(GetCurrentProcess(), target, JMP_PATCH_SIZE);

        rec.installed = true;
        return true;
    }

    void uninstall_one(size_t slot) {
        HookRecord& rec = g_records[slot];
        if (!rec.installed) return;

        DWORD prev;
        if (!VirtualProtect(rec.target, JMP_PATCH_SIZE, PAGE_EXECUTE_READWRITE, &prev)) return;

        std::memcpy(rec.target, rec.saved_bytes, JMP_PATCH_SIZE);

        DWORD dummy;
        VirtualProtect(rec.target, JMP_PATCH_SIZE, rec.saved_protection, &dummy);
        FlushInstructionCache(GetCurrentProcess(), rec.target, JMP_PATCH_SIZE);

        rec.installed = false;
    }

}  // anonymous namespace


namespace PT::UsermodeHookProbe {

    bool Install(const std::wstring& log_path) {
        if (!DirectSyscall::IsResolved()) {
            if (!DirectSyscall::Initialize()) return false;
        }

        g_log_path = log_path;
        if (!g_log_path.empty()) {
            g_log.open(g_log_path, std::ios::out | std::ios::trunc);
        }

        // Install all six. If any fail, we still return false so main.cpp
        // can abort — a partial probe would give misleading counts.
        bool ok = true;
        ok &= install_one(0, "NtOpenProcess",           reinterpret_cast<void*>(&Probe_NtOpenProcess));
        ok &= install_one(1, "NtAllocateVirtualMemory", reinterpret_cast<void*>(&Probe_NtAllocateVirtualMemory));
        ok &= install_one(2, "NtProtectVirtualMemory",  reinterpret_cast<void*>(&Probe_NtProtectVirtualMemory));
        ok &= install_one(3, "NtWriteVirtualMemory",    reinterpret_cast<void*>(&Probe_NtWriteVirtualMemory));
        ok &= install_one(4, "NtReadVirtualMemory",     reinterpret_cast<void*>(&Probe_NtReadVirtualMemory));
        ok &= install_one(5, "NtCreateThreadEx",        reinterpret_cast<void*>(&Probe_NtCreateThreadEx));
        return ok;
    }

    void Uninstall() {
        for (size_t i = 0; i < 6; ++i) uninstall_one(i);
        if (g_log.is_open()) g_log.close();
    }

    const HitCounts&   GetCounts()   { return g_counts; }
    const std::wstring& GetLogPath() { return g_log_path; }

    void ResetCounts() {
        g_counts.NtOpenProcess.store(0);
        g_counts.NtAllocateVirtualMemory.store(0);
        g_counts.NtProtectVirtualMemory.store(0);
        g_counts.NtWriteVirtualMemory.store(0);
        g_counts.NtReadVirtualMemory.store(0);
        g_counts.NtCreateThreadEx.store(0);
    }

}  // namespace PT::UsermodeHookProbe
