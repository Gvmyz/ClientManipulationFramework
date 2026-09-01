; =============================================================================
; DirectSyscallStubs.asm — x64 direct-syscall stubs for the NT primitives.
; =============================================================================
;
; MSVC's x64 compiler will NOT emit the `syscall` instruction from inline
; asm (inline asm is unsupported on x64). We therefore ship the stubs as
; a standalone MASM file compiled with ml64.exe.
;
; Each stub reads its per-function syscall number from a global variable
; that DirectSyscall.cpp fills at runtime (via HellsGate-style parsing
; of ntdll's stubs). The stub then follows the Windows x64 syscall
; convention:
;
;   mov r10, rcx          ; the kernel expects param 1 in r10, not rcx
;   mov eax, <syscall#>   ; the actual syscall number
;   syscall               ; enter kernel; return in rax
;   ret                   ; return to the C caller
;
; RCX/RDX/R8/R9 hold the first four args per the standard x64 ABI, and
; the direct-syscall convention preserves them; the kernel picks them up
; unchanged. Arg5+ are on the stack per the shadow-store convention and
; the kernel reads them via the standard ABI too.
;
; No caller-side changes needed: our C++ prototypes match the ntdll
; exports exactly, so the compiler generates the same argument-passing
; code it would have for a normal ntdll call.
;
; BUILD (MSBuild vcxproj):
;   Right-click the project -> Build Dependencies -> Build Customizations
;   -> tick "masm(.targets, .props)". Then include this .asm in the
;   project's source list; it will build with ml64.exe automatically.
; =============================================================================

.CODE

; Externs match the C++ globals declared in DirectSyscall.cpp with
; extern "C" linkage. MASM syntax: EXTERN <symbol>:<type>.
EXTERN g_syscall_NtOpenProcess           : DWORD
EXTERN g_syscall_NtAllocateVirtualMemory : DWORD
EXTERN g_syscall_NtProtectVirtualMemory  : DWORD
EXTERN g_syscall_NtWriteVirtualMemory    : DWORD
EXTERN g_syscall_NtReadVirtualMemory     : DWORD
EXTERN g_syscall_NtCreateThreadEx        : DWORD


Direct_NtOpenProcess PROC
    mov     r10, rcx
    mov     eax, g_syscall_NtOpenProcess
    syscall
    ret
Direct_NtOpenProcess ENDP


Direct_NtAllocateVirtualMemory PROC
    mov     r10, rcx
    mov     eax, g_syscall_NtAllocateVirtualMemory
    syscall
    ret
Direct_NtAllocateVirtualMemory ENDP


Direct_NtProtectVirtualMemory PROC
    mov     r10, rcx
    mov     eax, g_syscall_NtProtectVirtualMemory
    syscall
    ret
Direct_NtProtectVirtualMemory ENDP


Direct_NtWriteVirtualMemory PROC
    mov     r10, rcx
    mov     eax, g_syscall_NtWriteVirtualMemory
    syscall
    ret
Direct_NtWriteVirtualMemory ENDP


Direct_NtReadVirtualMemory PROC
    mov     r10, rcx
    mov     eax, g_syscall_NtReadVirtualMemory
    syscall
    ret
Direct_NtReadVirtualMemory ENDP


Direct_NtCreateThreadEx PROC
    mov     r10, rcx
    mov     eax, g_syscall_NtCreateThreadEx
    syscall
    ret
Direct_NtCreateThreadEx ENDP


END
