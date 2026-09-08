# Hacker Disassembler Engine (HDE) 32 / 64

Author: Vyacheslav Patkov, 2006-2009.
Status: public domain (from author's original distribution).

## What this is

A minimal length disassembler for x86 (`hde32`) and x86-64 (`hde64`). Given a
pointer to bytes, `hdeXX_disasm` returns the length of the first instruction
and a decoded struct that names the ModR/M byte, SIB byte, immediate and
displacement fields, plus a flags word that says which of those are present
and whether the immediate is a relative branch operand.

`ProcessToolkit/src/HookInjection.cpp` uses this to (1) find the smallest
instruction-aligned prologue length that covers our JMP, and (2) classify
each preserved instruction's position-dependent operand so the trampoline
builder can relocate it. The rel8-refusal policy (do not hook prologues
containing short conditional or unconditional branches) lives in
HookInjection.cpp; hde is a decoder, not a policy engine.

## Provenance

Files fetched 2026-09-06 from Tsuda Kageyu's MinHook project, tag `v1.3.3`:
<https://github.com/TsudaKageyu/minhook/tree/v1.3.3/src/hde>

Raw URLs used, e.g.
<https://raw.githubusercontent.com/TsudaKageyu/minhook/v1.3.3/src/hde/hde64.h>

MinHook vendors the pristine Patkov distribution unchanged. The public
domain declaration stays in the top-of-file comment of every source and
header in this directory.

## Why this over rolling our own

The earlier `ProcessToolkit/src/LengthDisasm.cpp` (removed on 2026-09-06)
implemented the same interface in about 340 lines, restricted to the
instruction subset that appears in compiler-generated prologues. That was
fine for the study but weaker than a public-domain reference implementation
used by MinHook, EasyHook and every hook engine that vendors HDE. Swapping
to HDE keeps the fingerprint the classifier sees identical (the syscalls
that fire ETW-TI events do not care which decoder decided the prologue
length) while removing a bespoke module the thesis would otherwise have
to defend.

## Files

- `hde32.h`, `hde32.c`, `table32.h` — x86 decoder. `hde32.c` compiles to
  nothing on x64 builds thanks to `#if defined(_M_IX86) || defined(__i386__)`.
- `hde64.h`, `hde64.c`, `table64.h` — x64 decoder. Same trick, arch-gated
  the other way.
- `pstdint.h` — portable `<stdint.h>` shim. Redundant on modern MSVC, kept
  because the hde headers `#include "pstdint.h"` unconditionally.
