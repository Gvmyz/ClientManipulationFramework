#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Minimal x86/x64 length-disassembler used by HookInjection to identify safe
// instruction boundaries in a target function's prologue and to detect
// operands that must be fixed up when the bytes are copied to a trampoline
// at a different virtual address.
//
// Covers the instruction subset that appears in typical compiler-generated
// prologues (register moves, push/pop, sub rsp, lea, mov, imul, jumps and
// calls, common two-byte 0F XX forms). Unrecognized encodings return
// nullopt so callers can refuse to hook rather than silently corrupt.
//
// The disassembler is NOT a full x86/x64 decoder — it deliberately trades
// completeness for a small, auditable implementation. Prologue coverage in
// real MSVC/MinGW Release binaries is high; SIMD / VEX / EVEX instructions
// are outside its scope and should never appear in the leading bytes of a
// standard function anyway.
namespace PT::LengthDisasm {

	// Classifies the kind of position-dependent operand an instruction carries,
	// if any. Used by the trampoline builder to relocate the operand's value
	// when the instruction is copied to a new address.
	enum class RipRel {
		None,             // no position-dependent operand
		ModrmRipDisp32,   // x64 only: ModR/M encodes [rip + disp32]
		CallJmpRel32,     // CALL rel32 or JMP rel32 (both x86 and x64)
		JccRel32,         // conditional jump long form (0F 80..8F rel32)
		ShortRel8,        // JMP rel8 or Jcc rel8 — refuse to hook (rel8 fixups
		                  // may not fit after relocation)
	};

	struct Instruction {
		std::size_t length;         // total instruction length in bytes
		RipRel rip_rel_kind;        // position-dependent operand classification
		std::size_t rip_disp_offset; // byte offset of the operand within the
		                             // instruction, valid iff rip_rel_kind != None
	};

	// Decode the instruction at bytes[0..limit). Returns nullopt on unrecognized
	// encoding or if the instruction extends past `limit`.
	//
	// is_x64: true → REX prefix acknowledged and ModR/M mod=00 rm=101 decoded as
	// [rip+disp32] (RipRel::ModrmRipDisp32). false → same encoding is [disp32]
	// absolute in x86 and needs no relocation (RipRel::None).
	std::optional<Instruction> decode(
		const std::uint8_t* bytes,
		std::size_t limit,
		bool is_x64
	);

	// Walk the buffer instruction by instruction to find the smallest cumulative
	// length that is at least min_size AND falls on an instruction boundary.
	// Returns nullopt if any instruction in the walk is undecodable, or if
	// min_size cannot be reached within `bytes.size()`.
	//
	// Used to pick preserve_bytes for the inline-hook trampoline: the caller
	// wants "at least HOOK_JMP_LENGTH bytes, aligned so the last preserved
	// instruction is not cut".
	std::optional<std::size_t> aligned_length_at_least(
		const std::vector<std::uint8_t>& bytes,
		std::size_t min_size,
		bool is_x64
	);

	// Walk the buffer up to `preserved_bytes` and collect every position-dependent
	// operand's (kind, offset-from-start, instruction-length). Returns nullopt if
	// any instruction is undecodable. Empty vector means "safe to copy verbatim".
	struct Fixup {
		RipRel kind;
		std::size_t operand_offset;    // where the disp/rel value lives in `bytes`
		std::size_t instr_offset;      // where the instruction begins in `bytes`
		std::size_t instr_length;      // total length of that instruction
	};

	std::optional<std::vector<Fixup>> collect_fixups(
		const std::vector<std::uint8_t>& bytes,
		std::size_t preserved_bytes,
		bool is_x64
	);

}  // namespace PT::LengthDisasm
