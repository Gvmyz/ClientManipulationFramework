#include "LengthDisasm.h"

namespace PT::LengthDisasm {

	namespace {

		// Sentinel for unknown opcodes — 0xFF is larger than any real immediate.
		constexpr std::uint8_t IMM_UNKNOWN = 0xFF;

		struct OpcodeAttr {
			bool has_modrm;
			std::uint8_t imm_size;   // 0, 1, 2, 4, or IMM_UNKNOWN
		};
		constexpr OpcodeAttr UNKNOWN{false, IMM_UNKNOWN};

		// Primary (single-byte) opcode attribute lookup. Covers the subset
		// commonly emitted by MSVC/MinGW/gcc in function prologues.
		OpcodeAttr lookup_primary(std::uint8_t op) {
			switch (op) {
			// ALU (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP) with ModR/M — no imm
			case 0x00: case 0x01: case 0x02: case 0x03:
			case 0x08: case 0x09: case 0x0A: case 0x0B:
			case 0x10: case 0x11: case 0x12: case 0x13:
			case 0x18: case 0x19: case 0x1A: case 0x1B:
			case 0x20: case 0x21: case 0x22: case 0x23:
			case 0x28: case 0x29: case 0x2A: case 0x2B:
			case 0x30: case 0x31: case 0x32: case 0x33:
			case 0x38: case 0x39: case 0x3A: case 0x3B:
				return {true, 0};

			// PUSH/POP r64 (or r32 on x86) — 1-byte, no imm/modrm
			case 0x50: case 0x51: case 0x52: case 0x53:
			case 0x54: case 0x55: case 0x56: case 0x57:
			case 0x58: case 0x59: case 0x5A: case 0x5B:
			case 0x5C: case 0x5D: case 0x5E: case 0x5F:
				return {false, 0};

			case 0x68: return {false, 4};   // PUSH imm32
			case 0x6A: return {false, 1};   // PUSH imm8
			case 0x69: return {true, 4};    // IMUL r, r/m, imm32
			case 0x6B: return {true, 1};    // IMUL r, r/m, imm8

			// Short conditional jumps 0x70..0x7F — 1 byte rel8. Refuse to hook
			// prologues containing these; caller sees RipRel::ShortRel8 and
			// declines.
			case 0x70: case 0x71: case 0x72: case 0x73:
			case 0x74: case 0x75: case 0x76: case 0x77:
			case 0x78: case 0x79: case 0x7A: case 0x7B:
			case 0x7C: case 0x7D: case 0x7E: case 0x7F:
				return {false, 1};

			// ALU-imm group  (80 = imm8, 81 = imm32, 83 = imm8-sign-extended)
			case 0x80: return {true, 1};
			case 0x81: return {true, 4};
			case 0x83: return {true, 1};

			// TEST / XCHG / MOV / LEA / POP r/m — all have ModR/M, no imm
			case 0x84: case 0x85: case 0x86: case 0x87:
			case 0x88: case 0x89: case 0x8A: case 0x8B:
			case 0x8D:
			case 0x8F:
				return {true, 0};

			// NOP, CBW/CWDE/CDQE, CWD/CDQ, PUSHF, POPF, SAHF, LAHF
			case 0x90:
			case 0x91: case 0x92: case 0x93: case 0x94:
			case 0x95: case 0x96: case 0x97:
			case 0x98: case 0x99:
			case 0x9C: case 0x9D: case 0x9E: case 0x9F:
				return {false, 0};

			// MOV imm to reg (byte / word/dword/qword)
			case 0xB0: case 0xB1: case 0xB2: case 0xB3:
			case 0xB4: case 0xB5: case 0xB6: case 0xB7:
				return {false, 1};
			case 0xB8: case 0xB9: case 0xBA: case 0xBB:
			case 0xBC: case 0xBD: case 0xBE: case 0xBF:
				// Overridden to 8 by REX.W in decode() below.
				return {false, 4};

			// Shift group 2 (C0 imm8, C1 imm8)
			case 0xC0: case 0xC1: return {true, 1};
			case 0xC2: return {false, 2};   // RET imm16
			case 0xC3: return {false, 0};   // RET
			case 0xC6: return {true, 1};    // MOV r/m8, imm8
			case 0xC7: return {true, 4};    // MOV r/m32, imm32
			case 0xC9: return {false, 0};   // LEAVE
			case 0xCC: return {false, 0};   // INT3

			// Shift group 2 (D0/D1 no imm, D2/D3 no imm — count in CL)
			case 0xD0: case 0xD1: case 0xD2: case 0xD3:
				return {true, 0};

			// CALL rel32 / JMP rel32 / JMP rel8
			case 0xE8: case 0xE9: return {false, 4};
			case 0xEB:            return {false, 1};

			// F6/F7 group — /0 and /1 sub-ops carry an extra imm; caller checks
			// modrm.reg to decide and adjusts imm_size accordingly.
			case 0xF6: return {true, 0};
			case 0xF7: return {true, 0};

			// FE / FF group (INC/DEC/CALL/JMP/PUSH via ModR/M)
			case 0xFE: return {true, 0};
			case 0xFF: return {true, 0};

			// A8/A9: TEST AL/AX, imm — no ModR/M
			case 0xA8: return {false, 1};
			case 0xA9: return {false, 4};

			default:
				return UNKNOWN;
			}
		}

		// Two-byte opcode attribute lookup (following a 0x0F prefix).
		// Only handles the two-byte forms that plausibly appear in prologues:
		// long conditional jumps, SETcc, IMUL r,r/m, MOVSX/MOVZX, bit tests.
		OpcodeAttr lookup_two_byte(std::uint8_t op) {
			switch (op) {
			// Long conditional jumps 0x0F 80..8F — 4-byte rel32
			case 0x80: case 0x81: case 0x82: case 0x83:
			case 0x84: case 0x85: case 0x86: case 0x87:
			case 0x88: case 0x89: case 0x8A: case 0x8B:
			case 0x8C: case 0x8D: case 0x8E: case 0x8F:
				return {false, 4};

			// SETcc — ModR/M, no imm
			case 0x90: case 0x91: case 0x92: case 0x93:
			case 0x94: case 0x95: case 0x96: case 0x97:
			case 0x98: case 0x99: case 0x9A: case 0x9B:
			case 0x9C: case 0x9D: case 0x9E: case 0x9F:
				return {true, 0};

			// IMUL r, r/m
			case 0xAF: return {true, 0};

			// MOVSX / MOVZX
			case 0xB6: case 0xB7: case 0xBE: case 0xBF:
				return {true, 0};

			// BT / BTS / BTR / BTC
			case 0xA3: case 0xAB: case 0xB3: case 0xBB:
				return {true, 0};

			// BTx imm8 forms — 0F BA has ModR/M + imm8
			case 0xBA: return {true, 1};

			// CMOVcc 0x0F 40..4F — ModR/M
			case 0x40: case 0x41: case 0x42: case 0x43:
			case 0x44: case 0x45: case 0x46: case 0x47:
			case 0x48: case 0x49: case 0x4A: case 0x4B:
			case 0x4C: case 0x4D: case 0x4E: case 0x4F:
				return {true, 0};

			// XADD  0x0F C0/C1 — ModR/M
			case 0xC0: case 0xC1: return {true, 0};

			default:
				return UNKNOWN;
			}
		}

	}  // anonymous namespace

	std::optional<Instruction> decode(
		const std::uint8_t* bytes, std::size_t limit, bool is_x64)
	{
		if (!bytes || limit == 0) {
			return std::nullopt;
		}

		std::size_t off = 0;
		bool rex_w = false;

		// Legacy prefixes (up to 4, though rarely more than 1-2 in practice).
		for (int i = 0; i < 4 && off < limit; ++i) {
			const std::uint8_t b = bytes[off];
			const bool is_prefix =
				b == 0xF0 || b == 0xF2 || b == 0xF3 ||
				b == 0x66 || b == 0x67 ||
				b == 0x2E || b == 0x3E || b == 0x26 ||
				b == 0x64 || b == 0x65 || b == 0x36;
			if (!is_prefix) break;
			++off;
		}

		if (off >= limit) return std::nullopt;

		// REX prefix (x64 only).
		if (is_x64 && (bytes[off] & 0xF0) == 0x40) {
			rex_w = (bytes[off] & 0x08) != 0;
			++off;
		}

		if (off >= limit) return std::nullopt;

		// Primary opcode (may be one or two bytes; 0x0F introduces a two-byte
		// opcode).
		const std::uint8_t primary_op = bytes[off];
		++off;

		OpcodeAttr attr;
		bool is_two_byte = false;
		std::uint8_t secondary_op = 0;
		if (primary_op == 0x0F) {
			if (off >= limit) return std::nullopt;
			secondary_op = bytes[off];
			++off;
			attr = lookup_two_byte(secondary_op);
			is_two_byte = true;
		} else {
			attr = lookup_primary(primary_op);
		}

		if (attr.imm_size == IMM_UNKNOWN) {
			return std::nullopt;   // unhandled opcode
		}

		// REX.W promotes B8..BF's imm32 to imm64.
		if (rex_w && !is_two_byte && primary_op >= 0xB8 && primary_op <= 0xBF) {
			attr.imm_size = 8;
		}

		// F6/F7 special: /0 and /1 (TEST r/m, imm) carry an extra immediate.
		if (!is_two_byte && (primary_op == 0xF6 || primary_op == 0xF7) && attr.has_modrm) {
			if (off >= limit) return std::nullopt;
			const std::uint8_t modrm_peek = bytes[off];
			const std::uint8_t reg = (modrm_peek >> 3) & 0x7;
			if (reg == 0 || reg == 1) {
				attr.imm_size = (primary_op == 0xF6) ? 1 : 4;
			}
		}

		Instruction result{0, RipRel::None, 0};

		if (attr.has_modrm) {
			if (off >= limit) return std::nullopt;
			const std::uint8_t modrm = bytes[off];
			++off;
			const std::uint8_t mod = (modrm >> 6) & 0x3;
			const std::uint8_t rm  = modrm & 0x7;

			bool has_sib = false;
			std::size_t disp_size = 0;

			if (mod != 0x3) {
				has_sib = (rm == 0x4);
				if (has_sib) {
					if (off >= limit) return std::nullopt;
					const std::uint8_t sib = bytes[off];
					++off;
					const std::uint8_t base = sib & 0x7;
					if (mod == 0x0 && base == 0x5) {
						disp_size = 4;
					}
				} else if (mod == 0x0 && rm == 0x5) {
					// No SIB, mod=00, rm=101.
					// x64 → [rip + disp32]; x86 → [disp32] (absolute, no fixup).
					disp_size = 4;
					if (is_x64) {
						result.rip_rel_kind = RipRel::ModrmRipDisp32;
						result.rip_disp_offset = off;   // disp32 starts here
					}
				}
			}

			if (mod == 0x1) disp_size = 1;
			else if (mod == 0x2) disp_size = 4;
			// mod=0 handled above; mod=3 is register-to-register, no disp.

			if (off + disp_size > limit) return std::nullopt;
			off += disp_size;
		}

		// Position-dependent operand for CALL rel32 / JMP rel32 / JMP rel8 /
		// Jcc rel8 / Jcc rel32. Recorded so the trampoline builder can patch
		// or refuse.
		if (!is_two_byte) {
			if (primary_op == 0xE8 || primary_op == 0xE9) {
				result.rip_rel_kind = RipRel::CallJmpRel32;
				result.rip_disp_offset = off;
			} else if (primary_op == 0xEB) {
				result.rip_rel_kind = RipRel::ShortRel8;
				result.rip_disp_offset = off;
			} else if (primary_op >= 0x70 && primary_op <= 0x7F) {
				result.rip_rel_kind = RipRel::ShortRel8;
				result.rip_disp_offset = off;
			}
		} else if (secondary_op >= 0x80 && secondary_op <= 0x8F) {
			result.rip_rel_kind = RipRel::JccRel32;
			result.rip_disp_offset = off;
		}

		if (off + attr.imm_size > limit) return std::nullopt;
		off += attr.imm_size;

		result.length = off;
		return result;
	}

	std::optional<std::size_t> aligned_length_at_least(
		const std::vector<std::uint8_t>& bytes,
		std::size_t min_size,
		bool is_x64)
	{
		std::size_t cursor = 0;
		while (cursor < bytes.size()) {
			auto ins = decode(bytes.data() + cursor, bytes.size() - cursor, is_x64);
			if (!ins) return std::nullopt;
			cursor += ins->length;
			if (cursor >= min_size) return cursor;
		}
		return std::nullopt;   // reached end without hitting min_size
	}

	std::optional<std::vector<Fixup>> collect_fixups(
		const std::vector<std::uint8_t>& bytes,
		std::size_t preserved_bytes,
		bool is_x64)
	{
		std::vector<Fixup> fixups;
		std::size_t cursor = 0;
		while (cursor < preserved_bytes && cursor < bytes.size()) {
			auto ins = decode(bytes.data() + cursor, bytes.size() - cursor, is_x64);
			if (!ins) return std::nullopt;
			if (ins->rip_rel_kind != RipRel::None) {
				fixups.push_back(Fixup{
					.kind = ins->rip_rel_kind,
					.operand_offset = cursor + ins->rip_disp_offset,
					.instr_offset = cursor,
					.instr_length = ins->length,
				});
			}
			cursor += ins->length;
		}
		return fixups;
	}

}  // namespace PT::LengthDisasm
