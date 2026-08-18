#include "HookInjection.h"

#include <TlHelp32.h>
#include <cstring>

#include "LengthDisasm.h"
#include "Memory.h"
#include "MemoryPatch.h"

namespace PT::HookInjection {

	namespace {

		// Trampoline region layout (one 4KB page in the target):
		//   [0x00] hit counter (uint64_t on x64, uint32_t on x86)
		//   [0x08..0x10] padding
		//   [0x10] shellcode start
		constexpr std::size_t TRAMPOLINE_SIZE  = 4096;
		constexpr std::size_t SHELLCODE_OFFSET = 0x10;
		constexpr std::size_t COUNTER_OFFSET   = 0x00;

		// How many prologue bytes to read for disassembly. Must be at least
		// large enough to cover HOOK_BYTES + one worst-case instruction (15).
		constexpr std::size_t PROLOGUE_READ_WINDOW = 32;

#ifdef _WIN64
		constexpr std::size_t HOOK_BYTES = 14;
		constexpr bool IS_X64 = true;
		// Bytes of counter-increment code that precede the preserved prologue
		// inside the shellcode. The prologue's first byte lands at
		// shellcode_addr + PROLOGUE_OFFSET_IN_SHELLCODE, which is what the
		// fixup delta must be computed against.
		constexpr std::size_t PROLOGUE_OFFSET_IN_SHELLCODE = 8;   // lock inc [rip+disp32]

		// Assemble the 14-byte absolute JMP that goes at target_function:
		//   FF 25 00 00 00 00       jmp qword ptr [rip + 0]
		//   XX XX XX XX XX XX XX XX <destination>
		std::vector<std::uint8_t> assemble_hook_jump(
			std::uintptr_t /*hook_source*/, std::uintptr_t destination)
		{
			std::vector<std::uint8_t> buf(HOOK_BYTES);
			buf[0] = 0xFF; buf[1] = 0x25;
			buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00;
			std::memcpy(&buf[6], &destination, sizeof(destination));
			return buf;
		}

		// x64 trampoline shellcode:
		//   F0 48 FF 05 <disp32>   lock inc qword ptr [rip + disp32]   (8 bytes)
		//   <preserved bytes>                                            (N bytes)
		//   FF 25 00 00 00 00      jmp qword ptr [rip + 0]              (6 bytes)
		//   <8 bytes return>                                             (8 bytes)
		//
		// Uses RIP-relative addressing for the counter and an absolute return
		// address for the trailing JMP so we don't clobber any GPRs.
		std::vector<std::uint8_t> build_shellcode(
			std::uintptr_t trampoline_base,
			const std::vector<std::uint8_t>& prologue,
			std::uintptr_t return_address)
		{
			const std::uintptr_t shellcode_addr = trampoline_base + SHELLCODE_OFFSET;
			const std::uintptr_t counter_addr   = trampoline_base + COUNTER_OFFSET;

			// [rip + disp32] resolves against the byte AFTER the instruction.
			const std::int64_t disp = static_cast<std::int64_t>(counter_addr) -
									  static_cast<std::int64_t>(shellcode_addr + 8);
			const std::int32_t disp32 = static_cast<std::int32_t>(disp);

			std::vector<std::uint8_t> code;
			code.reserve(8 + prologue.size() + 6 + 8);

			code.push_back(0xF0);  // lock
			code.push_back(0x48);  // REX.W
			code.push_back(0xFF);
			code.push_back(0x05);
			code.insert(code.end(),
						reinterpret_cast<const std::uint8_t*>(&disp32),
						reinterpret_cast<const std::uint8_t*>(&disp32) + 4);

			code.insert(code.end(), prologue.begin(), prologue.end());

			code.push_back(0xFF); code.push_back(0x25);
			code.push_back(0x00); code.push_back(0x00);
			code.push_back(0x00); code.push_back(0x00);

			code.insert(code.end(),
						reinterpret_cast<const std::uint8_t*>(&return_address),
						reinterpret_cast<const std::uint8_t*>(&return_address) + 8);

			return code;
		}

#else   // _WIN64

		constexpr std::size_t HOOK_BYTES = 5;
		constexpr bool IS_X64 = false;
		// See x64 comment above. On x86 the counter-increment is
		// `F0 FF 05 <abs32>` = 7 bytes.
		constexpr std::size_t PROLOGUE_OFFSET_IN_SHELLCODE = 7;

		// x86 5-byte relative JMP: `E9 <rel32>`.
		std::vector<std::uint8_t> assemble_hook_jump(
			std::uintptr_t source, std::uintptr_t destination)
		{
			std::vector<std::uint8_t> buf(HOOK_BYTES);
			buf[0] = 0xE9;
			const std::int32_t rel32 = static_cast<std::int32_t>(
				static_cast<std::int64_t>(destination) -
				static_cast<std::int64_t>(source + 5));
			std::memcpy(&buf[1], &rel32, sizeof(rel32));
			return buf;
		}

		// x86 trampoline shellcode:
		//   F0 FF 05 <abs32>   lock inc dword ptr [counter]         (7 bytes)
		//   <preserved bytes>                                        (N bytes)
		//   E9 <rel32>         jmp <return_address>                  (5 bytes)
		std::vector<std::uint8_t> build_shellcode(
			std::uintptr_t trampoline_base,
			const std::vector<std::uint8_t>& prologue,
			std::uintptr_t return_address)
		{
			const std::uintptr_t shellcode_addr = trampoline_base + SHELLCODE_OFFSET;
			const std::uintptr_t counter_addr   = trampoline_base + COUNTER_OFFSET;

			std::vector<std::uint8_t> code;
			code.reserve(7 + prologue.size() + 5);

			code.push_back(0xF0);
			code.push_back(0xFF);
			code.push_back(0x05);
			const std::uint32_t addr32 = static_cast<std::uint32_t>(counter_addr);
			code.insert(code.end(),
						reinterpret_cast<const std::uint8_t*>(&addr32),
						reinterpret_cast<const std::uint8_t*>(&addr32) + 4);

			code.insert(code.end(), prologue.begin(), prologue.end());

			// Relative JMP back. Instruction sits at shellcode + 7 + prologue.
			const std::uintptr_t jmp_source = shellcode_addr + 7 + prologue.size();
			code.push_back(0xE9);
			const std::int32_t rel32 = static_cast<std::int32_t>(
				static_cast<std::int64_t>(return_address) -
				static_cast<std::int64_t>(jmp_source + 5));
			code.insert(code.end(),
						reinterpret_cast<const std::uint8_t*>(&rel32),
						reinterpret_cast<const std::uint8_t*>(&rel32) + 4);

			return code;
		}

#endif  // _WIN64

		// Apply position-dependent-operand fixups to a prologue that has been
		// copied from `src_base` to `dst_base` (both are absolute VAs in the
		// TARGET process — the shellcode runs there, not in the attacker).
		// Each fixup's operand is a 32-bit signed relative offset from the
		// address of the byte AFTER the operand back to the target it names;
		// relocating the containing instruction by `delta` bytes means the
		// operand must be adjusted by `-delta` to keep pointing at the same
		// absolute target.
		void apply_fixups(
			std::vector<std::uint8_t>& prologue,
			const std::vector<PT::LengthDisasm::Fixup>& fixups,
			std::uintptr_t src_base,
			std::uintptr_t dst_base)
		{
			const std::int64_t delta =
				static_cast<std::int64_t>(dst_base) - static_cast<std::int64_t>(src_base);
			for (const auto& fx : fixups) {
				if (fx.kind == PT::LengthDisasm::RipRel::None ||
					fx.kind == PT::LengthDisasm::RipRel::ShortRel8) {
					continue;   // ShortRel8 should have been rejected earlier
				}
				if (fx.operand_offset + 4 > prologue.size()) continue;
				std::int32_t operand;
				std::memcpy(&operand, prologue.data() + fx.operand_offset, sizeof(operand));
				const std::int64_t adjusted =
					static_cast<std::int64_t>(operand) - delta;
				const std::int32_t new_operand = static_cast<std::int32_t>(adjusted);
				std::memcpy(prologue.data() + fx.operand_offset, &new_operand, sizeof(new_operand));
			}
		}

		// Allocate `size` bytes of RWX memory in the target within ±2GB of
		// `near_va` — the range within which x64 RIP-relative disp32 operands
		// can still address the same absolute targets after being copied into
		// the trampoline. Scans free regions with VirtualQueryEx and asks
		// VirtualAllocEx for a specific base; returns nullopt if no free region
		// large enough exists in that window.
		//
		// x86 code paths ignore this (no RIP-relative addressing to preserve)
		// and can fall back to a plain VirtualAllocEx with no hint.
		std::optional<std::uintptr_t> allocate_nearby_rwx(
			const WinHandle& process,
			std::uintptr_t near_va,
			std::size_t size)
		{
			constexpr std::uintptr_t GRANULARITY  = 0x10000;             // 64 KB
			constexpr std::uintptr_t MAX_DISTANCE = 0x7FFF0000ULL;       // ~2 GB safety margin
			const std::uintptr_t low  = (near_va > MAX_DISTANCE)
				? ((near_va - MAX_DISTANCE) & ~(GRANULARITY - 1))
				: 0;
			const std::uintptr_t high = near_va + MAX_DISTANCE;

			std::uintptr_t cursor = low;
			while (cursor < high) {
				MEMORY_BASIC_INFORMATION mbi{};
				if (!VirtualQueryEx(process.get(),
									reinterpret_cast<LPCVOID>(cursor),
									&mbi, sizeof(mbi))) {
					break;
				}
				const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
				const auto region_end  = region_base + mbi.RegionSize;

				if (mbi.State == MEM_FREE) {
					// Align UP to allocation granularity within the free region.
					std::uintptr_t candidate =
						(region_base + GRANULARITY - 1) & ~(GRANULARITY - 1);
					while (candidate + size <= region_end && candidate < high) {
						LPVOID got = VirtualAllocEx(
							process.get(),
							reinterpret_cast<LPVOID>(candidate),
							size,
							MEM_COMMIT | MEM_RESERVE,
							PAGE_EXECUTE_READWRITE);
						if (got) {
							return reinterpret_cast<std::uintptr_t>(got);
						}
						candidate += GRANULARITY;
					}
				}

				// Advance past this region (avoid infinite loop on zero size).
				cursor = (mbi.RegionSize > 0) ? region_end : (cursor + GRANULARITY);
			}
			return std::nullopt;
		}

		// RAII helper: snapshot all threads in `target_pid`, suspend each with
		// SuspendThread, and resume them all on destruction. Ensures no target
		// thread is executing inside the .text region during our write.
		class TargetThreadSuspender {
		public:
			explicit TargetThreadSuspender(DWORD target_pid) : ok_(false) {
				if (target_pid == 0) return;
				HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
				if (snap == INVALID_HANDLE_VALUE) return;
				THREADENTRY32 te{};
				te.dwSize = sizeof(te);
				if (Thread32First(snap, &te)) {
					do {
						if (te.th32OwnerProcessID != target_pid) continue;
						const DWORD access = THREAD_SUSPEND_RESUME;
						HANDLE th = OpenThread(access, FALSE, te.th32ThreadID);
						if (!th) continue;
						if (SuspendThread(th) == static_cast<DWORD>(-1)) {
							CloseHandle(th);
							continue;
						}
						handles_.push_back(th);
					} while (Thread32Next(snap, &te));
				}
				CloseHandle(snap);
				ok_ = true;
			}

			~TargetThreadSuspender() {
				for (HANDLE th : handles_) {
					ResumeThread(th);
					CloseHandle(th);
				}
			}

			TargetThreadSuspender(const TargetThreadSuspender&) = delete;
			TargetThreadSuspender& operator=(const TargetThreadSuspender&) = delete;

			bool ok() const { return ok_; }
			std::size_t count() const { return handles_.size(); }

		private:
			std::vector<HANDLE> handles_;
			bool ok_;
		};

	}  // anonymous namespace

	std::optional<HookOutcome> install_inline_hook(
		const WinHandle& process,
		std::uintptr_t target_function,
		std::size_t preserve_bytes_hint)
	{
		if (!process || target_function == 0) {
			return std::nullopt;
		}

		// 1. Read a generous window of the prologue for disassembly. If the
		//    caller passed a hint that's larger, honor it — we still need at
		//    least that many bytes buffered for fixup analysis.
		//    (Not using std::max: Windows.h leaks `max` as a macro under the
		//    default MSVC configuration.)
		const std::size_t hint_window = preserve_bytes_hint + HOOK_BYTES;
		const std::size_t read_size =
			(PROLOGUE_READ_WINDOW > hint_window) ? PROLOGUE_READ_WINDOW : hint_window;
		auto probe = PT::MemoryPatch::read_bytes(process, target_function, read_size);
		if (!probe) return std::nullopt;

		// 2. Decide preserve_bytes: use the hint if given (>= HOOK_BYTES), else
		//    walk the disassembler to find the smallest aligned length that
		//    fits our JMP.
		std::size_t preserved = 0;
		if (preserve_bytes_hint >= HOOK_BYTES) {
			preserved = preserve_bytes_hint;
		} else {
			auto auto_len = PT::LengthDisasm::aligned_length_at_least(
				*probe, HOOK_BYTES, IS_X64);
			if (!auto_len) return std::nullopt;   // undecodable prologue
			preserved = *auto_len;
		}
		if (preserved > probe->size()) return std::nullopt;

		// 3. Walk the preserved region collecting position-dependent-operand
		//    fixups; reject if we find something we cannot safely relocate
		//    (short rel8 branches — rel8 fixups may overflow after relocation).
		auto fixups = PT::LengthDisasm::collect_fixups(*probe, preserved, IS_X64);
		if (!fixups) return std::nullopt;
		for (const auto& fx : *fixups) {
			if (fx.kind == PT::LengthDisasm::RipRel::ShortRel8) {
				return std::nullopt;
			}
		}

		// 4. Allocate the trampoline page (RWX) in the target. For x64, place
		//    it within ±2GB of target_function so RIP-relative disp32 operands
		//    in the preserved prologue still fit after being relocated into
		//    the trampoline. x86 has no such constraint.
		std::optional<std::uintptr_t> trampoline_base;
#ifdef _WIN64
		trampoline_base = allocate_nearby_rwx(process, target_function, TRAMPOLINE_SIZE);
#endif
		if (!trampoline_base) {
			trampoline_base = PT::Memory::allocate_memory(
				process, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}
		if (!trampoline_base) return std::nullopt;

		// 5. Copy the preserved bytes locally and apply any fixups so the
		//    RIP-relative / CALL-rel32 / JMP-rel32 operands still point at the
		//    same absolute target after the instruction moves into the trampoline.
		//    The preserved prologue lands at shellcode_addr + PROLOGUE_OFFSET
		//    (after the counter-increment prefix) — this is the address the
		//    delta must be computed against, NOT the raw shellcode base.
		std::vector<std::uint8_t> preserved_bytes(
			probe->begin(), probe->begin() + preserved);
		const std::uintptr_t prologue_dst_base =
			*trampoline_base + SHELLCODE_OFFSET + PROLOGUE_OFFSET_IN_SHELLCODE;
		apply_fixups(preserved_bytes, *fixups,
					 target_function, prologue_dst_base);

		// 6. Assemble the trampoline buffer: [counter=0][padding][shellcode].
		std::vector<std::uint8_t> trampoline_buffer(TRAMPOLINE_SIZE, 0);
		const auto shellcode = build_shellcode(
			*trampoline_base, preserved_bytes, target_function + preserved);
		if (SHELLCODE_OFFSET + shellcode.size() > TRAMPOLINE_SIZE) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}
		std::memcpy(trampoline_buffer.data() + SHELLCODE_OFFSET,
					shellcode.data(), shellcode.size());

		// 7. Write the full trampoline buffer into the allocated page.
		if (!PT::Memory::write_memory(
				process, *trampoline_base,
				trampoline_buffer.data(), trampoline_buffer.size())) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}

		// 8. Build the detour bytes: JMP + NOP padding to reach `preserved`.
		auto detour = assemble_hook_jump(
			target_function, *trampoline_base + SHELLCODE_OFFSET);
		const std::size_t nop_padding = preserved - HOOK_BYTES;
		detour.insert(detour.end(), nop_padding, static_cast<std::uint8_t>(0x90));

		// 9. Suspend every target thread during the .text overwrite so no
		//    thread is mid-execution inside the region we're about to modify.
		//    Best-effort: OpenThread may fail for threads we can't touch
		//    (system/protected); that's acceptable — a race with such a thread
		//    is astronomically unlikely inside a 15-byte prologue window.
		const DWORD target_pid = GetProcessId(process.get());
		TargetThreadSuspender suspender(target_pid);

		// 10. Flip .text at target_function to RWX, write detour, restore.
		auto patch_outcome = PT::MemoryPatch::patch_bytes(
			process, target_function, detour, /*change_protection=*/true);
		if (!patch_outcome) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}
		// Threads resume on suspender destruction (below).

		return HookOutcome{
			.target_function     = target_function,
			.trampoline_base     = *trampoline_base,
			.hook_bytes_size     = HOOK_BYTES,
			.preserved_bytes     = preserved,
			.previous_protection = patch_outcome->previous_protection,
			.protection_restored = patch_outcome->protection_restored,
			.original_prologue   = std::vector<std::uint8_t>(
				probe->begin(), probe->begin() + preserved),
		};
	}

	std::optional<std::uint64_t> read_hit_counter(
		const WinHandle& process,
		std::uintptr_t trampoline_base)
	{
		if (!process || trampoline_base == 0) {
			return std::nullopt;
		}

#ifdef _WIN64
		std::uint64_t counter = 0;
		if (!PT::Memory::read_trivial_memory(process, trampoline_base + COUNTER_OFFSET, counter)) {
			return std::nullopt;
		}
		return counter;
#else
		std::uint32_t counter = 0;
		if (!PT::Memory::read_trivial_memory(process, trampoline_base + COUNTER_OFFSET, counter)) {
			return std::nullopt;
		}
		return static_cast<std::uint64_t>(counter);
#endif
	}

}  // namespace PT::HookInjection
