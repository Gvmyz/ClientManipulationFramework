#include "IatHook.h"

#include <Psapi.h>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#include "Memory.h"
#include "MemoryPatch.h"

namespace PT::IatHook {

	namespace {

		// Trampoline layout (one 4KB page in the target):
		//   [0x00] hit counter (uint64_t x64, uint32_t x86)
		//   [0x10] shellcode start
		//   [0x40] absolute pointer to the original import target (used by the
		//          trailing `jmp [orig_ptr]` — kept in a separate slot so the
		//          shellcode never needs to touch a GPR to hold it)
		constexpr std::size_t TRAMPOLINE_SIZE  = 4096;
		constexpr std::size_t COUNTER_OFFSET   = 0x00;
		constexpr std::size_t SHELLCODE_OFFSET = 0x10;
		constexpr std::size_t ORIG_PTR_OFFSET  = 0x40;

#ifdef _WIN64
		constexpr std::size_t SLOT_SIZE = 8;
#else
		constexpr std::size_t SLOT_SIZE = 4;
#endif

		// Read a null-terminated ASCII string from the target. Bounded so a
		// broken IAT walk (following a garbage RVA) cannot infinite-loop us.
		std::optional<std::string> read_ascii_c_string(
			const WinHandle& process, std::uintptr_t addr, std::size_t max_len = 256)
		{
			std::string result;
			result.reserve(32);
			std::uint8_t byte;
			for (std::size_t i = 0; i < max_len; ++i) {
				if (!PT::Memory::read_trivial_memory(process, addr + i, byte)) return std::nullopt;
				if (byte == 0) return result;
				result.push_back(static_cast<char>(byte));
			}
			return std::nullopt;
		}

		bool ci_equal(std::string_view a, std::string_view b) {
			if (a.size() != b.size()) return false;
			for (std::size_t i = 0; i < a.size(); ++i) {
				const auto ca = static_cast<unsigned char>(a[i]);
				const auto cb = static_cast<unsigned char>(b[i]);
				if (std::tolower(ca) != std::tolower(cb)) return false;
			}
			return true;
		}

		std::string wide_to_narrow_ascii(std::wstring_view w) {
			std::string out;
			out.reserve(w.size());
			for (wchar_t ch : w) {
				out.push_back((ch > 0 && ch <= 0x7F) ? static_cast<char>(ch) : '?');
			}
			return out;
		}

		struct IatSlot {
			std::uintptr_t slot_va;
			std::uintptr_t original_target;
		};

		// Walk `image_base`'s import descriptor table and return the IAT
		// slot + current pointer for the (dll_name_wanted, fn_name_wanted)
		// pair, or nullopt if the target does not import that function.
		std::optional<IatSlot> find_iat_slot(
			const WinHandle& process,
			std::uintptr_t image_base,
			std::string_view dll_name_wanted,
			std::string_view fn_name_wanted)
		{
			IMAGE_DOS_HEADER dos{};
			if (!PT::Memory::read_trivial_memory(process, image_base, dos)) return std::nullopt;
			if (dos.e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

			const std::uintptr_t nt_addr = image_base + static_cast<std::uintptr_t>(dos.e_lfanew);

#ifdef _WIN64
			IMAGE_NT_HEADERS64 nt{};
#else
			IMAGE_NT_HEADERS32 nt{};
#endif
			if (!PT::Memory::read_trivial_memory(process, nt_addr, nt)) return std::nullopt;
			if (nt.Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

			const auto& imp_dir =
				nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) return std::nullopt;

			const std::uintptr_t imp_desc_base = image_base + imp_dir.VirtualAddress;

			for (std::size_t i = 0; ; ++i) {
				IMAGE_IMPORT_DESCRIPTOR desc{};
				const std::uintptr_t desc_va =
					imp_desc_base + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
				if (!PT::Memory::read_trivial_memory(process, desc_va, desc)) return std::nullopt;
				// A zero-filled descriptor terminates the array.
				if (desc.Name == 0 && desc.FirstThunk == 0) break;

				auto dll_name = read_ascii_c_string(process, image_base + desc.Name);
				if (!dll_name) continue;
				if (!ci_equal(*dll_name, dll_name_wanted)) continue;

				// Walk the INT (OriginalFirstThunk) parallel with the IAT
				// (FirstThunk). The INT tells us the imported name; the IAT
				// holds the resolved pointer we want to overwrite. A bound
				// import descriptor has OriginalFirstThunk == 0 — in that
				// case walking the IAT for the *name* is impossible, so we
				// return nullopt for that DLL.
				if (desc.OriginalFirstThunk == 0) continue;
				const std::uintptr_t int_base = image_base + desc.OriginalFirstThunk;
				const std::uintptr_t iat_base = image_base + desc.FirstThunk;

				for (std::size_t j = 0; ; ++j) {
#ifdef _WIN64
					IMAGE_THUNK_DATA64 thunk{};
					const std::uintptr_t int_slot_va =
						int_base + j * sizeof(IMAGE_THUNK_DATA64);
					if (!PT::Memory::read_trivial_memory(process, int_slot_va, thunk)) return std::nullopt;
					if (thunk.u1.AddressOfData == 0) break;   // end of thunk list
					if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;   // ordinal import, skip

					const std::uintptr_t name_va =
						image_base + thunk.u1.AddressOfData + sizeof(WORD);   // skip Hint
					auto fn_name = read_ascii_c_string(process, name_va);
					if (!fn_name) continue;
					if (!ci_equal(*fn_name, fn_name_wanted)) continue;

					const std::uintptr_t slot_va =
						iat_base + j * sizeof(IMAGE_THUNK_DATA64);
					std::uint64_t original = 0;
					if (!PT::Memory::read_trivial_memory(process, slot_va, original)) return std::nullopt;
					return IatSlot{slot_va, static_cast<std::uintptr_t>(original)};
#else
					IMAGE_THUNK_DATA32 thunk{};
					const std::uintptr_t int_slot_va =
						int_base + j * sizeof(IMAGE_THUNK_DATA32);
					if (!PT::Memory::read_trivial_memory(process, int_slot_va, thunk)) return std::nullopt;
					if (thunk.u1.AddressOfData == 0) break;
					if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG32) continue;

					const std::uintptr_t name_va =
						image_base + thunk.u1.AddressOfData + sizeof(WORD);
					auto fn_name = read_ascii_c_string(process, name_va);
					if (!fn_name) continue;
					if (!ci_equal(*fn_name, fn_name_wanted)) continue;

					const std::uintptr_t slot_va =
						iat_base + j * sizeof(IMAGE_THUNK_DATA32);
					std::uint32_t original = 0;
					if (!PT::Memory::read_trivial_memory(process, slot_va, original)) return std::nullopt;
					return IatSlot{slot_va, static_cast<std::uintptr_t>(original)};
#endif
				}
			}
			return std::nullopt;
		}

		// Build the trampoline buffer. Layout is fixed regardless of arch, only
		// the shellcode differs. All addresses are absolute VAs in the target.
		std::vector<std::uint8_t> build_trampoline(
			std::uintptr_t trampoline_base,
			std::uintptr_t original_target)
		{
			std::vector<std::uint8_t> buf(TRAMPOLINE_SIZE, 0);

			const std::uintptr_t counter_va   = trampoline_base + COUNTER_OFFSET;
			const std::uintptr_t shellcode_va = trampoline_base + SHELLCODE_OFFSET;
			const std::uintptr_t orig_ptr_va  = trampoline_base + ORIG_PTR_OFFSET;

			std::uint8_t* p = buf.data() + SHELLCODE_OFFSET;

#ifdef _WIN64
			// F0 48 FF 05 <disp32_ctr>   lock inc qword [rip + disp]   (8 bytes)
			// FF 25 <disp32_orig>        jmp qword [rip + disp]        (6 bytes)
			//
			// [rip+disp] resolves relative to the byte AFTER the instruction.
			// After the 8-byte lock-inc, RIP = shellcode_va + 8.
			// After the 6-byte jmp,      RIP = shellcode_va + 14.
			const std::int64_t disp_ctr_i64 =
				static_cast<std::int64_t>(counter_va) -
				static_cast<std::int64_t>(shellcode_va + 8);
			const std::int64_t disp_orig_i64 =
				static_cast<std::int64_t>(orig_ptr_va) -
				static_cast<std::int64_t>(shellcode_va + 14);
			const std::int32_t disp_ctr  = static_cast<std::int32_t>(disp_ctr_i64);
			const std::int32_t disp_orig = static_cast<std::int32_t>(disp_orig_i64);

			*p++ = 0xF0; *p++ = 0x48; *p++ = 0xFF; *p++ = 0x05;
			std::memcpy(p, &disp_ctr, 4); p += 4;
			*p++ = 0xFF; *p++ = 0x25;
			std::memcpy(p, &disp_orig, 4); p += 4;

			// Original target absolute address, 8 bytes at ORIG_PTR_OFFSET.
			std::memcpy(buf.data() + ORIG_PTR_OFFSET, &original_target, 8);
#else
			// F0 FF 05 <abs32_ctr>       lock inc dword [counter]      (7 bytes)
			// FF 25 <abs32_orig>         jmp dword [orig_ptr]          (6 bytes)
			const std::uint32_t abs_ctr  = static_cast<std::uint32_t>(counter_va);
			const std::uint32_t abs_orig = static_cast<std::uint32_t>(orig_ptr_va);

			*p++ = 0xF0; *p++ = 0xFF; *p++ = 0x05;
			std::memcpy(p, &abs_ctr, 4); p += 4;
			*p++ = 0xFF; *p++ = 0x25;
			std::memcpy(p, &abs_orig, 4); p += 4;

			const std::uint32_t orig32 = static_cast<std::uint32_t>(original_target);
			std::memcpy(buf.data() + ORIG_PTR_OFFSET, &orig32, 4);
#endif
			return buf;
		}

	}  // anonymous namespace

	std::optional<IatHookOutcome> install_iat_hook(
		const WinHandle& process,
		DWORD /*target_pid*/,
		std::wstring_view import_module,
		std::string_view function_name)
	{
		if (!process || import_module.empty() || function_name.empty()) {
			return std::nullopt;
		}

		// Enum modules; the main image is always the first entry.
		HMODULE modules[512]{};
		DWORD needed = 0;
		if (!EnumProcessModulesEx(
				process.get(), modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
			return std::nullopt;
		}
		if (needed < sizeof(HMODULE)) return std::nullopt;
		const std::uintptr_t image_base =
			reinterpret_cast<std::uintptr_t>(modules[0]);

		const std::string dll_ascii = wide_to_narrow_ascii(import_module);
		auto slot = find_iat_slot(process, image_base, dll_ascii, function_name);
		if (!slot) return std::nullopt;

		auto trampoline_base = PT::Memory::allocate_memory(
			process, TRAMPOLINE_SIZE,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		if (!trampoline_base) return std::nullopt;

		auto tramp_bytes = build_trampoline(*trampoline_base, slot->original_target);
		if (!PT::Memory::write_memory(
				process, *trampoline_base, tramp_bytes.data(), tramp_bytes.size())) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}

		// Overwrite the IAT slot with the trampoline shellcode address. The
		// IAT typically resolves to PAGE_READONLY after loader init, so we
		// go through patch_bytes(change_protection=true) — this fires the
		// PROTECTVM_REMOTE events that let the classifier distinguish an IAT
		// hook from an inline hook (whose .text-directed protection flip is
		// silently suppressed by the kernel on module .text pages).
		const std::uintptr_t shellcode_va = *trampoline_base + SHELLCODE_OFFSET;
		std::vector<std::uint8_t> slot_bytes(SLOT_SIZE, 0);
#ifdef _WIN64
		std::memcpy(slot_bytes.data(), &shellcode_va, SLOT_SIZE);
#else
		const std::uint32_t shellcode32 = static_cast<std::uint32_t>(shellcode_va);
		std::memcpy(slot_bytes.data(), &shellcode32, SLOT_SIZE);
#endif
		auto patch = PT::MemoryPatch::patch_bytes(
			process, slot->slot_va, slot_bytes, /*change_protection=*/true);
		if (!patch) {
			PT::Memory::free_memory(process, *trampoline_base, 0);
			return std::nullopt;
		}

		return IatHookOutcome{
			.iat_slot_va        = slot->slot_va,
			.original_target_va = slot->original_target,
			.trampoline_base    = *trampoline_base,
			.counter_va         = *trampoline_base + COUNTER_OFFSET,
			.slot_size          = SLOT_SIZE,
		};
	}

	std::optional<std::uint64_t> read_hit_counter(
		const WinHandle& process,
		std::uintptr_t counter_va)
	{
		if (!process || counter_va == 0) return std::nullopt;

#ifdef _WIN64
		std::uint64_t counter = 0;
		if (!PT::Memory::read_trivial_memory(process, counter_va, counter)) return std::nullopt;
		return counter;
#else
		std::uint32_t counter = 0;
		if (!PT::Memory::read_trivial_memory(process, counter_va, counter)) return std::nullopt;
		return static_cast<std::uint64_t>(counter);
#endif
	}

}  // namespace PT::IatHook
