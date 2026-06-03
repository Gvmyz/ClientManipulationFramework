#include "MemoryPatch.h"

#include "ProcessMemory.h"

namespace PT::MemoryPatch {
	std::optional<PatchOutcome> patch_bytes(
		const WinHandle& process,
		std::uintptr_t address,
		const std::vector<std::uint8_t>& bytes,
		bool change_protection
	) {
		if (!process || bytes.empty() || address == 0) {
			return std::nullopt;
		}

		void* remote = reinterpret_cast<void*>(address);
		PatchOutcome outcome{address, 0, 0, false};

		DWORD prev_protect = 0;
		if (change_protection) {
			if (!VirtualProtectEx(
				process.get(), remote, bytes.size(),
				PAGE_EXECUTE_READWRITE, &prev_protect)) {
				return std::nullopt;
			}
			outcome.previous_protection = prev_protect;
		}

		const bool wrote = PT::ProcessMemory::remote_write(
			process, remote, bytes.data(), bytes.size());

		if (!wrote) {
			// Don't leave the page RWX on failure.
			if (change_protection) {
				DWORD discarded = 0;
				VirtualProtectEx(
					process.get(), remote, bytes.size(), prev_protect, &discarded);
			}
			return std::nullopt;
		}
		outcome.bytes_written = bytes.size();

		// Restore even if the write succeeded — report the result but don't
		// treat a failed restore as a failed patch.
		if (change_protection) {
			DWORD discarded = 0;
			outcome.protection_restored = VirtualProtectEx(
				process.get(), remote, bytes.size(), prev_protect, &discarded) != 0;
		}

		return outcome;
	}

	std::optional<std::vector<std::uint8_t>> read_bytes(
		const WinHandle& process,
		std::uintptr_t address,
		std::size_t count
	) {
		if (!process || count == 0 || address == 0) {
			return std::nullopt;
		}

		std::vector<std::uint8_t> out(count);
		if (!PT::ProcessMemory::remote_read(
			process, reinterpret_cast<void*>(address), out.data(), count)) {
			return std::nullopt;
		}
		return out;
	}
}
