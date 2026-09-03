#include <Windows.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ApcInjection.h"
#include "DllInjection.h"
#include "HookInjection.h"
#include "IatHook.h"
#include "Memory.h"
#include "MemoryPatch.h"
#include "Process.h"
#include "ProcessMemory.h"
#include "Utils.h"
#include "DirectSyscall.h"
#include "UsermodeHookProbe.h"
#include <sstream>

namespace {
	struct Options {
		std::optional<DWORD> pid;
		std::optional<std::wstring> dll_path;
		std::optional<std::wstring> module_name;
		std::optional<std::string> function_name;
		bool committed_only{false};
		bool private_only{false};
		bool executable_only{false};
		// patch-memory verb
		std::optional<std::uintptr_t> address;
		std::optional<std::vector<std::uint8_t>> bytes;
		bool restore_protection{false};
		bool verify{false};
		// patch-memory tick mode: repeatedly write the same bytes at a fixed
		// interval (Cheat-Engine "freeze value" pattern). tick_count=1 (default)
		// preserves the classic one-shot behaviour.
		int tick_count{1};
		int tick_interval_ms{0};
		// hook-inline: how long to wait after installing the hook before
		// reading back the trampoline's hit counter (--verify only).
		int verify_wait_ms{2000};
		// hook-inline: minimum trampoline hit count required for --verify to
		// pass. Default 1 = "the hooked function must have executed through
		// the detour at least once during verify_wait_ms". Pass 0 to skip the
		// counter check entirely — useful for hooking game functions whose
		// call cadence we don't know in advance (e.g. rare AC handlers).
		// Also honored by apc-inject for the queued-APC counter check.
		int min_verify_hits{1};
		// hook-inline: total bytes to overwrite at the target function.
		// Must be >= the architecture's JMP length (14 x64, 5 x86). 0 means
		// "let the disassembler auto-detect the smallest aligned length".
		std::size_t preserve_bytes{0};
		// hook-inline: --module (reused from injection) + --rva pair resolves
		// the target address against a loaded module's base — e.g.
		// `--module ac_client.exe --rva 0x12345` for an AssaultCube .text
		// function whose RVA came from disassembly. --address takes precedence
		// if both forms are supplied.
		std::optional<std::uintptr_t> rva;
		// patch-aob: byte pattern (as hex, no wildcards for the baseline) to
		// scan for across the target's committed memory before doing the
		// write. Reused across --bytes semantics: the scan finds the address,
		// then the classic patch-memory write path uses --bytes to overwrite
		// (or the same pattern if --bytes is omitted).
		std::optional<std::vector<std::uint8_t>> aob_pattern;
		// patch-memory: Cheat-Engine-style pointer chain resolver. Syntax:
		//   "<module>+<hex-offset>[->hex-offset[->hex-offset...]]"
		// Examples:
		//   ac_client.exe+0x17E0A8           — static address (no dereference)
		//   ac_client.exe+0x17E0A8->0xEC     — one dereference + final offset
		//                                       (AC's local player health)
		// When present, this overrides --address: the tool resolves the chain
		// at runtime and uses the result as the write target.
		std::optional<std::wstring> pointer_chain;

		// --via-direct-syscall: global evasion flag. When set, every
		// cross-process memory primitive in Memory.cpp routes through
		// PT::DirectSyscall::Nt* wrappers, which emit the syscall
		// instruction directly and bypass every user-mode hook on
		// ntdll's exports. This is the RQ3 direct-syscall evasion axis.
		bool via_direct_syscall{false};

		// --observe-usermode-hooks: RQ3 diagnostic. Install our own inline
		// hooks on ntdll's Nt* exports before the attack runs. Counts and
		// logs every invocation. Under the Win32 path counters increment
		// (>= 4); under --via-direct-syscall they stay at 0. Combined with
		// the observation that ETW-TI and Sysmon still fire in both cases,
		// this produces the four-cell RQ3 evidence table.
		bool observe_usermode_hooks{false};
	};

	void print_usage(const wchar_t* exe_name) {
		std::wcout
			<< L"Usage:\n"
			<< L"  " << exe_name << L" list-processes\n"
			<< L"  " << exe_name << L" inspect-memory --pid <pid> [--committed] [--private] [--executable]\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid <pid> --dll <path> [--module <name>] [--call <export>]\n"
			<< L"  " << exe_name << L" inject-manualmap --pid <pid> --dll <path> [--call <export>]\n"
			<< L"  " << exe_name << L" inject-threadhijack --pid <pid> --dll <path> [--module <name>] [--call <export>]\n"
			<< L"  " << exe_name << L" patch-memory --pid <pid>\n"
			<< L"                              (--address <hex> | --pointer-chain <spec>)\n"
			<< L"                              --bytes <hex>\n"
			<< L"                              [--restore-protection] [--verify]\n"
			<< L"                              [--tick-count <N>] [--tick-interval-ms <ms>]\n"
			<< L"  " << exe_name << L" hook-inline --pid <pid>\n"
			<< L"                              (--address <hex> | --module <name> --rva <hex>)\n"
			<< L"                              [--preserve-bytes <N>] [--verify]\n"
			<< L"                              [--verify-wait-ms <ms>]\n"
			<< L"  " << exe_name << L" hook-iat   --pid <pid> --module <dll> --call <function>\n"
			<< L"                              [--verify] [--verify-wait-ms <ms>] [--verify-hits <N>]\n"
			<< L"  " << exe_name << L" list-imports --pid <pid>\n"
			<< L"                              (diagnostic: prints every (dll, function) pair the target imports;\n"
			<< L"                               use to pick a valid --module + --call for hook-iat)\n"
			<< L"  " << exe_name << L" apc-inject --pid <pid> [--verify]\n"
			<< L"                              [--verify-wait-ms <ms>] [--verify-hits <N>]\n"
			<< L"  " << exe_name << L" patch-aob --pid <pid> --aob-pattern <hex>\n"
			<< L"                              [--bytes <hex>] [--restore-protection] [--verify]\n\n"
			<< L"Global options (accepted by every subcommand):\n"
			<< L"  --via-direct-syscall        RQ3 evasion: emit the syscall instruction directly\n"
			<< L"                              from ProcessToolkit for every cross-process memory\n"
			<< L"                              primitive (NtOpenProcess / NtAllocateVirtualMemory /\n"
			<< L"                              NtWriteVirtualMemory / NtReadVirtualMemory /\n"
			<< L"                              NtProtectVirtualMemory / NtCreateThreadEx), bypassing\n"
			<< L"                              every user-mode ntdll hook. Syscall numbers are\n"
			<< L"                              resolved at startup by parsing ntdll's export table\n"
			<< L"                              (HellsGate; no hardcoded numbers). ETW-TI still fires\n"
			<< L"                              because those events originate in kernel mode.\n"
			<< L"                              Aborts the run if ntdll's stubs appear hooked.\n"
			<< L"  --observe-usermode-hooks    RQ3 diagnostic: install inline hooks on our own\n"
			<< L"                              ntdll's Nt* exports before the attack runs; count\n"
			<< L"                              and log every invocation. Under the Win32 path\n"
			<< L"                              counters increment (>= 4); under --via-direct-syscall\n"
			<< L"                              they stay at 0 -- empirical proof that direct-syscall\n"
			<< L"                              bypasses user-mode API hooks. Log file:\n"
			<< L"                              usermode-hooks-<targetPid>-<attackerPid>.log.\n\n"
			<< L"Examples:\n"
			<< L"  " << exe_name << L" list-processes\n"
			<< L"  " << exe_name << L" inspect-memory --pid 1234 --committed --executable\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n"
			<< L"  " << exe_name << L" inject-manualmap --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n"
			<< L"  " << exe_name << L" inject-threadhijack --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n"
			<< L"  " << exe_name << L" patch-memory --pid 1234 --address 0x7FF6C0123ABC --bytes 0F270000 --verify\n"
			<< L"  " << exe_name << L" patch-memory --pid 1234 --pointer-chain ac_client.exe+0x17E0A8->0xEC --bytes 64000000 --tick-count 20 --tick-interval-ms 50\n"
			<< L"  " << exe_name << L" hook-inline --pid 1234 --address 0x7FF6C0123ABC --verify\n"
			<< L"  " << exe_name << L" hook-inline --pid 1234 --module ac_client.exe --rva 0x12345 --verify\n"
			<< L"  " << exe_name << L" hook-iat    --pid 1234 --module kernel32.dll --call SleepEx --verify\n"
			<< L"  " << exe_name << L" apc-inject  --pid 1234 --verify --verify-wait-ms 2000\n"
			<< L"  " << exe_name << L" patch-aob   --pid 1234 --aob-pattern 58020000 --bytes 0F270000 --verify\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid 1234 --dll C:\\path\\TestDll.dll --via-direct-syscall\n";
	}

	std::optional<DWORD> parse_pid(std::wstring_view value) {
		if (value.empty()) {
			return std::nullopt;
		}

		std::wstring input{value};
		wchar_t* end = nullptr;
		errno = 0;
		const unsigned long pid = std::wcstoul(input.c_str(), &end, 10);
		if (errno != 0 || end == input.c_str() || *end != L'\0' || pid > MAXDWORD) {
			return std::nullopt;
		}
		return static_cast<DWORD>(pid);
	}

	// Parse a hex virtual address. Accepts "0x..." or bare hex digits.
	// Forward declarations for helpers defined later in this file. The
	// patch-memory handler calls resolve_pointer_chain, which sits alongside
	// aob_scan below the injection handlers for locality with its consumer.
	std::optional<std::uintptr_t> resolve_pointer_chain(
		const WinHandle& process, std::wstring_view spec);

	std::optional<std::uintptr_t> parse_hex_address(std::wstring_view value) {
		if (value.size() > 2 && (value.starts_with(L"0x") || value.starts_with(L"0X"))) {
			value.remove_prefix(2);
		}
		if (value.empty()) {
			return std::nullopt;
		}

		std::wstring input{value};
		wchar_t* end = nullptr;
		errno = 0;
		const auto parsed = std::wcstoull(input.c_str(), &end, 16);
		if (errno != 0 || end == input.c_str() || *end != L'\0') {
			return std::nullopt;
		}
		return static_cast<std::uintptr_t>(parsed);
	}

	// Parse an even-length hex byte string into raw bytes.
	// "0F270000" -> {0x0F, 0x27, 0x00, 0x00}. Accepts optional "0x" prefix.
	std::optional<std::vector<std::uint8_t>> parse_hex_bytes(std::wstring_view value) {
		if (value.size() > 2 && (value.starts_with(L"0x") || value.starts_with(L"0X"))) {
			value.remove_prefix(2);
		}
		if (value.empty() || value.size() % 2 != 0) {
			return std::nullopt;
		}

		const auto nibble = [](wchar_t c) -> int {
			if (c >= L'0' && c <= L'9') return c - L'0';
			if (c >= L'a' && c <= L'f') return c - L'a' + 10;
			if (c >= L'A' && c <= L'F') return c - L'A' + 10;
			return -1;
		};

		std::vector<std::uint8_t> bytes;
		bytes.reserve(value.size() / 2);

		for (std::size_t i = 0; i < value.size(); i += 2) {
			const int hi = nibble(value[i]);
			const int lo = nibble(value[i + 1]);
			if (hi < 0 || lo < 0) {
				return std::nullopt;
			}
			bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
		}
		return bytes;
	}

	std::optional<std::string> narrow_ascii(std::wstring_view value) {
		std::string result;
		result.reserve(value.size());

		for (wchar_t ch : value) {
			if (ch < 0 || ch > 0x7F) {
				return std::nullopt;
			}
			result.push_back(static_cast<char>(ch));
		}
		return result;
	}

	std::optional<Options> parse_options(int argc, wchar_t** argv, int first_index) {
		Options options{};

		for (int i = first_index; i < argc; ++i) {
			const std::wstring_view arg{argv[i]};

			if (arg == L"--pid" && i + 1 < argc) {
				auto pid = parse_pid(argv[++i]);
				if (!pid) {
					PT::Cli::print_error("Invalid --pid value");
					return std::nullopt;
				}
				options.pid = *pid;
			} else if (arg == L"--dll" && i + 1 < argc) {
				options.dll_path = argv[++i];
			} else if (arg == L"--module" && i + 1 < argc) {
				options.module_name = argv[++i];
			} else if (arg == L"--call" && i + 1 < argc) {
				auto function_name = narrow_ascii(argv[++i]);
				if (!function_name) {
					PT::Cli::print_error("--call expects an ASCII export name");
					return std::nullopt;
				}
				options.function_name = *function_name;
			} else if (arg == L"--committed") {
				options.committed_only = true;
			} else if (arg == L"--private") {
				options.private_only = true;
			} else if (arg == L"--executable") {
				options.executable_only = true;
			} else if (arg == L"--address" && i + 1 < argc) {
				auto address = parse_hex_address(argv[++i]);
				if (!address) {
					PT::Cli::print_error("Invalid --address value (expected hex, e.g. 0x7FF6C0123ABC)");
					return std::nullopt;
				}
				options.address = *address;
			} else if (arg == L"--bytes" && i + 1 < argc) {
				auto bytes = parse_hex_bytes(argv[++i]);
				if (!bytes) {
					PT::Cli::print_error("Invalid --bytes value (expected even-length hex string, e.g. 0F270000)");
					return std::nullopt;
				}
				options.bytes = std::move(*bytes);
			} else if (arg == L"--restore-protection") {
				options.restore_protection = true;
			} else if (arg == L"--via-direct-syscall") {
				options.via_direct_syscall = true;
			} else if (arg == L"--observe-usermode-hooks") {
				options.observe_usermode_hooks = true;
			} else if (arg == L"--verify") {
				options.verify = true;
			} else if (arg == L"--tick-count" && i + 1 < argc) {
				try {
					options.tick_count = std::stoi(argv[++i]);
				} catch (...) {
					PT::Cli::print_error("Invalid --tick-count value (expected positive integer)");
					return std::nullopt;
				}
				if (options.tick_count < 1) {
					PT::Cli::print_error("--tick-count must be >= 1");
					return std::nullopt;
				}
			} else if (arg == L"--tick-interval-ms" && i + 1 < argc) {
				try {
					options.tick_interval_ms = std::stoi(argv[++i]);
				} catch (...) {
					PT::Cli::print_error("Invalid --tick-interval-ms value (expected integer >= 0)");
					return std::nullopt;
				}
				if (options.tick_interval_ms < 0) {
					PT::Cli::print_error("--tick-interval-ms must be >= 0");
					return std::nullopt;
				}
			} else if (arg == L"--verify-wait-ms" && i + 1 < argc) {
				try {
					options.verify_wait_ms = std::stoi(argv[++i]);
				} catch (...) {
					PT::Cli::print_error("Invalid --verify-wait-ms value (expected integer >= 0)");
					return std::nullopt;
				}
				if (options.verify_wait_ms < 0) {
					PT::Cli::print_error("--verify-wait-ms must be >= 0");
					return std::nullopt;
				}
			} else if (arg == L"--preserve-bytes" && i + 1 < argc) {
				try {
					const int parsed = std::stoi(argv[++i]);
					if (parsed < 0) {
						PT::Cli::print_error("--preserve-bytes must be >= 0");
						return std::nullopt;
					}
					options.preserve_bytes = static_cast<std::size_t>(parsed);
				} catch (...) {
					PT::Cli::print_error("Invalid --preserve-bytes value (expected integer >= 0)");
					return std::nullopt;
				}
			} else if (arg == L"--rva" && i + 1 < argc) {
				auto rva = parse_hex_address(argv[++i]);
				if (!rva) {
					PT::Cli::print_error("Invalid --rva value (expected hex, e.g. 0x12345)");
					return std::nullopt;
				}
				options.rva = *rva;
			} else if (arg == L"--pointer-chain" && i + 1 < argc) {
				options.pointer_chain = argv[++i];
			} else if (arg == L"--aob-pattern" && i + 1 < argc) {
				auto pattern = parse_hex_bytes(argv[++i]);
				if (!pattern || pattern->empty()) {
					PT::Cli::print_error("Invalid --aob-pattern value (expected even-length hex string, e.g. 58020000)");
					return std::nullopt;
				}
				options.aob_pattern = std::move(*pattern);
			} else if (arg == L"--verify-hits" && i + 1 < argc) {
				try {
					options.min_verify_hits = std::stoi(argv[++i]);
				} catch (...) {
					PT::Cli::print_error("Invalid --verify-hits value (expected integer >= 0)");
					return std::nullopt;
				}
				if (options.min_verify_hits < 0) {
					PT::Cli::print_error("--verify-hits must be >= 0");
					return std::nullopt;
				}
			} else {
				std::wcerr << L"Unknown or incomplete argument: " << arg << L'\n';
				return std::nullopt;
			}
		}

		return options;
	}

	std::wstring dll_filename(const std::wstring& dll_path) {
		return std::filesystem::path{dll_path}.filename().wstring();
	}

	void print_memory_info(const PT::MemoryInfo& mbi) {
		std::cout << "BaseAddress: " << PT::Cli::to_hex(mbi.base_address) << '\n';
		std::cout << "AllocationBase: " << PT::Cli::to_hex(mbi.allocation_base) << '\n';
		std::cout << "RegionSize: " << mbi.region_size << '\n';
		std::cout << "State: " << PT::Memory::get_state_name(mbi.state) << '\n';
		std::cout << "Protect: " << PT::Memory::get_protect_name(mbi.protect) << '\n';
		std::cout << "Type: " << PT::Memory::get_type_name(mbi.type) << "\n\n";
	}

	int list_processes() {
		PT::Cli::print_section("Processes");

		for (const auto pid : PT::Process::list_processes()) {
			if (pid == 0) {
				continue;
			}

			if (const auto path = PT::Process::get_image_path(pid)) {
				std::wcout << L"PID: " << pid << L" | " << *path << L'\n';
			}
		}

		return 0;
	}

	int inspect_memory(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("inspect-memory requires --pid");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::Process::open_process(*options.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		auto memory_infos = PT::Memory::get_memory_infos(process);
		if (options.committed_only) {
			memory_infos = PT::Memory::filter_committed_regions(memory_infos);
		}
		if (options.private_only) {
			memory_infos = PT::Memory::filter_private_regions(memory_infos);
		}
		if (options.executable_only) {
			memory_infos = PT::Memory::filter_executable_regions(memory_infos);
		}

		PT::Cli::print_named_value("Region count", memory_infos.size());
		for (const auto& memory_info : memory_infos) {
			print_memory_info(memory_info);
		}

		return 0;
	}

	int inject_loadlibrary(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("inject-loadlibrary requires --pid");
			return 2;
		}
		if (!options.dll_path || options.dll_path->empty()) {
			PT::Cli::print_error("inject-loadlibrary requires --dll");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("Inject DLL");
		auto load_library_result = PT::DllInjection::inject_dll_loadlibrary(process, *options.dll_path);
		if (!PT::Cli::run_step("Injected DLL", load_library_result.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("LoadLibraryW return value", *load_library_result);

		if (!options.function_name) {
			return 0;
		}

		const std::wstring module_name = options.module_name.value_or(dll_filename(*options.dll_path));

		PT::Cli::print_section("Find Remote Module");
		auto dll_base = PT::Memory::find_module_base(process, module_name);
		if (!PT::Cli::run_step("Found remote module base", dll_base.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("Remote DLL base", *dll_base);

		PT::Cli::print_section("Call Exported Function");
		const bool call_result = PT::DllInjection::call_exported_function(
			process,
			*options.dll_path,
			*dll_base,
			*options.function_name
		);

		return PT::Cli::run_step(std::format("Called function {}", *options.function_name), call_result) ? 0 : 1;
	}

	int inject_threadhijack(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("inject-threadhijack requires --pid");
			return 2;
		}
		if (!options.dll_path || options.dll_path->empty()) {
			PT::Cli::print_error("inject-threadhijack requires --dll");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("Hijack Thread");
		auto hijack_result = PT::DllInjection::inject_dll_threadhijack(process, *options.dll_path);
		if (!PT::Cli::run_step("Hijacked thread for DLL injection", hijack_result.has_value())) {
			return 1;
		}

		PT::Cli::print_named_value("Hijacked thread ID", *hijack_result);

		if (!options.function_name) {
			return 0;
		}

		const std::wstring module_name = options.module_name.value_or(dll_filename(*options.dll_path));

		PT::Cli::print_section("Find Remote Module");
		auto dll_base = PT::Memory::find_module_base(process, module_name);
		if (!PT::Cli::run_step("Found remote module base", dll_base.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("Remote DLL base", *dll_base);

		PT::Cli::print_section("Call Exported Function");
		const bool call_result = PT::DllInjection::call_exported_function(
			process,
			*options.dll_path,
			*dll_base,
			*options.function_name
		);

		return PT::Cli::run_step(std::format("Called function {}", *options.function_name), call_result) ? 0 : 1;
	}

	int patch_memory(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("patch-memory requires --pid");
			return 2;
		}
		if (!options.address && !options.pointer_chain) {
			PT::Cli::print_error("patch-memory requires --address or --pointer-chain");
			return 2;
		}
		if (!options.bytes || options.bytes->empty()) {
			PT::Cli::print_error("patch-memory requires --bytes");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");

		auto process = PT::ProcessMemory::open_process_memory_only(*options.pid, options.verify);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		// Resolve the target address. --pointer-chain takes precedence over
		// --address; the chain resolver does its own module lookup + one
		// dereference per arrow in the spec, then produces the final VA that
		// the write loop below hits.
		std::uintptr_t target_addr = 0;
		if (options.pointer_chain) {
			PT::Cli::print_section("Resolve Pointer Chain");
			PT::Cli::print_named_value("Chain spec length (chars)",
				options.pointer_chain->size());
			auto resolved = resolve_pointer_chain(process, *options.pointer_chain);
			if (!PT::Cli::run_step("Resolved pointer chain", resolved.has_value())) {
				return 1;
			}
			PT::Cli::print_named_hex("Resolved target address", *resolved);
			target_addr = *resolved;
		} else {
			target_addr = *options.address;
		}

		PT::Cli::print_section("Patch Memory");
		PT::Cli::print_named_hex("Target address", target_addr);
		PT::Cli::print_named_value("Bytes to write", options.bytes->size());
		PT::Cli::print_named_value(
			"Toggle protection (RWX during write)",
			options.restore_protection ? "yes" : "no");
		if (options.tick_count > 1) {
			PT::Cli::print_named_value("Tick count", options.tick_count);
			PT::Cli::print_named_value("Tick interval (ms)", options.tick_interval_ms);
		}

		// Tick mode: repeat the patch_bytes call N times with a fixed sleep in
		// between. Each tick fires its own WRITEVM (and, if --restore-protection,
		// two PROTECTVMs). tick_count=1 (default) makes this behave exactly
		// like the classic one-shot patch — no code path change for existing
		// runs. Interval 0 means "as fast as possible" (bursts).
		SIZE_T last_bytes_written = 0;
		DWORD  last_prev_protect  = 0;
		bool   last_protect_restored = false;
		for (int t = 0; t < options.tick_count; ++t) {
			if (t > 0 && options.tick_interval_ms > 0) {
				Sleep(static_cast<DWORD>(options.tick_interval_ms));
			}
			auto outcome = PT::MemoryPatch::patch_bytes(
				process, target_addr, *options.bytes, options.restore_protection);
			if (!outcome.has_value()) {
				PT::Cli::run_step(
					std::format("Wrote bytes to remote memory (tick {}/{})",
								t + 1, options.tick_count),
					false);
				return 1;
			}
			last_bytes_written    = outcome->bytes_written;
			last_prev_protect     = outcome->previous_protection;
			last_protect_restored = outcome->protection_restored;
		}

		PT::Cli::run_step(
			(options.tick_count > 1)
				? std::format("Wrote bytes to remote memory ({} ticks OK)", options.tick_count)
				: std::string("Wrote bytes to remote memory"),
			true);
		PT::Cli::print_named_value("Bytes written (per tick)", last_bytes_written);
		if (options.restore_protection) {
			PT::Cli::print_named_hex("Previous protection (last tick)", last_prev_protect);
			PT::Cli::run_step("Restored previous protection", last_protect_restored);
		}

		if (options.verify) {
			PT::Cli::print_section("Verify");
			auto read_back = PT::MemoryPatch::read_bytes(
				process, target_addr, options.bytes->size());
			if (!PT::Cli::run_step("Read bytes back from target", read_back.has_value())) {
				return 1;
			}
			const bool match = (*read_back == *options.bytes);
			if (!PT::Cli::run_step("Read-back matches requested patch", match)) {
				return 1;
			}
		}

		return 0;
	}

	int hook_inline(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("hook-inline requires --pid");
			return 2;
		}
		if (!options.address && !(options.module_name && options.rva)) {
			PT::Cli::print_error("hook-inline requires --address, or --module + --rva");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		// Resolve --address, or --module + --rva → absolute target VA.
		std::uintptr_t target_addr = 0;
		if (options.address) {
			target_addr = *options.address;
		} else {
			PT::Cli::print_section("Resolve Module + RVA");
			auto mod_base = PT::Memory::find_module_base(process, *options.module_name);
			if (!PT::Cli::run_step("Found target module base", mod_base.has_value())) {
				return 1;
			}
			PT::Cli::print_named_hex("Module base", *mod_base);
			PT::Cli::print_named_hex("RVA", *options.rva);
			target_addr = *mod_base + *options.rva;
		}

		PT::Cli::print_section("Install Inline Hook");
		PT::Cli::print_named_hex("Target function", target_addr);
		if (options.preserve_bytes > 0) {
			PT::Cli::print_named_value("Preserve bytes (requested)", options.preserve_bytes);
		} else {
			PT::Cli::print_named_value("Preserve bytes", "auto (disassembler)");
		}

		auto outcome = PT::HookInjection::install_inline_hook(
			process, target_addr, options.preserve_bytes);
		if (!PT::Cli::run_step("Installed inline hook", outcome.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("Trampoline base", outcome->trampoline_base);
		PT::Cli::print_named_value("JMP length", outcome->hook_bytes_size);
		PT::Cli::print_named_value("Bytes preserved / overwritten", outcome->preserved_bytes);
		PT::Cli::print_named_hex("Previous .text protection", outcome->previous_protection);
		PT::Cli::run_step("Restored .text protection", outcome->protection_restored);

		if (options.verify) {
			PT::Cli::print_section("Verify");

			// (a) Read back the first byte of target_function; must be 0xFF (x64
			//     absolute-JMP opcode `FF 25 ...`) or 0xE9 (x86 relative JMP).
			auto post_hook_bytes = PT::MemoryPatch::read_bytes(
				process, target_addr, outcome->preserved_bytes);
			if (!PT::Cli::run_step("Read bytes back from target function", post_hook_bytes.has_value())) {
				return 1;
			}
			const std::uint8_t expected_opcode =
#ifdef _WIN64
				0xFF;
#else
				0xE9;
#endif
			const bool jmp_installed =
				!post_hook_bytes->empty() && post_hook_bytes->front() == expected_opcode;
			if (!PT::Cli::run_step("Overwrite opcode matches expected JMP", jmp_installed)) {
				return 1;
			}

			// (b) Wait, then read the trampoline counter — nonzero means the
			//     target actually called the hooked function through our
			//     detour at least once during verify_wait_ms. When
			//     min_verify_hits is 0 the runtime-firing check is skipped
			//     entirely (useful for game functions whose call cadence we
			//     don't know in advance — install-only verification).
			if (options.min_verify_hits == 0) {
				PT::Cli::print_named_value(
					"Runtime-firing check", "skipped (--verify-hits 0)");
				return 0;
			}
			if (options.verify_wait_ms > 0) {
				Sleep(static_cast<DWORD>(options.verify_wait_ms));
			}
			auto counter = PT::HookInjection::read_hit_counter(process, outcome->trampoline_base);
			if (!PT::Cli::run_step("Read trampoline hit counter", counter.has_value())) {
				return 1;
			}
			PT::Cli::print_named_value("Trampoline hits observed", *counter);
			const bool hook_fired = *counter >= static_cast<std::uint64_t>(options.min_verify_hits);
			if (!PT::Cli::run_step(
					std::format("Hook fired at least {} time(s)", options.min_verify_hits),
					hook_fired)) {
				return 1;
			}
		}

		return 0;
	}

	// Enumerate the target's import descriptor table and print every
	// (import_dll, function_name) pair. Diagnostic — helps pick a valid
	// (module, function) pair for `hook-iat` against unfamiliar targets
	// (e.g. AC's ac_client.exe imports Win32 message-loop APIs but does NOT
	// import GetAsyncKeyState, which is what motivated adding this).
	int list_imports(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("list-imports requires --pid");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::Process::open_process(
			*options.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		HMODULE modules[512]{};
		DWORD needed = 0;
		if (!EnumProcessModulesEx(process.get(), modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
			PT::Cli::print_error("EnumProcessModulesEx failed");
			return 1;
		}
		if (needed < sizeof(HMODULE)) {
			PT::Cli::print_error("target has zero loaded modules");
			return 1;
		}
		const std::uintptr_t image_base = reinterpret_cast<std::uintptr_t>(modules[0]);

		PT::Cli::print_section("Walk Import Descriptors");
		PT::Cli::print_named_hex("Main image base", image_base);

		IMAGE_DOS_HEADER dos{};
		if (!PT::Memory::read_trivial_memory(process, image_base, dos) ||
			dos.e_magic != IMAGE_DOS_SIGNATURE) {
			PT::Cli::print_error("main image has no valid DOS header");
			return 1;
		}
		const std::uintptr_t nt_addr = image_base + dos.e_lfanew;
#ifdef _WIN64
		IMAGE_NT_HEADERS64 nt{};
#else
		IMAGE_NT_HEADERS32 nt{};
#endif
		if (!PT::Memory::read_trivial_memory(process, nt_addr, nt) ||
			nt.Signature != IMAGE_NT_SIGNATURE) {
			PT::Cli::print_error("main image has no valid NT headers");
			return 1;
		}
		const auto& imp_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) {
			PT::Cli::print_error("main image has no import directory");
			return 1;
		}
		const std::uintptr_t desc_base = image_base + imp_dir.VirtualAddress;

		auto read_c_str = [&](std::uintptr_t addr) -> std::string {
			std::string out;
			std::uint8_t byte;
			for (std::size_t i = 0; i < 256; ++i) {
				if (!PT::Memory::read_trivial_memory(process, addr + i, byte) || byte == 0) break;
				out.push_back(static_cast<char>(byte));
			}
			return out;
		};

		std::size_t total_dlls = 0, total_fns = 0;
		for (std::size_t i = 0; ; ++i) {
			IMAGE_IMPORT_DESCRIPTOR desc{};
			if (!PT::Memory::read_trivial_memory(
					process, desc_base + i * sizeof(desc), desc)) break;
			if (desc.Name == 0 && desc.FirstThunk == 0) break;

			const std::string dll = read_c_str(image_base + desc.Name);
			if (dll.empty()) continue;
			total_dlls++;
			std::cout << "\n[" << dll << "]\n";

			if (desc.OriginalFirstThunk == 0) {
				std::cout << "  (bound imports — names not readable)\n";
				continue;
			}
			const std::uintptr_t int_base = image_base + desc.OriginalFirstThunk;
			for (std::size_t j = 0; ; ++j) {
#ifdef _WIN64
				IMAGE_THUNK_DATA64 thunk{};
				if (!PT::Memory::read_trivial_memory(
						process, int_base + j * sizeof(thunk), thunk)) break;
				if (thunk.u1.AddressOfData == 0) break;
				if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					std::cout << "  (ordinal " << (thunk.u1.Ordinal & 0xFFFF) << ")\n";
					continue;
				}
#else
				IMAGE_THUNK_DATA32 thunk{};
				if (!PT::Memory::read_trivial_memory(
						process, int_base + j * sizeof(thunk), thunk)) break;
				if (thunk.u1.AddressOfData == 0) break;
				if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
					std::cout << "  (ordinal " << (thunk.u1.Ordinal & 0xFFFF) << ")\n";
					continue;
				}
#endif
				const std::string fn = read_c_str(image_base + thunk.u1.AddressOfData + sizeof(WORD));
				if (fn.empty()) continue;
				total_fns++;
				std::cout << "  " << fn << "\n";
			}
		}

		std::cout << "\n";
		PT::Cli::print_named_value("Imported DLLs (with named imports)", total_dlls);
		PT::Cli::print_named_value("Named imports total", total_fns);
		return 0;
	}

	int hook_iat(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("hook-iat requires --pid");
			return 2;
		}
		if (!options.module_name || options.module_name->empty()) {
			PT::Cli::print_error("hook-iat requires --module (imported DLL name, e.g. kernel32.dll)");
			return 2;
		}
		if (!options.function_name || options.function_name->empty()) {
			PT::Cli::print_error("hook-iat requires --call (imported function name, e.g. SleepEx)");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("Install IAT Hook");
		std::wcout << L"  Imported module: " << *options.module_name << L'\n';
		std::cout  << "  Function       : " << *options.function_name << '\n';

		auto outcome = PT::IatHook::install_iat_hook(
			process, *options.pid, *options.module_name, *options.function_name);
		if (!PT::Cli::run_step("Installed IAT hook", outcome.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("IAT slot",             outcome->iat_slot_va);
		PT::Cli::print_named_hex("Original target",      outcome->original_target_va);
		PT::Cli::print_named_hex("Trampoline base",      outcome->trampoline_base);
		PT::Cli::print_named_hex("Counter addr",         outcome->counter_va);
		PT::Cli::print_named_value("Slot size (bytes)",  outcome->slot_size);

		if (options.verify) {
			PT::Cli::print_section("Verify");

			// (a) Read the IAT slot back — must equal (trampoline_base + 0x10),
			//     the shellcode entry point we wrote.
			auto slot_bytes = PT::MemoryPatch::read_bytes(
				process, outcome->iat_slot_va, outcome->slot_size);
			if (!PT::Cli::run_step("Read IAT slot back", slot_bytes.has_value())) {
				return 1;
			}
			std::uintptr_t observed_slot = 0;
			std::memcpy(&observed_slot, slot_bytes->data(), outcome->slot_size);
			const std::uintptr_t expected_slot = outcome->trampoline_base + 0x10;
			const bool slot_matches = (observed_slot == expected_slot);
			if (!PT::Cli::run_step("IAT slot now points at trampoline shellcode", slot_matches)) {
				return 1;
			}

			// (b) Wait, then read the trampoline hit counter. Nonzero =>
			//     the target has called through the hooked import at least
			//     once. --verify-hits 0 skips the runtime-firing check (for
			//     imports whose call cadence we don't know in advance).
			if (options.min_verify_hits == 0) {
				PT::Cli::print_named_value(
					"Runtime-firing check", "skipped (--verify-hits 0)");
				return 0;
			}
			if (options.verify_wait_ms > 0) {
				Sleep(static_cast<DWORD>(options.verify_wait_ms));
			}
			auto counter = PT::IatHook::read_hit_counter(process, outcome->counter_va);
			if (!PT::Cli::run_step("Read trampoline hit counter", counter.has_value())) {
				return 1;
			}
			PT::Cli::print_named_value("Trampoline hits observed", *counter);
			const bool fired = *counter >= static_cast<std::uint64_t>(options.min_verify_hits);
			if (!PT::Cli::run_step(
					std::format("IAT hook fired at least {} time(s)", options.min_verify_hits),
					fired)) {
				return 1;
			}
		}

		return 0;
	}

	// Resolve a Cheat-Engine-style pointer chain in the target process.
	// Syntax: "<module>+<hex-offset>[->hex-offset[->hex-offset...]]"
	//
	// For a chain like `M+A -> B -> C`:
	//   addr = module_base(M) + A
	//   for each further offset (B, C, ...):
	//       ptr = ReadProcessMemory(addr, sizeof(void*))   // dereference
	//       addr = ptr + offset
	//   return addr
	//
	// A chain with zero arrows (`M+A`) returns module_base(M) + A directly
	// — equivalent to --address but easier to spec across builds that
	// relocate the module image (ASLR-aware; AC 1.3.0.2 loads at its
	// preferred base so this doesn't matter here, but future targets may).
	//
	// The dereferenced pointer size follows the attacker's architecture:
	// std::uintptr_t is 8 bytes on x64 and 4 bytes on x86, which matches
	// the target's architecture in every experiment we run (same-arch
	// attacker/target). Cross-arch pointer chains would need explicit
	// width handling; out of scope for the current corpus.
	std::optional<std::uintptr_t> resolve_pointer_chain(
		const WinHandle& process, std::wstring_view spec)
	{
		if (!process || spec.empty()) return std::nullopt;

		// Split on "->" to separate the module+base-offset token from any
		// dereferenceable offsets.
		std::vector<std::wstring_view> tokens;
		{
			std::size_t start = 0;
			while (start <= spec.size()) {
				const auto sep = spec.find(L"->", start);
				if (sep == std::wstring_view::npos) {
					tokens.push_back(spec.substr(start));
					break;
				}
				tokens.push_back(spec.substr(start, sep - start));
				start = sep + 2;   // skip "->"
			}
		}
		if (tokens.empty()) return std::nullopt;

		// First token: "<module>+<hex-offset>"
		const auto& first = tokens[0];
		const auto plus_pos = first.find(L'+');
		if (plus_pos == std::wstring_view::npos) {
			PT::Cli::print_error("--pointer-chain must start with '<module>+<hex-offset>'");
			return std::nullopt;
		}
		const std::wstring module_name{first.substr(0, plus_pos)};
		auto base_off = parse_hex_address(first.substr(plus_pos + 1));
		if (!base_off) {
			PT::Cli::print_error("--pointer-chain: invalid base offset in first token");
			return std::nullopt;
		}

		auto module_base = PT::Memory::find_module_base(process, module_name);
		if (!module_base) {
			PT::Cli::print_error("--pointer-chain: could not resolve module base");
			return std::nullopt;
		}

		std::uintptr_t addr = *module_base + *base_off;

		// Each subsequent token: dereference `addr`, then add the offset.
		for (std::size_t i = 1; i < tokens.size(); ++i) {
			auto off = parse_hex_address(tokens[i]);
			if (!off) {
				PT::Cli::print_error("--pointer-chain: invalid offset in chain");
				return std::nullopt;
			}
			std::uintptr_t next_ptr = 0;
			if (!PT::Memory::read_trivial_memory(process, addr, next_ptr)) {
				PT::Cli::print_error("--pointer-chain: dereference read failed (bad pointer or unreadable)");
				return std::nullopt;
			}
			addr = next_ptr + *off;
		}
		return addr;
	}

	// Scan the target process's WRITABLE committed memory for a byte pattern
	// and return the absolute address of the FIRST match, or std::nullopt if
	// nothing matches. Every writable region is read exhaustively even after
	// the first match is found — this is deliberate:
	//
	//   * Cheat Engine's default AOB scan builds a full match list rather
	//     than stopping early, so the user can iteratively narrow it (edit
	//     value, rescan, filter). Our tool applies only the first match, but
	//     the reconnaissance READ workload matches CE's real behavior.
	//   * Fingerprint-wise, an early-terminating scan bottoms out at 3-5
	//     READVM_REMOTE events (whichever region contains the first match)
	//     and gets buried in ambient noise from Windows internals reading
	//     target memory. Exhaustive scanning produces 30-100+ attacker-
	//     attributed READVMs that clearly dominate the read-count feature.
	//
	// Filters out regions that either can't be safely read OR can't be
	// written to at their existing protection:
	//   * MEM_FREE / MEM_RESERVE — not committed
	//   * PAGE_NOACCESS / PAGE_GUARD — reads would AV
	//   * PAGE_EXECUTE / PAGE_READONLY / PAGE_EXECUTE_READ — read-only pages
	//     (system-DLL .text and .rdata, mapped section views of read-only
	//     files, immutable image imports). A pattern match here CAN succeed
	//     — a constant in ntdll happens to be 0x00000258, for instance — but
	//     the subsequent WriteProcessMemory would fail with ERROR_NOACCESS
	//     because the page isn't PAGE_*WRITE*. Cheat Engine's default AOB
	//     scan filters to writable regions for exactly this reason; adding a
	//     protection-flip variant that scans .text and then RWX-writes is a
	//     separate technique (patch_alloc / code-cave workflow).
	// Also skips huge regions (>= 128 MB) to keep the scan bounded on games
	// that mmap large asset files.
	std::optional<std::uintptr_t> aob_scan(
		const WinHandle& process,
		const std::vector<std::uint8_t>& pattern)
	{
		if (!process || pattern.empty()) {
			return std::nullopt;
		}

		constexpr std::size_t MAX_REGION_BYTES = 128 * 1024 * 1024;   // 128 MB cutoff

		// The union of every protection class that permits a subsequent
		// WriteProcessMemory without a preceding VirtualProtectEx.
		constexpr DWORD WRITABLE_MASK =
			PAGE_READWRITE | PAGE_WRITECOPY |
			PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

		std::optional<std::uintptr_t> first_hit;

		auto regions = PT::Memory::get_memory_infos(process);
		for (const auto& r : regions) {
			if (r.state != MEM_COMMIT) continue;
			if (r.protect & PAGE_NOACCESS) continue;
			if (r.protect & PAGE_GUARD)    continue;
			if ((r.protect & WRITABLE_MASK) == 0) continue;   // read-only page
			if (r.region_size == 0)        continue;
			if (r.region_size > MAX_REGION_BYTES) continue;
			if (r.region_size < pattern.size()) continue;

			std::vector<std::uint8_t> buffer(r.region_size);
			if (!PT::Memory::read_memory(
					process, r.base_address, buffer.data(), buffer.size())) {
				// A region that ReadProcessMemory refused (guard pages we
				// didn't catch, protected pages, etc.) is expected; keep
				// scanning rather than aborting on the first failure.
				continue;
			}

			// Record the first match but keep scanning — the READVMs we're
			// about to issue for the remaining regions are the whole point.
			if (!first_hit) {
				auto hit = std::search(
					buffer.begin(), buffer.end(),
					pattern.begin(),  pattern.end());
				if (hit != buffer.end()) {
					const std::size_t offset =
						static_cast<std::size_t>(hit - buffer.begin());
					first_hit = r.base_address + offset;
				}
			}
		}
		return first_hit;
	}

	int patch_aob(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("patch-aob requires --pid");
			return 2;
		}
		if (!options.aob_pattern || options.aob_pattern->empty()) {
			PT::Cli::print_error("patch-aob requires --aob-pattern");
			return 2;
		}
		// The replacement bytes default to the pattern itself if --bytes is
		// omitted (writes the same value back — the null patch, useful for
		// dry runs where we only want to characterize the read/write pattern
		// without changing target state). Most real invocations pass --bytes.
		const auto& write_bytes = options.bytes.value_or(*options.aob_pattern);
		if (write_bytes.empty()) {
			PT::Cli::print_error("patch-aob requires --bytes (or defaults to --aob-pattern; both empty)");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process_memory_only(
			*options.pid, options.verify);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("AOB Scan");
		PT::Cli::print_named_value("Pattern length (bytes)", options.aob_pattern->size());

		auto hit_addr = aob_scan(process, *options.aob_pattern);
		if (!PT::Cli::run_step("Found pattern in target memory", hit_addr.has_value())) {
			return 1;
		}
		PT::Cli::print_named_hex("First match address", *hit_addr);

		PT::Cli::print_section("Patch Memory");
		PT::Cli::print_named_hex("Target address", *hit_addr);
		PT::Cli::print_named_value("Bytes to write", write_bytes.size());
		PT::Cli::print_named_value(
			"Toggle protection (RWX during write)",
			options.restore_protection ? "yes" : "no");

		auto outcome = PT::MemoryPatch::patch_bytes(
			process, *hit_addr, write_bytes, options.restore_protection);
		if (!PT::Cli::run_step("Wrote bytes to remote memory", outcome.has_value())) {
			return 1;
		}
		PT::Cli::print_named_value("Bytes written", outcome->bytes_written);

		if (options.verify) {
			PT::Cli::print_section("Verify");
			auto read_back = PT::MemoryPatch::read_bytes(
				process, *hit_addr, write_bytes.size());
			if (!PT::Cli::run_step("Read bytes back from target", read_back.has_value())) {
				return 1;
			}
			const bool match = (*read_back == write_bytes);
			if (!PT::Cli::run_step("Read-back matches requested patch", match)) {
				return 1;
			}
		}

		return 0;
	}

	int apc_inject(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("apc-inject requires --pid");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("Queue User APC");

		auto outcome = PT::ApcInjection::queue_apc(process, *options.pid);
		if (!PT::Cli::run_step("Allocated + wrote shellcode + queued APC", outcome.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("Trampoline base", outcome->trampoline_base);
		PT::Cli::print_named_hex("APC routine addr", outcome->apc_routine_addr);
		PT::Cli::print_named_hex("Counter addr", outcome->counter_addr);
		PT::Cli::print_named_value("Target thread ID", outcome->target_thread_id);

		if (options.verify) {
			PT::Cli::print_section("Verify");

			// APCs are pending until the target thread hits an alertable
			// wait. TestTarget uses SleepEx(TRUE) every 10ms so we usually
			// see a hit within the first iteration; give it a generous
			// window to accommodate slower callers. min_verify_hits==0 lets
			// the caller skip the runtime-firing check entirely, matching
			// hook-inline's semantics.
			if (options.min_verify_hits == 0) {
				PT::Cli::print_named_value(
					"Runtime-firing check", "skipped (--verify-hits 0)");
				return 0;
			}
			if (options.verify_wait_ms > 0) {
				Sleep(static_cast<DWORD>(options.verify_wait_ms));
			}
			auto counter = PT::ApcInjection::read_hit_counter(process, outcome->counter_addr);
			if (!PT::Cli::run_step("Read APC hit counter", counter.has_value())) {
				return 1;
			}
			PT::Cli::print_named_value("APC hits observed", *counter);
			const bool apc_fired =
				*counter >= static_cast<std::uint64_t>(options.min_verify_hits);
			if (!PT::Cli::run_step(
					std::format("APC fired at least {} time(s)", options.min_verify_hits),
					apc_fired)) {
				return 1;
			}
		}

		return 0;
	}

	int inject_manualmap(const Options& options) {
		if (!options.pid) {
			PT::Cli::print_error("inject-manualmap requires --pid");
			return 2;
		}
		if (!options.dll_path || options.dll_path->empty()) {
			PT::Cli::print_error("inject-manualmap requires --dll");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("Manual Map DLL");
		auto map_result = PT::DllInjection::inject_dll_manualmap(process, *options.dll_path);
		if (!PT::Cli::run_step("Manually mapped DLL", map_result.has_value())) {
			return 1;
		}

		PT::Cli::print_named_hex("Mapped image base", *map_result);

		if (!options.function_name) {
			return 0;
		}

		PT::Cli::print_section("Call Exported Function");
		const bool call_result = PT::DllInjection::call_exported_function(
			process,
			*options.dll_path,
			*map_result,
			*options.function_name
		);

		return PT::Cli::run_step(std::format("Called function {}", *options.function_name), call_result) ? 0 : 1;
	}
}

int wmain(int argc, wchar_t** argv) {
	PT::Cli::enable_ansi();

	if (argc < 2) {
		print_usage(argv[0]);
		return 2;
	}

	const std::wstring_view command{argv[1]};
	if (command == L"--help" || command == L"-h" || command == L"help") {
		print_usage(argv[0]);
		return 0;
	}

	if (command == L"list-processes") {
		return list_processes();
	}

	auto options = parse_options(argc, argv, 2);
	if (!options) {
		print_usage(argv[0]);
		return 2;
	}

	// RQ3 evasion: if --via-direct-syscall was set, resolve syscall
	// numbers from ntdll and enable the DirectSyscall dispatch layer.
	// Every subsequent cross-process primitive in Memory.cpp then
	// bypasses ntdll's exports and enters the kernel directly. Failure
	// to resolve is fatal for the run — a mixed-path run would confuse
	// the RQ3 tier-A vs tier-B comparison.
	if (options->via_direct_syscall) {
		if (!PT::DirectSyscall::Initialize()) {
			PT::Cli::print_error(
				"--via-direct-syscall requested but ntdll syscall-number "
				"resolution failed (likely EDR-style user-mode hook on the "
				"target stubs; see HalosGate for a fallback strategy).");
			return 3;
		}
		PT::DirectSyscall::SetEnabled(true);
		std::wcout << L"[+] Direct-syscall dispatch enabled (RQ3 evasion)\n";
	}

	// RQ3 diagnostic: install user-mode hooks on our own ntdll so we can
	// count how many times the attack code path would have been observable
	// to a user-mode-hooking EDR. Compare counts across --via-direct-syscall
	// on/off. Requires DirectSyscall to be initialized (probe forwards to
	// Direct_Nt* stubs to avoid recursing into its own hooks).
	if (options->observe_usermode_hooks) {
		if (!PT::DirectSyscall::IsResolved() && !PT::DirectSyscall::Initialize()) {
			PT::Cli::print_error(
				"--observe-usermode-hooks requested but DirectSyscall init failed.");
			return 3;
		}
		std::wstringstream log_path;
		log_path << L"usermode-hooks-"
		         << (options->pid ? *options->pid : 0) << L"-"
		         << GetCurrentProcessId() << L".log";
		if (!PT::UsermodeHookProbe::Install(log_path.str())) {
			PT::Cli::print_error(
				"--observe-usermode-hooks: probe install failed.");
			return 3;
		}
		// Zero the counters AFTER install so we ignore any invocations
		// that happened during startup / loader activity. Counts now
		// reflect only what the attack code triggers.
		PT::UsermodeHookProbe::ResetCounts();
		std::wcout << L"[+] User-mode hook probe installed (RQ3 diagnostic; log: "
		           << log_path.str() << L")\n";
	}

	// Helper: dispatch a subcommand by name. Returns the subcommand's
	// exit code, or -1 for "unknown command" (caller handles usage print).
	auto dispatch_command = [&](const std::wstring_view& c) -> int {
		if (c == L"inspect-memory")       return inspect_memory(*options);
		if (c == L"inject-loadlibrary")   return inject_loadlibrary(*options);
		if (c == L"inject-manualmap")     return inject_manualmap(*options);
		if (c == L"inject-threadhijack")  return inject_threadhijack(*options);
		if (c == L"patch-memory")         return patch_memory(*options);
		if (c == L"hook-inline")          return hook_inline(*options);
		if (c == L"hook-iat")             return hook_iat(*options);
		if (c == L"list-imports")         return list_imports(*options);
		if (c == L"apc-inject")           return apc_inject(*options);
		if (c == L"patch-aob")            return patch_aob(*options);
		return -1;  // sentinel for unknown-command handling below
	};

	int subcommand_rc = dispatch_command(command);

	// If the probe was installed, dump the counts before we return. This
	// runs whether the subcommand succeeded or not, so a partially-
	// completed attack still reports what user-mode hooks it fired.
	if (options->observe_usermode_hooks) {
		const auto& c = PT::UsermodeHookProbe::GetCounts();
		std::wcout << L"\n=== User-mode hook probe results ===\n"
		           << L"  NtOpenProcess:           " << c.NtOpenProcess.load() << L"\n"
		           << L"  NtAllocateVirtualMemory: " << c.NtAllocateVirtualMemory.load() << L"\n"
		           << L"  NtProtectVirtualMemory:  " << c.NtProtectVirtualMemory.load() << L"\n"
		           << L"  NtWriteVirtualMemory:    " << c.NtWriteVirtualMemory.load() << L"\n"
		           << L"  NtReadVirtualMemory:     " << c.NtReadVirtualMemory.load() << L"\n"
		           << L"  NtCreateThreadEx:        " << c.NtCreateThreadEx.load() << L"\n"
		           << L"  (log: " << PT::UsermodeHookProbe::GetLogPath() << L")\n"
		           << L"  log lines written:       " << PT::UsermodeHookProbe::GetLogLinesWritten() << L"\n"
		           << L"  log lines dropped:       " << PT::UsermodeHookProbe::GetLogLinesDropped() << L"\n";
		PT::UsermodeHookProbe::Uninstall();
	}

	if (subcommand_rc == -1) {
		std::wcerr << L"Unknown command: " << command << L'\n';
		print_usage(argv[0]);
		return 2;
	}
	return subcommand_rc;
}
