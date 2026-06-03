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

#include "DllInjection.h"
#include "Memory.h"
#include "MemoryPatch.h"
#include "Process.h"
#include "ProcessMemory.h"
#include "Utils.h"

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
	};

	void print_usage(const wchar_t* exe_name) {
		std::wcout
			<< L"Usage:\n"
			<< L"  " << exe_name << L" list-processes\n"
			<< L"  " << exe_name << L" inspect-memory --pid <pid> [--committed] [--private] [--executable]\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid <pid> --dll <path> [--module <name>] [--call <export>]\n"
			<< L"  " << exe_name << L" inject-manualmap --pid <pid> --dll <path> [--call <export>]\n"
			<< L"  " << exe_name << L" inject-threadhijack --pid <pid> --dll <path> [--module <name>] [--call <export>]\n"
			<< L"  " << exe_name << L" patch-memory --pid <pid> --address <hex> --bytes <hex> [--restore-protection] [--verify]\n\n"
			<< L"Examples:\n"
			<< L"  " << exe_name << L" list-processes\n"
			<< L"  " << exe_name << L" inspect-memory --pid 1234 --committed --executable\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n"
			<< L"  " << exe_name << L" inject-manualmap --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n"
			<< L"  " << exe_name << L" inject-threadhijack --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n"
			<< L"  " << exe_name << L" patch-memory --pid 1234 --address 0x7FF6C0123ABC --bytes 0F270000 --verify\n";
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
			} else if (arg == L"--verify") {
				options.verify = true;
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
		if (!options.address) {
			PT::Cli::print_error("patch-memory requires --address");
			return 2;
		}
		if (!options.bytes || options.bytes->empty()) {
			PT::Cli::print_error("patch-memory requires --bytes");
			return 2;
		}

		PT::Cli::print_section("Open Target Process");
		auto process = PT::ProcessMemory::open_process(*options.pid);
		if (!PT::Cli::run_step(std::format("Opened process {}", *options.pid), process.valid())) {
			return 1;
		}

		PT::Cli::print_section("Patch Memory");
		PT::Cli::print_named_hex("Target address", *options.address);
		PT::Cli::print_named_value("Bytes to write", options.bytes->size());
		PT::Cli::print_named_value(
			"Toggle protection (RWX during write)",
			options.restore_protection ? "yes" : "no");

		auto outcome = PT::MemoryPatch::patch_bytes(
			process, *options.address, *options.bytes, options.restore_protection);

		if (!PT::Cli::run_step("Wrote bytes to remote memory", outcome.has_value())) {
			return 1;
		}

		PT::Cli::print_named_value("Bytes written", outcome->bytes_written);
		if (options.restore_protection) {
			PT::Cli::print_named_hex("Previous protection", outcome->previous_protection);
			PT::Cli::run_step("Restored previous protection", outcome->protection_restored);
		}

		if (options.verify) {
			PT::Cli::print_section("Verify");
			auto read_back = PT::MemoryPatch::read_bytes(
				process, *options.address, options.bytes->size());
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

	if (command == L"inspect-memory") {
		return inspect_memory(*options);
	}
	if (command == L"inject-loadlibrary") {
		return inject_loadlibrary(*options);
	}
	if (command == L"inject-manualmap") {
		return inject_manualmap(*options);
	}
	if (command == L"inject-threadhijack") {
		return inject_threadhijack(*options);
	}
	if (command == L"patch-memory") {
		return patch_memory(*options);
	}

	std::wcerr << L"Unknown command: " << command << L'\n';
	print_usage(argv[0]);
	return 2;
}
