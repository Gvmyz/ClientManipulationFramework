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
	};

	void print_usage(const wchar_t* exe_name) {
		std::wcout
			<< L"Usage:\n"
			<< L"  " << exe_name << L" list-processes\n"
			<< L"  " << exe_name << L" inspect-memory --pid <pid> [--committed] [--private] [--executable]\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid <pid> --dll <path> [--module <name>] [--call <export>]\n\n"
			<< L"Examples:\n"
			<< L"  " << exe_name << L" list-processes\n"
			<< L"  " << exe_name << L" inspect-memory --pid 1234 --committed --executable\n"
			<< L"  " << exe_name << L" inject-loadlibrary --pid 1234 --dll C:\\path\\TestDll.dll --call RunTest\n";
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

	std::wcerr << L"Unknown command: " << command << L'\n';
	print_usage(argv[0]);
	return 2;
}
