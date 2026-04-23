#pragma once

#include <iostream>
#include <Windows.h>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <optional>

namespace PT::Cli {
	// ANSI colors
	inline constexpr const char* RESET = "\033[0m";
	inline constexpr const char* RED = "\033[31m";
	inline constexpr const char* GREEN = "\033[32m";
	inline constexpr const char* YELLOW = "\033[33m";
	inline constexpr const char* BOLD = "\033[1m";

	inline void print_success(std::string_view message) {
		std::cout << GREEN << "[+] " << message << RESET << '\n';
	}

	inline void print_error(std::string_view message) {
		std::cerr << RED << "[-] " << message << RESET << '\n';
	}

	inline void print_info(std::string_view message) {
		std::cout << YELLOW << "[*] " << message << RESET << '\n';
	}

	inline void print_section(std::string_view title) {
		std::cout << "\n=== " << title << " ===\n";
	}

	template <typename T>
	std::string to_hex(T value) {
		static_assert(std::is_integral_v<T> || std::is_pointer_v<T>,
					  "to_hex requires an integral or pointer type");

		std::ostringstream oss;
		oss << "0x" << std::hex << std::uppercase;

		if constexpr (std::is_pointer_v<T>) {
			oss << reinterpret_cast<std::uintptr_t>(value);
		} else {
			oss << static_cast<std::uintptr_t>(value);
		}

		return oss.str();
	}

	template <typename T>
	void print_named_value(std::string_view name, const T& value) {
		std::cout << "[*] " << name << ": " << value << '\n';
	}

	template <typename T>
	void print_named_hex(std::string_view name, T value) {
		std::cout << "[*] " << name << ": " << to_hex(value) << '\n';
	}

	inline void print_win32_error(std::string_view context, DWORD error = GetLastError()) {
		std::cerr << "[-] " << context << " failed (GetLastError=" << error << " / "
			<< to_hex(error) << ")\n";
	}

	template <typename T>
	bool require_value(const std::optional<T>& value, std::string_view error_message) {
		if (!value) {
			print_error(error_message);
			return false;
		}
		return true;
	}

	inline bool run_step(std::string_view name, bool ok) {
		if (ok) {
			print_success(name);
		} else {
			print_error(name);
		}
		return ok;
	}

	void enable_ansi() {
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hOut == INVALID_HANDLE_VALUE) return;

		DWORD mode = 0;
		if (!GetConsoleMode(hOut, &mode)) return;

		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		SetConsoleMode(hOut, mode);
	}
}
