
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

#include <Windows.h>

// noinline so the hook_inline experiments have a stable, out-of-line function
// entry to overwrite. With MSVC's whole-program optimisation the compiler
// otherwise inlines the body into main() and no call ever reaches the
// standalone `hello()` symbol whose address the sidecar advertises.
__declspec(noinline) void hello() {
	std::cout << "Hello from Target!" << std::endl;
}

// Dedicated hook target: pure register arithmetic so the first ~16 bytes are
// self-contained instructions with no RIP-relative operands. A cross-process
// inline hook that copies those bytes into a trampoline can execute them
// verbatim without a disassembler-based fixup pass. Called from the main
// loop through a volatile function pointer so MSVC can't inline it away.
extern "C" __declspec(noinline) std::uint64_t hookable_function(std::uint64_t a, std::uint64_t b) {
	std::uint64_t c = a * b;
	c ^= (a << 3);
	c += (b >> 2);
	c *= 0xDEADBEEFULL;
	c ^= 0xCAFEBABE12345678ULL;
	return c;
}

// Writes symbol addresses to a JSON sidecar so the runner can resolve manifest
// tokens like {targetInfo.value_addr} without scraping stdout.
void write_address_sidecar(const void* value_addr) {
	std::ostringstream filename;
	filename << "target-info-" << GetCurrentProcessId() << ".json";

	std::ofstream out(filename.str(), std::ios::trunc);
	if (!out) {
		return;
	}

	const auto to_hex = [](const void* p) {
		std::ostringstream os;
		os << "0x" << std::hex << std::uppercase << reinterpret_cast<std::uintptr_t>(p);
		return os.str();
	};

	out << "{\n"
		<< "  \"pid\": " << GetCurrentProcessId() << ",\n"
		<< "  \"value_addr\": \"" << to_hex(value_addr) << "\",\n"
		<< "  \"hello_addr\": \"" << to_hex(reinterpret_cast<const void*>(&hello)) << "\",\n"
		<< "  \"hookable_function_addr\": \"" << to_hex(reinterpret_cast<const void*>(&hookable_function)) << "\"\n"
		<< "}\n";
}


int main() {
	int value = 600;

	std::cout << "PID: " << GetCurrentProcessId() << std::endl;
	std::cout << "Address of value: " << &value << std::endl;
	std::cout << "Address of hello: " << hello << std::endl;
	std::cout << "Press SPACE to increment value\n";

	write_address_sidecar(&value);

	// Call hookable_function() periodically so hook_inline experiments can
	// observe the installed detour firing (via the trampoline's hit counter)
	// during the runner's cooldown window. Interval of ~100ms gives the
	// trampoline several opportunities to run per experiment. The volatile
	// function pointer prevents MSVC from inlining or constant-folding the
	// call so the standalone symbol's entry actually gets executed.
	static volatile auto fp = &hookable_function;
	static volatile std::uint64_t sink = 0;
	std::uint64_t tick = 0;
	while (true) {
		if (GetAsyncKeyState(VK_SPACE) & 1) {
			value++;
			std::cout << "Value: " << value << std::endl;
		}

		if ((++tick % 10) == 0) {
			sink = fp(tick, tick >> 1);
		}
		// Also call hello() periodically so hook_inline tests that target it
		// (RIP-relative + CALL rel32 in its prologue — the fixup-heavy case)
		// can observe the trampoline firing. Slower than hookable_function so
		// stdout doesn't get flooded.
		if ((tick % 100) == 0) {
			hello();
		}

		// SleepEx(ms, bAlertable=TRUE) instead of plain Sleep so the main
		// thread hits an alertable wait every ~10ms. Queued user-mode APCs
		// only fire when the target thread enters an alertable state; without
		// this, the apc_classic experiment queues a routine that never runs.
		// Return value is 0 for timeout and WAIT_IO_COMPLETION (192) when an
		// APC drained during the wait — we ignore it, the loop continues
		// either way.
		SleepEx(10, TRUE);
	}
}
