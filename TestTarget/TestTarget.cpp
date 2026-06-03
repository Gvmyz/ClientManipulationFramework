
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

#include <Windows.h>

void hello() {
	std::cout << "Hello from Target!\n";
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
		<< "  \"hello_addr\": \"" << to_hex(reinterpret_cast<const void*>(&hello)) << "\"\n"
		<< "}\n";
}


int main() {
	int value = 600;

	std::cout << "PID: " << GetCurrentProcessId() << std::endl;
	std::cout << "Address of value: " << &value << std::endl;
	std::cout << "Address of hello: " << hello << std::endl;
	std::cout << "Press SPACE to increment value\n";

	write_address_sidecar(&value);

	while (true) {
		if (GetAsyncKeyState(VK_SPACE) & 1) {
			value++;
			std::cout << "Value: " << value << std::endl;
		}

		Sleep(10);
	}
}
