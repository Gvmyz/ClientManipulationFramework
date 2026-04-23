
#include <iostream>

#include <Windows.h>

void hello() {
	std::cout << "Hello from Target!\n";
}


int main() {
	int value = 600;

	std::cout << "PID: " << GetCurrentProcessId() << std::endl;
	std::cout << "Address of value: " << &value << std::endl;
	std::cout << "Address of hello: " << hello << std::endl;
	std::cout << "Press SPACE to increment value\n";

	while (true) {
		if (GetAsyncKeyState(VK_SPACE) & 1) {
			value++;
			std::cout << "Value: " << value << std::endl;
		}

		Sleep(10);
	}
}