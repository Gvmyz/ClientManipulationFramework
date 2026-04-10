#include <iostream>

#include <windows.h>
#include <psapi.h>

#include "inspector.h"
#include "window.h"
#include <vector>




int main(int charc, char** argv) {
	//return run(charc, argv); 
	using namespace std;
	std::cout << "Hello world" << std::endl;

	std::vector<DWORD> processes = inspector::enum_processes();

	// Print the name and process identifier for each process.
	for (auto p : processes) {
		if (p != 0) {
			inspector::print_process_name_and_id(p);
		}
	}

	//inspector::proc_inspect(15048);

	return 0;
}

