#include <iostream>

#include <windows.h>
#include <psapi.h>

#include "inspector.h"
#include "window.h"





int main(int charc, char** argv) {
	return run(charc, argv);
	//using namespace std;
	//std::cout << "Hello world" << std::endl;

	//DWORD aProcesses[1024];
	//DWORD cbNeeded{ 0 };

	//if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
	//	cout << "Error while enumerating processes" << endl;
	//	return 1;
	//}

	//// Calculate how many process identifiers were returned.
	//DWORD cProcesses = cbNeeded / sizeof(DWORD);

	//// Print the name and process identifier for each process.
	//for (size_t i = 0; i < cProcesses; i++) {
	//	if (aProcesses[i] != 0) {
	//		// inspector::print_process_name_and_id(aProcesses[i]);
	//	}
	//}

	//inspector::proc_inspect(15048);

	//return 0;
}



// int hex_int = 0xff;
