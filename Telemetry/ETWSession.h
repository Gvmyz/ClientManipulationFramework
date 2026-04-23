#pragma once

#include <string>
#include <windows.h>
#include <evntrace.h>

class ETWSession {
public:
	ETWSession();
	~ETWSession();

	void start();
	void stop();

private:
	void initialize_properties();

	std::wstring session_name_{L"PTSession"};
	TRACEHANDLE session_handle_{0};

	bool running_{false};
};