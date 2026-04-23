// Telemetry.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <windows.h>
#include <evntrace.h>
#include <stdio.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")

void WINAPI OnEvent(PEVENT_RECORD rec) {
	// Process the event record here
	const auto& header = rec->EventHeader;
	FILETIME ft{};
	FileTimeToLocalFileTime(
		reinterpret_cast<const FILETIME*>(&header.TimeStamp), &ft);
	SYSTEMTIME st{};
	FileTimeToSystemTime(&ft, &st);
	/*printf("[%02d:%02d:%02d.%03d] PID: %lu  TID: %lu\n",
		   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
		   header.ProcessId, header.ThreadId);*/

	ULONG buffer_size = 0;
	TdhGetEventInformation(rec, 0, nullptr, nullptr, &buffer_size);

	auto buffer = std::make_unique<BYTE[]>(buffer_size);
	auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());

	auto status = TdhGetEventInformation(rec, 0, nullptr, info, &buffer_size);

	if (info->TaskNameOffset) {
		auto task = reinterpret_cast<wchar_t*>(buffer.get() + info->TaskNameOffset);
		if (wcscmp(task, L"ProcessStart") != 0) {
			return;
			printf(" Process Start Event Detected!");
		}
	}

	if (status != ERROR_SUCCESS) {
		std::cerr << "Failed to get event information: " << status << std::endl;
		return;
	}

	printf("[%02d:%02d:%02d.%03d] PID: %lu  TID: %lu\n",
		   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
		   header.ProcessId, header.ThreadId);

	if (info->EventNameOffset) {
		auto name = reinterpret_cast<wchar_t*>(buffer.get() + info->EventNameOffset);
		printf(" Event Name: %ls", name);
	}
	if (info->KeywordsNameOffset) {
		auto keywords = reinterpret_cast<wchar_t*>(buffer.get() + info->KeywordsNameOffset);
		printf(" Keywords: %ls", keywords);
	}
	if (info->OpcodeNameOffset) {
		auto opcode = reinterpret_cast<wchar_t*>(buffer.get() + info->OpcodeNameOffset);
		printf(" Opcode: %ls", opcode);
	}
	if (info->TaskNameOffset) {
		auto task = reinterpret_cast<wchar_t*>(buffer.get() + info->TaskNameOffset);
		printf(" Task: %ls", task);
	}
	if (info->LevelNameOffset) {
		auto level = reinterpret_cast<wchar_t*>(buffer.get() + info->LevelNameOffset);
		printf(" Level: %ws", level);
	}
	printf("\n\n");

	auto len = rec->UserDataLength;
	auto data = reinterpret_cast<BYTE*>(rec->UserData);
	auto ptr_size = rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
	ULONG start = 0;

	WCHAR text[256];
	for (ULONG i = 0; i < info->TopLevelPropertyCount && len > 0; ++i) {
		EVENT_PROPERTY_INFO prop = info->EventPropertyInfoArray[i];
		auto prop_name = reinterpret_cast<wchar_t*>(buffer.get() + prop.NameOffset);
		printf("  Name: %ls ", prop_name);
		if (prop.Flags == 0) {
			ULONG text_len = _countof(text);
			USHORT consumed;
			if (ERROR_SUCCESS == TdhFormatProperty(info, nullptr, ptr_size, prop.nonStructType.InType, prop.nonStructType.OutType, prop.length, len, data, &text_len, text, &consumed)) {
				printf("%ls\n", text);
				data += consumed;
				len -= consumed;
			}
		}
	}
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc < 2) {
		printf("Usage: %ls <Guid>\n", argv[0]);
		return 1;
	}
	std::cout << "Hello World!\n";

	GUID guid;
	if (CLSIDFromString(argv[1], &guid) != S_OK) {
		printf("Invalid GUID format: %ls\n", argv[1]);
		return 1;
	}

	const std::wstring session_name = L"MyTestSession";
	CONTROLTRACE_ID hTrace{0};
	std::size_t size = sizeof(EVENT_TRACE_PROPERTIES) + (session_name.size() + 1) * sizeof(wchar_t);
	auto buffer = std::make_unique<BYTE[]>(size);
	auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());
	// Why use memset, in what context not needed to use?
	memset(props, 0, size);

	props->Wnode.BufferSize = static_cast<ULONG>(size);
	props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	auto status = StartTraceW(&hTrace, session_name.c_str(), props);
	if (status == ERROR_ALREADY_EXISTS) {
		ControlTraceW(hTrace, session_name.c_str(), props, EVENT_TRACE_CONTROL_STOP);

		// Re-initialize the properties structure after stopping the existing session
		memset(props, 0, size);
		props->Wnode.BufferSize = static_cast<ULONG>(size);
		props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

		status = StartTraceW(&hTrace, session_name.c_str(), props);
	}
	if (status != ERROR_SUCCESS) {
		printf("Failed to start trace session: %u\n", status);
		return status;
	}

	status = EnableTraceEx2(hTrace, &guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
	if (status != ERROR_SUCCESS) {
		printf("Failed to enable trace provider: %u\n", status);
		return status;
	}

	EVENT_TRACE_LOGFILEW etl = {};
	etl.LoggerName = const_cast<wchar_t*>(session_name.c_str());
	etl.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	etl.EventRecordCallback = OnEvent;
	auto hParse = OpenTraceW(&etl);

	if (hParse == INVALID_PROCESSTRACE_HANDLE) {
		printf("Failed to open trace: %u\n", GetLastError());
		return 1;
	}

	ProcessTrace(&hParse, 1, nullptr, nullptr);

	//CloseTrace(hParse);

	// 1) install shutdown handler
	// 2) create telemetry session object
	// 3) start ETW session
	// 4) enable one provider
	// 5) start consumer thread
	// 6) wait until user stops program
	// 7) stop session
	// 8) join consumer thread
	// 9) clean up
}