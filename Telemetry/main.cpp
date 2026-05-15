// Telemetry.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include "JsonLogger.h"
#include <map>
#include <optional>

#pragma comment(lib, "tdh.lib")

// Use it later for filtering events based on process ID or name
// Extend it (Argument based)
struct TelemetryFilter {
	std::optional<DWORD> pid{std::nullopt};
	std::optional<std::wstring> process_name{std::nullopt};

	bool matches(const TelemetryEvent& e) const {
		if (pid && e.pid != *pid) {
			return false;
		}

		if (process_name) {
			if (e.process_name.empty()) {
				return false;
			}

			if (_wcsicmp(e.process_name.c_str(), process_name->c_str()) != 0) {
				return false;
			}
		}
		return true;
	}
};

TelemetryFilter g_filter{};



SYSTEMTIME filetime_to_systemtime(const FILETIME& ft) {
	SYSTEMTIME st{};
	FileTimeToSystemTime(&ft, &st);
	return st;
}

TelemetryEvent build_event(PEVENT_RECORD rec) {
	const auto& header = rec->EventHeader;
	TelemetryEvent event{};

	SYSTEMTIME st = filetime_to_systemtime(*reinterpret_cast<const FILETIME*>(&header.TimeStamp));
	event.utc_time = std::to_wstring(st.wYear) + L"-" +
		std::to_wstring(st.wMonth) + L"-" +
		std::to_wstring(st.wDay) + L" " +
		std::to_wstring(st.wHour) + L":" +
		std::to_wstring(st.wMinute) + L":" +
		std::to_wstring(st.wSecond) + L"." +
		std::to_wstring(st.wMilliseconds);
	event.pid = header.ProcessId;
	event.tid = header.ThreadId;

	ULONG buffer_size = 0;
	TdhGetEventInformation(rec, 0, nullptr, nullptr, &buffer_size);

	auto buffer = std::make_unique<BYTE[]>(buffer_size);
	auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());

	auto status = TdhGetEventInformation(rec, 0, nullptr, info, &buffer_size);
	if (status != ERROR_SUCCESS) {
		return event;
	}

	if (info->EventNameOffset) {
		event.name = reinterpret_cast<wchar_t*>(buffer.get() + info->EventNameOffset);
	}
	if (info->KeywordsNameOffset) {
		event.keywords = reinterpret_cast<wchar_t*>(buffer.get() + info->KeywordsNameOffset);
	}
	if (info->OpcodeNameOffset) {
		event.opcode = reinterpret_cast<wchar_t*>(buffer.get() + info->OpcodeNameOffset);
	}
	if (info->TaskNameOffset) {
		event.task = reinterpret_cast<wchar_t*>(buffer.get() + info->TaskNameOffset);
	}
	if (info->LevelNameOffset) {
		event.level = reinterpret_cast<wchar_t*>(buffer.get() + info->LevelNameOffset);
	}

	auto len = rec->UserDataLength;
	auto data = reinterpret_cast<BYTE*>(rec->UserData);
	auto ptr_size = rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;

	WCHAR text[256];
	for (ULONG i = 0; i < info->TopLevelPropertyCount && len > 0; ++i) {
		EVENT_PROPERTY_INFO prop = info->EventPropertyInfoArray[i];

		auto prop_name = reinterpret_cast<wchar_t*>(buffer.get() + prop.NameOffset);
		if (prop.Flags != 0) {
			continue;
		}

		ULONG text_len = _countof(text);
		USHORT consumed;

		status = TdhFormatProperty(info, nullptr, ptr_size, prop.nonStructType.InType, prop.nonStructType.OutType, prop.length, len, data, &text_len, text, &consumed);

		if (status == ERROR_SUCCESS) {
			event.properties[prop_name] = text;

			if (_wcsicmp(prop_name, L"ImageName") == 0 ||
				_wcsicmp(prop_name, L"FileName") == 0) {
				event.image_path = text;
			}

			if (_wcsicmp(prop_name, L"ProcessName") == 0 ||
				_wcsicmp(prop_name, L"ImageFileName") == 0) {
				event.process_name = text;
			}

			data += consumed;
			len -= consumed;
		}
	}
	return event;
}

bool is_process_start_event(const TelemetryEvent& event) {
	return wcscmp(event.task.c_str(), L"Process") == 0;
}

bool is_thread_event(const TelemetryEvent& event) {
	return event.task == L"ThreadStart" ||
		event.task == L"ThreadStop" ||
		event.name == L"ThreadStart" ||
		event.name == L"ThreadStop";
}

bool is_image_event(const TelemetryEvent& event) {
	return event.task == L"ImageLoad" ||
		event.name == L"ImageLoad" ||
		event.opcode == L"Load";
}

bool should_log_event(const TelemetryEvent& event) {
	return is_process_start_event(event) || is_thread_event(event) || is_image_event(event);
}

void print_event(const TelemetryEvent& event) {
	wprintf(
		L"%ls PID: %lu TID: %lu",
		event.utc_time.c_str(),
		event.pid,
		event.tid
	);

	if (!event.name.empty()) {
		wprintf(L" Event: %ls", event.name.c_str());
	}

	if (!event.task.empty()) {
		wprintf(L" Task: %ls", event.task.c_str());
	}

	if (!event.opcode.empty()) {
		wprintf(L" Opcode: %ls", event.opcode.c_str());
	}

	wprintf(L"\n");

	for (const auto& x : event.properties) {
		wprintf(L"  %ls: %ls\n", x.first.c_str(), x.second.c_str());
	}

	wprintf(L"\n");
}

void WINAPI OnEvent(PEVENT_RECORD rec) {
	auto event = build_event(rec);

	if (!should_log_event(event)) {
		return;
	}
	if (!g_filter.matches(event)) {
		return;
	}

	print_event(event);
	JsonLogger::instance().write_event(event);
}


int wmain(int argc, wchar_t* argv[]) {

	if (argc < 2) {
		wprintf(L"Usage: %ls <ProviderGuid> [--pid PID] [--name process.exe]\n", argv[0]);
		return 1;
	}

	// std::unordered_map<DWORD, std::wstring> pid_to_name;
	for (int i = 2; i < argc; ++i) {
		if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
			g_filter.pid = static_cast<DWORD>(std::wcstoul(argv[++i], nullptr, 10));
		} else if (wcscmp(argv[i], L"--name") == 0 && i + 1 < argc) {
			g_filter.process_name = argv[++i];
		} else {
			wprintf(L"Unknown argument: %ls\n", argv[i]);
			return 1;
		}
	}

	auto& logger = JsonLogger::init(L"telemetry.json");

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
}