// Telemetry: ETW consumer that subscribes to one or more providers on a single
// real-time session and writes matching events to a JSONL file.

#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include "JsonLogger.h"

#pragma comment(lib, "tdh.lib")

#include <cstdio>
#include <cstdarg>

static std::wstring g_diag_path;
static void diag(const wchar_t* fmt, ...) {
	if (g_diag_path.empty()) return;
	FILE* f = nullptr;
	if (_wfopen_s(&f, g_diag_path.c_str(), L"a, ccs=UTF-8") != 0 || !f) return;
	va_list ap; va_start(ap, fmt); vfwprintf(f, fmt, ap); va_end(ap);
	fwprintf(f, L"\n"); fclose(f);
}
static long g_event_count = 0;

struct ProviderSpec {
	std::wstring guid_string;    // canonical {XXXXXXXX-XXXX-...} form
	GUID guid{};
	std::wstring name;           // friendly label, stamped onto every emitted event
};

struct TelemetryConfig {
	std::vector<ProviderSpec> providers;
	std::wstring session_name{L"MyTestSession"};
	std::wstring output_path{L"telemetry.json"};
	ExperimentMetadata metadata{};
};

// Built-in friendly names for the providers we use. Lets a manifest just say
// `{ "guid": "..." }` and have the name filled in automatically.
static const std::map<std::wstring, std::wstring>& known_provider_names() {
	static const std::map<std::wstring, std::wstring> table = {
		{ L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}", L"KernelProcess" },
		{ L"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", L"Sysmon" },
		{ L"{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}", L"ThreatIntelligence" },
	};
	return table;
}

static std::wstring to_upper(std::wstring s) {
	for (auto& c : s) c = static_cast<wchar_t>(::towupper(c));
	return s;
}

static std::wstring lookup_known_name(const std::wstring& guid_string) {
	const auto& table = known_provider_names();
	const auto it = table.find(to_upper(guid_string));
	return it == table.end() ? std::wstring{} : it->second;
}

static std::wstring guid_to_string(const GUID& guid) {
	wchar_t buffer[64]{};
	const int written = StringFromGUID2(guid, buffer, _countof(buffer));
	return written > 0 ? std::wstring(buffer) : std::wstring{};
}

struct TelemetryFilter {
	std::optional<DWORD> pid{std::nullopt};
	std::optional<std::wstring> process_name{std::nullopt};
};

TelemetryFilter g_filter{};
TelemetryConfig g_config{};

// GUID-string (uppercase) -> friendly provider name. Built once at startup
// from g_config.providers so OnEvent can stamp event.provider_name in O(log N).
std::map<std::wstring, std::wstring> g_provider_name_by_guid;

void print_usage(const wchar_t* exe_name) {
	wprintf(
		L"Usage: %ls [<ProviderGuid>] [--provider GUID[:Name]] [--pid PID] [--name process.exe] "
		L"[--output path] [--session name] [--run-id id] [--label label] [--technique name] "
		L"[--target name] [--meta key=value]\n"
		L"\n"
		L"At least one provider required. A bare GUID as the first positional arg is treated as\n"
		L"one provider (legacy form); --provider can be repeated to subscribe to several. Each\n"
		L"provider may carry a friendly Name after a colon; built-in names are used automatically\n"
		L"for known GUIDs (KernelProcess, Sysmon).\n",
		exe_name
	);
}

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

	const auto guid_string = to_upper(guid_to_string(header.ProviderId));
	const auto it = g_provider_name_by_guid.find(guid_string);
	if (it != g_provider_name_by_guid.end()) {
		event.provider_name = it->second;
	}

	ULONG buffer_size = 0;
	TdhGetEventInformation(rec, 0, nullptr, nullptr, &buffer_size);

	auto buffer = std::make_unique<BYTE[]>(buffer_size);
	auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());

	auto status = TdhGetEventInformation(rec, 0, nullptr, info, &buffer_size);
	if (status != ERROR_SUCCESS) {
		return event;
	}

	if (info->EventNameOffset)    event.name     = reinterpret_cast<wchar_t*>(buffer.get() + info->EventNameOffset);
	if (info->KeywordsNameOffset) event.keywords = reinterpret_cast<wchar_t*>(buffer.get() + info->KeywordsNameOffset);
	if (info->OpcodeNameOffset)   event.opcode   = reinterpret_cast<wchar_t*>(buffer.get() + info->OpcodeNameOffset);
	if (info->TaskNameOffset)     event.task     = reinterpret_cast<wchar_t*>(buffer.get() + info->TaskNameOffset);
	if (info->LevelNameOffset)    event.level    = reinterpret_cast<wchar_t*>(buffer.get() + info->LevelNameOffset);

	auto len = rec->UserDataLength;
	auto data = reinterpret_cast<BYTE*>(rec->UserData);
	auto ptr_size = rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;

	WCHAR text[256];
	for (ULONG i = 0; i < info->TopLevelPropertyCount && len > 0; ++i) {
		EVENT_PROPERTY_INFO prop = info->EventPropertyInfoArray[i];
		auto prop_name = reinterpret_cast<wchar_t*>(buffer.get() + prop.NameOffset);
		if (prop.Flags != 0) continue;

		ULONG text_len = _countof(text);
		USHORT consumed;
		status = TdhFormatProperty(info, nullptr, ptr_size, prop.nonStructType.InType,
			prop.nonStructType.OutType, prop.length, len, data, &text_len, text, &consumed);

		std::wstring v = text;
		v.erase(std::remove_if(v.begin(), v.end(),
			[](wchar_t c) { return c == 0x200E || c == 0x200F || (c >= 0x202A && c <= 0x202E); }), v.end());
		event.properties[prop_name] = v;

		if (status == ERROR_SUCCESS) {
			event.properties[prop_name] = text;

			if (_wcsicmp(prop_name, L"ImageName") == 0 || _wcsicmp(prop_name, L"FileName") == 0) {
				event.image_path = text;
			}
			if (_wcsicmp(prop_name, L"ProcessName") == 0 || _wcsicmp(prop_name, L"ImageFileName") == 0) {
				event.process_name = text;
			}

			data += consumed;
			len -= consumed;
		}
	}
	return event;
}

bool is_process_start_event(const TelemetryEvent& e) {
	return wcscmp(e.task.c_str(), L"Process") == 0;
}

// Live (ThreadStart/Stop) plus rundown (ThreadDCStart/Stop) for threads that
// were already running when the session subscribed.
bool is_thread_event(const TelemetryEvent& e) {
	return e.task == L"ThreadStart" || e.task == L"ThreadStop" ||
		e.name == L"ThreadStart" || e.name == L"ThreadStop" ||
		e.name == L"ThreadDCStart" || e.name == L"ThreadDCStop";
}

// Live ImageLoad plus rundown ImageDCStart for modules already loaded.
bool is_image_event(const TelemetryEvent& e) {
	return e.task == L"ImageLoad" || e.name == L"ImageLoad" || e.name == L"ImageDCStart" ||
		e.opcode == L"Load" || e.opcode == L"DCStart";
}

bool is_sysmon_event(const TelemetryEvent& e) {
	return e.provider_name == L"Sysmon";
}

bool is_threatint_event(const TelemetryEvent& e) {
	return e.provider_name == L"ThreatIntelligence";
}

// Sysmon events are pre-filtered by sysmon-config.xml at the source. Admit
// all of them; the kernel-process events still go through the type filter.
bool should_log_event(const TelemetryEvent& event) {
	if (is_sysmon_event(event)) return true;
	if (is_threatint_event(event)) return true; 
	return is_process_start_event(event) || is_thread_event(event) || is_image_event(event);
}

void print_event(const TelemetryEvent& event) {
	wprintf(L"%ls PID: %lu TID: %lu", event.utc_time.c_str(), event.pid, event.tid);
	if (!event.name.empty())   wprintf(L" Event: %ls", event.name.c_str());
	if (!event.task.empty())   wprintf(L" Task: %ls", event.task.c_str());
	if (!event.opcode.empty()) wprintf(L" Opcode: %ls", event.opcode.c_str());
	wprintf(L"\n");
	for (const auto& [k, v] : event.properties) {
		wprintf(L"  %ls: %ls\n", k.c_str(), v.c_str());
	}
	wprintf(L"\n");
}

void WINAPI OnEvent(PEVENT_RECORD rec) {
	auto event = build_event(rec);
	const bool keep = should_log_event(event);
	if (++g_event_count <= 50)
		diag(L"raw #%ld provider=[%ls] task=[%ls] keep=%d", g_event_count,
			event.provider_name.c_str(), event.task.c_str(), keep);
	if (!keep) return;
	if (!is_sysmon_event(event) && g_filter.pid && g_filter.pid != event.pid) return;
	const bool wrote = JsonLogger::instance().write_event(event);
	if (g_event_count <= 50) diag(L"   write -> %d", wrote);
}

bool parse_meta_argument(const std::wstring_view value, std::wstring& key, std::wstring& data) {
	const auto pos = value.find(L'=');
	if (pos == std::wstring_view::npos || pos == 0 || pos + 1 >= value.size()) {
		return false;
	}
	key = std::wstring(value.substr(0, pos));
	data = std::wstring(value.substr(pos + 1));
	return true;
}

bool parse_provider_spec(const std::wstring& raw, ProviderSpec& spec) {
	const auto colon = raw.find(L':');
	const std::wstring guid_part = (colon == std::wstring::npos) ? raw : raw.substr(0, colon);
	const std::wstring name_part = (colon == std::wstring::npos) ? std::wstring{} : raw.substr(colon + 1);

	GUID parsed{};
	if (CLSIDFromString(guid_part.c_str(), &parsed) != S_OK) return false;
	spec.guid = parsed;
	spec.guid_string = guid_to_string(parsed);
	spec.name = name_part.empty() ? lookup_known_name(spec.guid_string) : name_part;
	return true;
}

bool parse_arguments(int argc, wchar_t* argv[]) {
	if (argc < 2) {
		print_usage(argv[0]);
		return false;
	}

	int next_arg = 1;
	// Legacy form: bare GUID as argv[1].
	if (argv[1][0] == L'{') {
		ProviderSpec spec;
		if (!parse_provider_spec(argv[1], spec)) {
			wprintf(L"Invalid provider GUID: %ls\n", argv[1]);
			return false;
		}
		g_config.providers.push_back(std::move(spec));
		next_arg = 2;
	}

	for (int i = next_arg; i < argc; ++i) {
		if (wcscmp(argv[i], L"--provider") == 0 && i + 1 < argc) {
			ProviderSpec spec;
			if (!parse_provider_spec(argv[++i], spec)) {
				wprintf(L"Invalid --provider value: %ls\n", argv[i]);
				return false;
			}
			g_config.providers.push_back(std::move(spec));
		} else if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
			g_filter.pid = static_cast<DWORD>(std::wcstoul(argv[++i], nullptr, 10));
		} else if (wcscmp(argv[i], L"--name") == 0 && i + 1 < argc) {
			g_filter.process_name = argv[++i];
		} else if (wcscmp(argv[i], L"--output") == 0 && i + 1 < argc) {
			g_config.output_path = argv[++i];
		} else if (wcscmp(argv[i], L"--session") == 0 && i + 1 < argc) {
			g_config.session_name = argv[++i];
		} else if (wcscmp(argv[i], L"--run-id") == 0 && i + 1 < argc) {
			g_config.metadata.run_id = argv[++i];
		} else if (wcscmp(argv[i], L"--label") == 0 && i + 1 < argc) {
			g_config.metadata.label = argv[++i];
		} else if (wcscmp(argv[i], L"--technique") == 0 && i + 1 < argc) {
			g_config.metadata.technique = argv[++i];
		} else if (wcscmp(argv[i], L"--target") == 0 && i + 1 < argc) {
			g_config.metadata.target = argv[++i];
		} else if (wcscmp(argv[i], L"--meta") == 0 && i + 1 < argc) {
			std::wstring key, value;
			if (!parse_meta_argument(argv[++i], key, value)) {
				wprintf(L"Invalid --meta value: %ls\n", argv[i]);
				return false;
			}
			g_config.metadata.extra[key] = value;
		} else {
			wprintf(L"Unknown argument: %ls\n", argv[i]);
			print_usage(argv[0]);
			return false;
		}
	}

	if (g_config.providers.empty()) {
		wprintf(L"At least one provider is required (positional GUID or --provider).\n");
		print_usage(argv[0]);
		return false;
	}

	for (const auto& p : g_config.providers) {
		g_provider_name_by_guid[to_upper(p.guid_string)] = p.name;
	}

	std::wstring joined;
	for (const auto& p : g_config.providers) {
		if (!joined.empty()) joined += L",";
		joined += p.guid_string;
	}
	g_config.metadata.provider_guid = joined;
	g_config.metadata.session_name = g_config.session_name;
	g_config.metadata.output_path = g_config.output_path;
	g_config.metadata.filter_pid = g_filter.pid;
	g_config.metadata.filter_process_name = g_filter.process_name;
	return true;
}

int wmain(int argc, wchar_t* argv[]) {
	if (!parse_arguments(argc, argv)) {
		return 1;
	}
	wprintf(L"Arguments parsed...\n");

	g_diag_path = g_config.output_path + L".log";
	diag(L"=== run start: %zu provider(s) ===", g_config.providers.size());

	auto& logger = JsonLogger::init(g_config.output_path);
	logger.set_experiment_metadata(g_config.metadata);

	diag(L"logger is_open=%d", (int)logger.is_open());

	CONTROLTRACE_ID hTrace{0};
	std::size_t size = sizeof(EVENT_TRACE_PROPERTIES) + (g_config.session_name.size() + 1) * sizeof(wchar_t);
	auto buffer = std::make_unique<BYTE[]>(size);
	auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());
	memset(props, 0, size);

	props->Wnode.BufferSize = static_cast<ULONG>(size);
	props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	props->BufferSize = 64;   // KB per buffer
	props->MinimumBuffers = 8;
	props->MaximumBuffers = 32;
	props->FlushTimer = 1;    // deliver at least every 1s -> low latency

	auto status = StartTraceW(&hTrace, g_config.session_name.c_str(), props);
	if (status == ERROR_ALREADY_EXISTS) {
		ControlTraceW(0, g_config.session_name.c_str(), props, EVENT_TRACE_CONTROL_STOP);

		memset(props, 0, size);
		props->Wnode.BufferSize = static_cast<ULONG>(size);
		props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		props->BufferSize = 64;
		props->MinimumBuffers = 8;
		props->MaximumBuffers = 32;
		props->FlushTimer = 1;

		status = StartTraceW(&hTrace, g_config.session_name.c_str(), props);
	}
	if (status != ERROR_SUCCESS) {
		printf("Failed to start trace session: %u\n", status);
		return status;
	}

	// Enable each provider and request a rundown. The rundown matters for
	// kernel-process: it re-emits Image/Thread DCStart events for state that
	// existed before we subscribed. For Sysmon the rundown is a no-op but
	// the call is harmless.
	for (const auto& provider : g_config.providers) {
		GUID guid_copy = provider.guid;

		// ETW-TI gates its cross-process (REMOTE) events behind keywords; MatchAnyKeyword=0
		// delivers only a subset (the LOCAL self-allocs). Request every keyword category for
		// TI so the remote alloc/write/inject events are delivered. Other providers keep 0.
		ULONGLONG match_any = (provider.name == L"ThreatIntelligence")
			? 0xFFFFFFFFFFFFFFFFULL : 0ULL;

		status = EnableTraceEx2(hTrace, &guid_copy, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
			TRACE_LEVEL_VERBOSE, match_any, 0, 0, nullptr);

		diag(L"enable %ls status=%lu", provider.guid_string.c_str(), status);

		if (status != ERROR_SUCCESS) {
			printf("Failed to enable provider %ls (status %lu)\n",
				provider.guid_string.c_str(), status);
			return status;
		}

		EnableTraceEx2(hTrace, &guid_copy, EVENT_CONTROL_CODE_CAPTURE_STATE,
			TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);

		const auto label = provider.name.empty() ? provider.guid_string : provider.name;
		wprintf(L"  enabled provider %ls (%ls)\n", label.c_str(), provider.guid_string.c_str());
	}

	wprintf(L"Telemetry started. %zu provider(s) enabled. Waiting for events...\n",
		g_config.providers.size());

	EVENT_TRACE_LOGFILEW etl = {};
	etl.LoggerName = const_cast<wchar_t*>(g_config.session_name.c_str());
	etl.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	etl.EventRecordCallback = OnEvent;
	auto hParse = OpenTraceW(&etl);

	if (hParse == INVALID_PROCESSTRACE_HANDLE) {
		printf("Failed to open trace: %u\n", GetLastError());
		return 1;
	}

	diag(L"waiting for events...");

	ProcessTrace(&hParse, 1, nullptr, nullptr);
}
