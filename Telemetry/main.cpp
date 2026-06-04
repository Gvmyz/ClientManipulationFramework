// Telemetry.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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

// One subscribed ETW provider. Telemetry can enable several of them on the same
// real-time session so a single run produces a merged trace. The friendly name
// is stamped onto every event the provider emits so downstream analysis can
// group / filter without round-tripping the GUID.
struct ProviderSpec {
	std::wstring guid_string;    // canonical {XXXXXXXX-XXXX-...} form
	GUID guid{};
	std::wstring name;           // friendly label, e.g. "KernelProcess", "Sysmon"
};

struct TelemetryConfig {
	std::vector<ProviderSpec> providers;
	std::wstring session_name{L"MyTestSession"};
	std::wstring output_path{L"telemetry.json"};
	ExperimentMetadata metadata{};
};

// Built-in friendly names for provider GUIDs we use ourselves. Lets a manifest
// say `providers: [{ "guid": "..." }]` without spelling out the name — Telemetry
// fills it in automatically if it recognizes the GUID. Comparison is
// case-insensitive on the GUID string form.
static const std::map<std::wstring, std::wstring>& known_provider_names() {
	static const std::map<std::wstring, std::wstring> table = {
		{ L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}", L"KernelProcess" },
		{ L"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", L"Sysmon" },
	};
	return table;
}

static std::wstring to_upper(std::wstring s) {
	for (auto& c : s) c = static_cast<wchar_t>(::towupper(c));
	return s;
}

static std::wstring lookup_known_name(const std::wstring& guid_string) {
	const auto upper = to_upper(guid_string);
	const auto& table = known_provider_names();
	const auto it = table.find(upper);
	return it == table.end() ? std::wstring{} : it->second;
}

// Format a GUID back to its canonical {XXXXXXXX-XXXX-...} string so we can use
// it as a map key for the per-event provider name lookup.
static std::wstring guid_to_string(const GUID& guid) {
	wchar_t buffer[64]{};
	const int written = StringFromGUID2(guid, buffer, _countof(buffer));
	return written > 0 ? std::wstring(buffer) : std::wstring{};
}

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
TelemetryConfig g_config{};

// GUID-string (uppercase, canonical) -> friendly provider name. Populated from
// g_config.providers after parse so OnEvent can stamp event.provider_name in
// constant time without iterating the providers vector for every event.
std::map<std::wstring, std::wstring> g_provider_name_by_guid;

void print_usage(const wchar_t* exe_name) {
	wprintf(
		L"Usage: %ls [<ProviderGuid>] [--provider GUID[:Name]] [--pid PID] [--name process.exe] "
		L"[--output path] [--session name] [--run-id id] [--label label] [--technique name] "
		L"[--target name] [--meta key=value]\n"
		L"\n"
		L"At least one provider must be supplied. A bare GUID as the first positional argument\n"
		L"is treated as one provider for backward compatibility; --provider can be repeated to\n"
		L"subscribe to several on the same session. Each provider may carry a friendly Name\n"
		L"(suffixed after a colon) that is stamped onto every event it emits. Built-in names\n"
		L"are used automatically for GUIDs Telemetry recognizes (KernelProcess, Sysmon).\n",
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

	// Stamp the friendly provider name on the event so downstream analysis can
	// group/filter by provider without rederiving it from the GUID. The lookup
	// table is built once at startup from g_config.providers.
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
	// ThreadStart / ThreadStop are live events.
	// ThreadDCStart / ThreadDCStop are rundown equivalents emitted for threads
	// that were already running when the ETW session subscribed.
	return event.task == L"ThreadStart" ||
		event.task == L"ThreadStop" ||
		event.name == L"ThreadStart" ||
		event.name == L"ThreadStop" ||
		event.name == L"ThreadDCStart" ||
		event.name == L"ThreadDCStop";
}

bool is_image_event(const TelemetryEvent& event) {
	// ImageLoad is the live event.
	// ImageDCStart is the rundown equivalent for modules already loaded when the
	// ETW session subscribed. Both carry the same payload (ImageBase, ImageSize, etc.)
	return event.task == L"ImageLoad" ||
		event.name == L"ImageLoad" ||
		event.name == L"ImageDCStart" ||
		event.opcode == L"Load" ||
		event.opcode == L"DCStart";
}

// Sysmon's ETW provider only emits events the operator opted into via
// sysmon-config.xml — its config file already does the filtering. So we admit
// every Sysmon event unconditionally; trying to second-guess it here would just
// drop the most interesting cross-process signals (ProcessAccess, etc.)
bool is_sysmon_event(const TelemetryEvent& event) {
	return event.provider_name == L"Sysmon";
}

bool should_log_event(const TelemetryEvent& event) {
	if (is_sysmon_event(event)) {
		return true;
	}
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

	// PID filter: applies to kernel-process events only. Sysmon events are
	// already filtered at the source by sysmon-config.xml (TargetImage matches
	// TestTarget.exe), and they record the cross-process source PID in their
	// header (e.g. ProcessAccess: header.ProcessId == ProcessToolkit, the
	// TARGET pid is in the properties). Applying the header-PID filter to
	// Sysmon events would drop exactly the cross-process events we care about.
	if (!is_sysmon_event(event) && g_filter.pid && g_filter.pid != event.pid) {
		return;
	}

	print_event(event);
	JsonLogger::instance().write_event(event);
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

// Parse "<GUID>" or "<GUID>:<Name>" into a ProviderSpec. The GUID must be in
// canonical curly-brace form ("{XXXXXXXX-XXXX-...}"). If a name is not given,
// fall back to the known_provider_names() table; if it is also not known, the
// provider name on emitted events will be empty (still usable, just unlabeled).
bool parse_provider_spec(const std::wstring& raw, ProviderSpec& spec) {
	const auto colon = raw.find(L':');
	const std::wstring guid_part = (colon == std::wstring::npos) ? raw : raw.substr(0, colon);
	const std::wstring name_part = (colon == std::wstring::npos) ? std::wstring{} : raw.substr(colon + 1);

	GUID parsed{};
	if (CLSIDFromString(guid_part.c_str(), &parsed) != S_OK) {
		return false;
	}
	spec.guid = parsed;
	spec.guid_string = guid_to_string(parsed);  // canonical re-formatting
	spec.name = name_part.empty() ? lookup_known_name(spec.guid_string) : name_part;
	return true;
}

bool parse_arguments(int argc, wchar_t* argv[]) {
	if (argc < 2) {
		print_usage(argv[0]);
		return false;
	}

	int next_arg = 1;

	// Backward compatibility: a bare GUID as argv[1] (not a --flag) is treated
	// as the first provider, so existing single-provider manifests keep working
	// without modification.
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
			std::wstring key;
			std::wstring value;
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

	// Build the GUID -> name map used by build_event for per-event labeling.
	for (const auto& p : g_config.providers) {
		g_provider_name_by_guid[to_upper(p.guid_string)] = p.name;
	}

	// Comma-join provider GUIDs into the legacy metadata field so existing
	// downstream tooling (which reads experiment.provider_guid) sees a stable
	// representation of the full multi-provider session.
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

	auto& logger = JsonLogger::init(g_config.output_path);
	logger.set_experiment_metadata(g_config.metadata);

	CONTROLTRACE_ID hTrace{0};
	std::size_t size = sizeof(EVENT_TRACE_PROPERTIES) + (g_config.session_name.size() + 1) * sizeof(wchar_t);
	auto buffer = std::make_unique<BYTE[]>(size);
	auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());
	memset(props, 0, size);

	props->Wnode.BufferSize = static_cast<ULONG>(size);
	props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	auto status = StartTraceW(&hTrace, g_config.session_name.c_str(), props);
	if (status == ERROR_ALREADY_EXISTS) {
		ControlTraceW(
			0,
			g_config.session_name.c_str(),
			props,
			EVENT_TRACE_CONTROL_STOP
		);

		// Re-initialize the properties structure after stopping the existing session
		memset(props, 0, size);
		props->Wnode.BufferSize = static_cast<ULONG>(size);
		props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

		status = StartTraceW(&hTrace, g_config.session_name.c_str(), props);
	}
	if (status != ERROR_SUCCESS) {
		printf("Failed to start trace session: %u\n", status);
		return status;
	}

	// Enable each requested provider on the shared session and request a state
	// snapshot (rundown) from it. Rundown matters for providers like
	// Microsoft-Windows-Kernel-Process: without it, ImageLoad/ThreadStart events
	// that fired before we subscribed are permanently lost. For Sysmon the
	// rundown is a no-op (its events are state changes, not enumerable state)
	// but issuing the call is harmless.
	for (const auto& provider : g_config.providers) {
		GUID guid_copy = provider.guid;  // EnableTraceEx2 takes a non-const pointer

		status = EnableTraceEx2(
			hTrace, &guid_copy, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
			TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr
		);
		if (status != ERROR_SUCCESS) {
			printf(
				"Failed to enable provider %ls (status %lu)\n",
				provider.guid_string.c_str(), status
			);
			return status;
		}

		EnableTraceEx2(
			hTrace, &guid_copy, EVENT_CONTROL_CODE_CAPTURE_STATE,
			TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr
		);

		const auto label = provider.name.empty() ? provider.guid_string : provider.name;
		wprintf(L"  enabled provider %ls (%ls)\n", label.c_str(), provider.guid_string.c_str());
	}

	wprintf(L"Telemetry started. %zu provider(s) enabled (rundown requested). Waiting for events...\n",
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

	ProcessTrace(&hParse, 1, nullptr, nullptr);
}
