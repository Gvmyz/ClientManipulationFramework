// ============================================================================
// Telemetry â€” ETW consumer that captures events into a JSONL file.
//
// WHAT ETW IS
// -----------
// Event Tracing for Windows (ETW) is Windows' kernel-mode event pipeline. It
// has three role players:
//
//   1. PROVIDER â€” a subsystem that emits typed events (e.g. the kernel's
//      Microsoft-Windows-Kernel-Process, Sysmon's driver, ThreatIntelligence).
//      Each provider is identified by a GUID. Providers emit events at a
//      LEVEL (Info, Verbose, ...) and tagged with KEYWORDS (bitmask that
//      groups events by category â€” a provider decides its own keyword meaning).
//
//   2. SESSION â€” a kernel-owned buffer pool that collects events from one or
//      more enabled providers. Sessions have names ("TISession" for us). Only
//      one session per name at a time.
//
//   3. CONSUMER â€” a user-mode process (this one) that opens the session and
//      is called back once per event. Consumers cannot decide what a provider
//      emits; they only choose which providers to enable and with what
//      level/keywords.
//
// DATA FLOW IN THIS PROGRAM
// -------------------------
//   parse_arguments()  ->  build g_config (providers, filters, metadata)
//        |
//   StartTraceW        ->  create/reuse the ETW session
//        |
//   EnableTraceEx2     ->  for each provider: subscribe with keyword mask.
//                          Also request CAPTURE_STATE = "rundown": have the
//                          kernel re-emit the state that already existed at
//                          subscription time (existing modules, threads).
//        |
//   enable_vm_logging_for_pid  ->  for each --enable-vm-logging-pid, call
//                                  NtSetInformationProcess to opt the target
//                                  into ETW-TI READVM/WRITEVM events.
//                                  Requires the caller to be PPL-Antimalware.
//        |
//   OpenTraceW         ->  attach the OnEvent callback to the session
//        |
//   ProcessTrace       ->  BLOCKING: drives the event loop. For each event
//                          buffered in the session:
//                              OnEvent(EVENT_RECORD*)  ->
//                                  build_event()          # decode TDH properties
//                                  should_log_event()     # class filter
//                                  JsonLogger::write_event()  # append JSONL
//                          Runs until the session is stopped externally
//                          (PPLRunner drops stop.flag).
//
// PPL / ETW-TI SPECIFIC
// ---------------------
// The ThreatIntelligence provider ("TI") has two event types (READVM, WRITEVM)
// that are OFF SYSTEM-WIDE by default. They only get emitted for target
// processes explicitly opted in via ProcessEnableReadWriteVmLogging, and that
// opt-in call only succeeds if THIS consumer is running with PPL-Antimalware
// protection. That's why Telemetry.exe must be launched under PPLRunner (a
// separate service configured for SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT
// and signed by the ELAM certificate).
//
// All other TI events (ALLOCVM, PROTECTVM, SETTHREADCONTEXT, MAPVIEW, ...)
// fire regardless of opt-in, provided we subscribe with a broad keyword mask.
// ============================================================================

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
#include "EventDecoder.h"

#pragma comment(lib, "tdh.lib")

#include <cstdio>
#include <cstdarg>

// ----------------------------------------------------------------------------
// Diagnostic log.
// ----------------------------------------------------------------------------
// The JSONL output is data for the analysis pipeline. Anything we want to see
// about the RUN itself â€” PPL opt-in status, first-50-events trace, provider
// enable results â€” goes into a separate ".log" file living next to the JSONL.
// The path is set by wmain() to `<output_path>.log`. Written UTF-8, appended.
// PPLRunner copies this file into the run directory as `telemetry.log` so it
// travels with the manifest and JSONL.
static std::wstring g_diag_path;
static void diag(const wchar_t* fmt, ...) {
	if (g_diag_path.empty()) return;
	FILE* f = nullptr;
	if (_wfopen_s(&f, g_diag_path.c_str(), L"a, ccs=UTF-8") != 0 || !f) return;
	va_list ap; va_start(ap, fmt); vfwprintf(f, fmt, ap); va_end(ap);
	fwprintf(f, L"\n"); fclose(f);
}

// Rolling counter used to cap noisy per-event diag lines to the first 50 events.
static long g_event_count = 0;

// ----------------------------------------------------------------------------
// Configuration types.
// ----------------------------------------------------------------------------

// One provider we've been asked to subscribe to.
struct ProviderSpec {
	std::wstring guid_string;    // canonical `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` form
	GUID guid{};                 // parsed binary GUID (what EnableTraceEx2 wants)
	std::wstring name;           // friendly label ("KernelProcess", "Sysmon", ...)
	                             // stamped onto every emitted event so the loader
	                             // can dispatch without re-comparing GUIDs.
};

// Full run configuration built from the command line.
struct TelemetryConfig {
	std::vector<ProviderSpec> providers;   // all --provider entries + any legacy positional GUID
	std::wstring session_name{L"MyTestSession"};  // ETW session name (overridable via --session)
	std::wstring output_path{L"telemetry.json"};  // JSONL destination
	std::vector<DWORD> vm_logging_pids;    // --enable-vm-logging-pid targets (see PPL note above)
	ExperimentMetadata metadata{};         // run_id / label / technique / target / extra{}
	                                       // Written into every event's `experiment` envelope.
};

// ----------------------------------------------------------------------------
// PPL vm-logging opt-in.
// ----------------------------------------------------------------------------
// The single hardest thing this program does. To get ETW-TI's cross-process
// READVM/WRITEVM events for a given target process, that target must be
// flagged in the kernel with `ProcessEnableReadWriteVmLogging`. Only a
// PPL-Antimalware caller can set this flag; a normal-integrity process gets
// STATUS_ACCESS_DENIED (0xC0000022).
//
// The class number (87) and struct are not in the public SDK headers; they're
// documented in the leaked ntoskrnl symbols and reverse-engineered Windows
// research. `ProcessInformationClass::ProcessEnableReadWriteVmLogging = 87`.
//
// This function is a no-op for the other TI event types (ALLOCVM,
// PROTECTVM, SETTHREADCONTEXT, MAPVIEW, ...) â€” those fire once a PPL consumer
// subscribes with the right keyword mask, regardless of per-target opt-in.
// This is exclusively about READVM/WRITEVM.
//
// Diag interpretation:
//   status = 0            -> STATUS_SUCCESS. READVM/WRITEVM enabled for this pid.
//   status = 0xC0000022   -> STATUS_ACCESS_DENIED. This process is not PPL-AM.
//                            Common when Telemetry.exe is launched directly
//                            instead of via PPLRunner.
//   status = 0xC0000008   -> STATUS_INVALID_HANDLE. The PID exited before we
//                            reached this call. Race condition.
static void enable_vm_logging_for_pid(DWORD pid) {
	constexpr ULONG ProcessEnableReadWriteVmLogging = 87;  // PROCESSINFOCLASS index

	// The kernel struct is a single byte with two 1-bit flags. Higher bits are
	// reserved/unused â€” passing 0xFF (all bits set) is undefined behavior and
	// may fail on future Windows versions. Setting exactly what we need is safe.
	struct ReadWriteVmLoggingInfo {
		union {
			UCHAR Flags;
			struct {
				UCHAR EnableReadVmLogging  : 1;
				UCHAR EnableWriteVmLogging : 1;
				UCHAR Unused               : 6;
			};
		};
	};
	using NtSetInformationProcessFn = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG);

	// NtSetInformationProcess is an internal ntdll export; it's not in kernel32
	// so we resolve it dynamically. If ntdll isn't loaded (impossible in
	// practice) we bail without touching the target.
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto pNtSetInformationProcess = reinterpret_cast<NtSetInformationProcessFn>(
		ntdll ? GetProcAddress(ntdll, "NtSetInformationProcess") : nullptr);
	if (!pNtSetInformationProcess) {
		diag(L"vm-logging pid=%lu: NtSetInformationProcess resolve failed", pid);
		return;
	}

	// PROCESS_SET_INFORMATION is the minimum right needed to call
	// NtSetInformationProcess. As a Sysmon-10 side effect this OpenProcess is
	// visible in the run â€” mask 0x2200 (SET_INFORMATION | SET_LIMITED_INFORMATION).
	// It's the ONLY Sysmon-10 event a truly-quiet baseline run captures.
	HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
	if (!h) {
		diag(L"vm-logging pid=%lu: OpenProcess failed gle=%lu", pid, GetLastError());
		return;
	}

	ReadWriteVmLoggingInfo info{};
	info.EnableReadVmLogging  = 1;
	info.EnableWriteVmLogging = 1;
	LONG status = pNtSetInformationProcess(h, ProcessEnableReadWriteVmLogging, &info, sizeof(info));
	CloseHandle(h);

	diag(L"vm-logging pid=%lu status=0x%08lx (0 = STATUS_SUCCESS; C0000022 = ACCESS_DENIED, "
		L"means consumer is not PPL-Antimalware)", pid, (unsigned long)status);
}

// ----------------------------------------------------------------------------
// Provider name resolution.
// ----------------------------------------------------------------------------
// Manifests can specify a provider two ways:
//   { "guid": "{...}", "name": "MyLabel" }   -- explicit name
//   { "guid": "{...}" }                       -- name looked up here
// The friendly name ends up in every event's `provider_name` field, which the
// Python loader uses to dispatch. We keep this table small on purpose: only
// the three providers used by the current study. Adding a new provider means
// adding one line here (plus updating the analysis pipeline to know about it).
static const std::map<std::wstring, std::wstring>& known_provider_names() {
	static const std::map<std::wstring, std::wstring> table = {
		{ L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}", L"KernelProcess" },       // Microsoft-Windows-Kernel-Process
		{ L"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", L"Sysmon" },              // Sysmon service (schema 4.90+)
		{ L"{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}", L"ThreatIntelligence" },  // Microsoft-Windows-Threat-Intelligence
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

// ----------------------------------------------------------------------------
// Consumer-side event filtering.
// ----------------------------------------------------------------------------
// Applied AFTER TDH decodes each event but BEFORE we write it to JSONL. If
// only --pid P is set, kernel-process events with header pid != P are dropped
// (with an exemption for Sysmon events, whose header pid is Sysmon's service
// PID, not the caller PID). --name is declared but not currently enforced.
//
// NOTE: this is a coarse filter. For per-pid ETW filtering you'd use
// EnableTraceEx2's payload filters; that requires per-provider schema
// knowledge and is not used here.
struct TelemetryFilter {
	std::optional<DWORD> pid{std::nullopt};
	std::optional<std::wstring> process_name{std::nullopt};
};

// Global state. Everything ETW-related is single-instance per process â€” the
// callback signature has no user data pointer, so these have to be globals
// (or wrapped in an accessor singleton, which we don't bother with).
TelemetryFilter g_filter{};
TelemetryConfig g_config{};

// GUID-string (uppercase) -> friendly provider name. Built once at startup
// from g_config.providers so OnEvent can stamp event.provider_name in O(log N).
std::map<std::wstring, std::wstring> g_provider_name_by_guid;

void print_usage(const wchar_t* exe_name) {
	wprintf(
		L"Usage: %ls [<ProviderGuid>] [--provider GUID[:Name]] [--pid PID] [--name process.exe] "
		L"[--output path] [--session name] [--enable-vm-logging-pid PID] [--run-id id] "
		L"[--label label] [--technique name] [--target name] [--meta key=value]\n"
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

// ----------------------------------------------------------------------------
// build_event â€” turn an ETW record into a TelemetryEvent we can serialize.
// ----------------------------------------------------------------------------
// Called once per event by the ETW runtime. `rec` is a live pointer into the
// session buffer and is valid only for the duration of this call â€” do NOT
// hold onto it or its inner pointers after returning.
//
// Two decode phases:
//   PHASE 1 â€” envelope: copy scalar fields directly from EVENT_HEADER
//     (timestamp, pid, tid, provider GUID).
//   PHASE 2 â€” event schema: ask TDH (Trace Data Helper) to describe the
//     event's user-data layout (task name, keywords, property list),
//     then walk the property array and format each into a wide string.
//
// Decoder v2 uses independent TDH property queries and records errors explicitly.
TelemetryEvent build_event(PEVENT_RECORD rec) {
	const auto& header = rec->EventHeader;
	TelemetryEvent event{};

	// --- Phase 1: envelope (always available regardless of TDH) ---

    SYSTEMTIME st = filetime_to_systemtime(*reinterpret_cast<const FILETIME*>(&header.TimeStamp));
    wchar_t timestamp[40]{};
    swprintf_s(timestamp, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    event.utc_time = timestamp;
    event.event_id = header.EventDescriptor.Id;
    event.event_version = header.EventDescriptor.Version;
    event.header_flags = header.Flags;
    event.provider_guid = guid_to_string(header.ProviderId);

	// The event-header pid/tid is the PROCESS THAT EMITTED THE EVENT, not
	// necessarily the process the event is *about*. For a Sysmon-10
	// ProcessAccess, this is Sysmon's service PID; the actual actors are in
	// the properties as SourceProcessId/TargetProcessId.
	event.pid = header.ProcessId;
	event.tid = header.ThreadId;

	// Look up the friendly provider name (built once in parse_arguments()).
	// Unknown GUIDs get empty provider_name â€” the Python loader will default
	// them to "KernelProcess" for backward compat.
	const auto guid_string = to_upper(guid_to_string(header.ProviderId));
	const auto it = g_provider_name_by_guid.find(guid_string);
	if (it != g_provider_name_by_guid.end()) {
		event.provider_name = it->second;
	}

	// --- Phase 2: TDH schema decode ---

	// Two-call idiom used everywhere in the Windows API:
	//   1st call with nullptr buffer -> returns required size in buffer_size.
	//   2nd call with allocated buffer -> fills TRACE_EVENT_INFO.
	// TRACE_EVENT_INFO holds string tables (task name, keyword name, ...) and
	// an array of property descriptors (EVENT_PROPERTY_INFO), all with offsets
	// into the same buffer.
	ULONG buffer_size = 0;
	TdhGetEventInformation(rec, 0, nullptr, nullptr, &buffer_size);

	auto buffer = std::make_unique<BYTE[]>(buffer_size);
	auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());

	auto status = TdhGetEventInformation(rec, 0, nullptr, info, &buffer_size);
	if (status != ERROR_SUCCESS) {
		// Providers with no registered manifest (some custom TraceLogging ones)
		// return here. We keep the envelope but lose all named metadata and
		// properties. Rare on the three providers we use.
        event.decode_errors[L"event_schema"] = std::to_wstring(status);
        PreserveFailedEventData(rec, event);
        return event;
    }

	// Copy the named-metadata strings out of the schema. Offsets are 0 when
	// the provider didn't define that field.
	if (info->EventNameOffset)    event.name     = reinterpret_cast<wchar_t*>(buffer.get() + info->EventNameOffset);
	if (info->KeywordsNameOffset) event.keywords = reinterpret_cast<wchar_t*>(buffer.get() + info->KeywordsNameOffset);
	if (info->OpcodeNameOffset)   event.opcode   = reinterpret_cast<wchar_t*>(buffer.get() + info->OpcodeNameOffset);
	if (info->TaskNameOffset)     event.task     = reinterpret_cast<wchar_t*>(buffer.get() + info->TaskNameOffset);
	if (info->LevelNameOffset)    event.level    = reinterpret_cast<wchar_t*>(buffer.get() + info->LevelNameOffset);

    DecodeEventProperties(rec, info, event);
    PreserveFailedEventData(rec, event);
	return event;
}

// ----------------------------------------------------------------------------
// Event classification helpers.
// ----------------------------------------------------------------------------
// Providers use different naming conventions:
//   - Some populate `task` (from `<task>` in the manifest).
//   - Some populate `name` (from `<event name>`).
//   - Some populate `opcode` (Start/Stop/DCStart/DCEnd).
// So the classifiers below check MULTIPLE fields to catch every casing a
// provider might emit. The "DC" prefix means "Data Collection", i.e. rundown
// events emitted at CAPTURE_STATE time for state that already existed.

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

// Whole-provider passthroughs: for Sysmon we admit every event (Sysmon
// already pre-filters at emission time via sysmon-config.xml); for TI we
// admit every event (all TI event types are potentially interesting for
// injection detection).
bool is_sysmon_event(const TelemetryEvent& e) {
	return e.provider_name == L"Sysmon";
}

bool is_threatint_event(const TelemetryEvent& e) {
	return e.provider_name == L"ThreatIntelligence";
}

// The consumer-side "keep or discard" filter. Runs AFTER build_event() but
// BEFORE JSON emission. Rules:
//   - Sysmon:           always keep (pre-filtered at source)
//   - ThreatIntelligence: always keep (per-event usefulness decided in analysis)
//   - KernelProcess:    keep only process-start, thread lifecycle, and
//                       image-load events; discard rundowns of everything else.
//
// If you subscribe to a new provider, add an is_*_event helper and admit it
// here â€” otherwise its events land in the trace but never in the JSONL.
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

// ----------------------------------------------------------------------------
// OnEvent â€” the ETW callback.
// ----------------------------------------------------------------------------
// Called once per event by ProcessTrace() from a worker thread the runtime
// owns. Must return quickly: while we're inside OnEvent the session cannot
// drain more buffers, and slow consumers cause EventsLost.
//
// PIPELINE:
//   1. Decode the event (build_event).
//   2. Diag-log the first 50 raw events so we can see subscription is live.
//   3. Class filter (should_log_event) â€” mostly a passthrough for our providers.
//   4. Optional pid filter (--pid). Sysmon events bypass this because the
//      Sysmon event header pid is the Sysmon service, not the actor.
//   5. Serialize + append to JSONL.
static unsigned long long g_decode_error_events = 0;
static unsigned long long g_write_error_events = 0;
void WINAPI OnEvent(PEVENT_RECORD rec) {
	auto event = build_event(rec);
    if (!event.decode_errors.empty()) ++g_decode_error_events;
	const bool keep = should_log_event(event) || !event.decode_errors.empty();

	// First-50 trace is invaluable when subscription looks empty ("nothing
	// arrives") â€” it tells you whether events are arriving at all vs being
	// filtered out. After the 50-cap the cost stays flat.
	if (++g_event_count <= 50)
		diag(L"raw #%ld provider=[%ls] task=[%ls] keep=%d", g_event_count,
			event.provider_name.c_str(), event.task.c_str(), keep);

	if (!keep) return;

	// --pid filter: only kernel-process events go through here. Sysmon events
	// have Sysmon-service pid in the header so they'd all be filtered out;
	// TI cross-process events also have "wrong" pids (e.g. System pid for
	// SETTHREADCONTEXT_REMOTE), so we let TI pass too via the same exemption.
	if (!is_sysmon_event(event) && g_filter.pid && g_filter.pid != event.pid) return;

	const bool wrote = JsonLogger::instance().write_event(event);
    if (!wrote) ++g_write_error_events;
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
		} else if (wcscmp(argv[i], L"--enable-vm-logging-pid") == 0 && i + 1 < argc) {
			g_config.vm_logging_pids.push_back(
				static_cast<DWORD>(std::wcstoul(argv[++i], nullptr, 10)));
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

// ============================================================================
// wmain â€” orchestrates the whole run.
//
// Sequence:
//   1. parse_arguments()          -> populate g_config, g_filter
//   2. diag log + JsonLogger init -> so any subsequent failure is logged
//   3. Start / recover the ETW session (StartTraceW)
//   4. Enable each provider on the session (EnableTraceEx2 twice per provider)
//   5. Opt requested target PIDs into ETW-TI READVM/WRITEVM
//   6. OpenTrace + ProcessTrace   -> blocking event loop until session stops
//
// Exit: ProcessTrace only returns when the session is STOPPED externally
// (PPLRunner drops stop.flag, which triggers ControlTraceW STOP). There is
// no clean exit on failure inside the loop â€” that would need a control
// handler which we don't implement here.
// ============================================================================
int wmain(int argc, wchar_t* argv[]) {
    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) { wprintf(L"CMF Telemetry decoder_version=2\n"); return 0; }

	// -- Step 1: parse CLI --
	if (!parse_arguments(argc, argv)) {
		return 1;
	}
	wprintf(L"Arguments parsed...\n");

	// -- Step 2: init diag + JSONL logger --
	// Diag path is co-located with the JSONL so PPLRunner can copy both.
	g_diag_path = g_config.output_path + L".log";
	diag(L"=== run start: %zu provider(s) ===", g_config.providers.size());

	auto& logger = JsonLogger::init(g_config.output_path);
	logger.set_experiment_metadata(g_config.metadata);

	diag(L"logger is_open=%d", (int)logger.is_open());

	// -- Step 3: start (or recover) the ETW session --
	//
	// EVENT_TRACE_PROPERTIES has a trailing session-name string in the same
	// allocation. Layout: [ EVENT_TRACE_PROPERTIES | session_name (wchar[]) ].
	// LoggerNameOffset is the byte offset from `props` to the start of the
	// name. `size` is the total.
	CONTROLTRACE_ID hTrace{0};
	std::size_t size = sizeof(EVENT_TRACE_PROPERTIES) + (g_config.session_name.size() + 1) * sizeof(wchar_t);
	auto buffer = std::make_unique<BYTE[]>(size);
	auto props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());
	memset(props, 0, size);

	props->Wnode.BufferSize   = static_cast<ULONG>(size);
	props->LogFileMode        = EVENT_TRACE_REAL_TIME_MODE;  // no file, callback-driven
	props->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);
	props->BufferSize         = 64;   // KB per buffer. Larger = fewer FlushTimer wakes, higher latency.
	props->MinimumBuffers     = 8;    // 8 * 64 KB = 512 KB minimum session pool.
	props->MaximumBuffers     = 32;   // 32 * 64 KB = 2 MB. Beyond this the runtime drops events.
	props->FlushTimer         = 1;    // 1s. Bursty providers benefit from smaller; we prefer low latency.

	auto status = StartTraceW(&hTrace, g_config.session_name.c_str(), props);
	if (status == ERROR_ALREADY_EXISTS) {
		// A previous run left the session up (crashed, killed, whatever).
		// Stop the dangling one and try again with a fresh property block.
		// The re-memset + re-init is needed because ControlTraceW writes
		// back into `props`. If we didn't reset we'd get invalid buffer
		// sizes / offsets on the second StartTraceW.
		ControlTraceW(0, g_config.session_name.c_str(), props, EVENT_TRACE_CONTROL_STOP);

		memset(props, 0, size);
		props->Wnode.BufferSize = static_cast<ULONG>(size);
		props->LogFileMode      = EVENT_TRACE_REAL_TIME_MODE;
		props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		props->BufferSize       = 64;
		props->MinimumBuffers   = 8;
		props->MaximumBuffers   = 32;
		props->FlushTimer       = 1;

		status = StartTraceW(&hTrace, g_config.session_name.c_str(), props);
		// REFACTOR CANDIDATE: the six lines above duplicate the ones above
		// StartTraceW. Extract into a small helper `configure_props(props, size)`.
	}
	if (status != ERROR_SUCCESS) {
		printf("Failed to start trace session: %u\n", status);
		return status;
	}

	// -- Step 4: enable providers on the session --
	//
	// Two EnableTraceEx2 calls per provider:
	//   (a) ENABLE_PROVIDER  â€” start receiving live events at the requested
	//       level and keyword mask.
	//   (b) CAPTURE_STATE    â€” request a "rundown": the kernel re-emits events
	//       for state that ALREADY exists (currently-loaded modules,
	//       currently-running threads). Only meaningful for kernel-process;
	//       Sysmon/TI ignore the request but the call is harmless.
	//
	// Rundowns matter for our analysis: without them, ImageLoad events for a
	// target's already-loaded DLLs never appear, and the orphan-thread
	// detector would misclassify existing threads whose Win32StartAddr sits
	// inside those unseen modules.
	for (const auto& provider : g_config.providers) {
		GUID guid_copy = provider.guid;  // EnableTraceEx2 takes non-const GUID*

		// KEYWORD MASK RATIONALE:
		//   Providers use keywords as event categories. MatchAnyKeyword=0
		//   often means "deliver only events with no keyword" â€” the default
		//   category. TI in particular gates cross-process (REMOTE) events
		//   behind specific keywords; with MatchAnyKeyword=0 we'd get the
		//   local self-alloc events and miss the injection signals.
		//   0xFFFF...FFFF = "give me every keyword-category you have".
		//
		//   Sysmon and kernel-process don't need this â€” they emit their events
		//   at MatchAnyKeyword=0 by default.
		ULONGLONG match_any = (provider.name == L"ThreatIntelligence")
			? 0xFFFFFFFFFFFFFFFFULL : 0ULL;

		status = EnableTraceEx2(hTrace, &guid_copy, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
			TRACE_LEVEL_VERBOSE,   // deliver every level from Critical..Verbose
			match_any,
			0,                     // MatchAllKeyword â€” 0 = don't further restrict
			0,                     // Timeout in ms â€” 0 = async
			nullptr);              // EnableParameters â€” no advanced filters

		diag(L"enable %ls status=%lu match_any=0x%llx level=%u",
			provider.guid_string.c_str(), status, match_any, (unsigned)TRACE_LEVEL_VERBOSE);

		if (status != ERROR_SUCCESS) {
			printf("Failed to enable provider %ls (status %lu)\n",
				provider.guid_string.c_str(), status);
			return status;
		}

		// Rundown request. Same signature as the enable call but the CONTROL
		// CODE is different. Silent on providers that don't implement rundown.
		EnableTraceEx2(hTrace, &guid_copy, EVENT_CONTROL_CODE_CAPTURE_STATE,
			TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);

		const auto label = provider.name.empty() ? provider.guid_string : provider.name;
		wprintf(L"  enabled provider %ls (%ls)\n", label.c_str(), provider.guid_string.c_str());
	}

	// -- Step 5: PPL vm-logging opt-in for target processes --
	//
	// Must happen AFTER the TI provider is enabled (otherwise the audit setup
	// has nowhere to send events) but BEFORE the injection fires (otherwise
	// we miss the WRITEVM events for the injection itself). The PowerShell
	// runner enforces this by starting the target, writing runner.cfg with
	// the target PID, starting the PPL service (which starts us with the
	// vm-logging pid arg), and only then running the manipulation.
	for (DWORD pid : g_config.vm_logging_pids) {
		enable_vm_logging_for_pid(pid);
	}

	wprintf(L"Telemetry started. %zu provider(s) enabled. Waiting for events...\n",
		g_config.providers.size());

	// -- Step 6: open the trace, register callback, enter event loop --
	//
	// EVENT_TRACE_LOGFILEW is dual-purpose (real-time OR file-backed). We're
	// real-time: LoggerName + PROCESS_TRACE_MODE_REAL_TIME. EVENT_RECORD mode
	// tells ETW to give us the modern EVENT_RECORD struct rather than the
	// legacy EVENT_TRACE.
	EVENT_TRACE_LOGFILEW etl = {};
	etl.LoggerName          = const_cast<wchar_t*>(g_config.session_name.c_str());
	etl.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	etl.EventRecordCallback = OnEvent;
	auto hParse = OpenTraceW(&etl);

	if (hParse == INVALID_PROCESSTRACE_HANDLE) {
		printf("Failed to open trace: %u\n", GetLastError());
		return 1;
	}

	diag(L"decoder_version=2; waiting for events...");

	// ProcessTrace is the actual event loop. It blocks this thread and calls
	// OnEvent for each buffered event until either:
	//   - the session is stopped (ControlTraceW EVENT_TRACE_CONTROL_STOP)
	//   - or CloseTrace() is called from another thread.
	//
	// We stop by having PPLRunner (a separate service that owns this process's
	// lifetime) drop C:\elam\stop.flag, which its own polling loop notices
	// and uses to StopTrace + Terminate us.
	//
	// NOTE: we don't clean up on return (no CloseTrace / StopTrace) because
	// return-from-wmain will tear down the process anyway and Windows reaps
	// the session handle. In a longer-lived binary you'd want proper cleanup.
    auto trace_status = ProcessTrace(&hParse, 1, nullptr, nullptr);
    diag(L"decode_health error_events=%llu write_errors=%llu trace_status=%lu", g_decode_error_events, g_write_error_events, trace_status);
    CloseTrace(hParse);
}
