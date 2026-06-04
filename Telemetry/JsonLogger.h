#pragma once

#include <Windows.h>

#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

struct TelemetryEvent {
	std::wstring utc_time;
	std::wstring name;
	std::wstring process_name;
	std::wstring image_path;
	std::wstring keywords;
	std::wstring opcode;
	std::wstring task;
	std::wstring level;
	// Friendly label of the provider that emitted this event (e.g. "KernelProcess",
	// "Sysmon"). Populated from rec->EventHeader.ProviderId via a name lookup at
	// build_event time. Lets the downstream pipeline group/filter by provider
	// without round-tripping the GUID. Empty if the provider was registered
	// without a friendly name.
	std::wstring provider_name;
	ULONG pid{};
	ULONG tid{};
	std::map<std::wstring, std::wstring> properties;
};

struct ExperimentMetadata {
	std::wstring provider_guid;
	std::wstring session_name;
	std::wstring output_path;
	std::optional<std::wstring> run_id;
	std::optional<std::wstring> label;
	std::optional<std::wstring> technique;
	std::optional<std::wstring> target;
	std::optional<DWORD> filter_pid;
	std::optional<std::wstring> filter_process_name;
	std::map<std::wstring, std::wstring> extra;
};

class JsonLogger {
public:
	static JsonLogger& init(const std::wstring& file_path) {
		static JsonLogger logger(file_path);
		return logger;
	}

	// Change this to have multiple files or different naming scheme based on runs
	static JsonLogger& instance() {
		return init(L"telemetry.json");
	}

	JsonLogger(const JsonLogger&) = delete;
	JsonLogger& operator=(const JsonLogger&) = delete;
	JsonLogger(JsonLogger&&) = delete;
	JsonLogger& operator=(JsonLogger&&) = delete;

	void set_experiment_metadata(ExperimentMetadata metadata) {
		std::lock_guard<std::mutex> lock(mutex_);
		metadata_ = std::move(metadata);
	}

	bool write_event(const TelemetryEvent& event) {
		std::lock_guard<std::mutex> lock(mutex_);

		if (!file_.is_open()) {
			return false;
		}

		file_ << build_record(event) << L'\n';
		file_.flush();
		return static_cast<bool>(file_);
	}

private:
	explicit JsonLogger(const std::wstring& file_path)
		: file_path_(file_path),
		file_(file_path_, std::ios::out | std::ios::app) {}

	~JsonLogger() {
		std::lock_guard<std::mutex> lock(mutex_);
		if (file_.is_open()) {
			file_.flush();
			file_.close();
		}
	}

	static std::wstring escape_json(const std::wstring& input) {
		std::wstringstream escaped{};

		for (wchar_t c : input) {
			switch (c) {
				case L'\"': escaped << L"\\\""; break;
				case L'\\': escaped << L"\\\\"; break;
				case L'\b': escaped << L"\\b"; break;
				case L'\f': escaped << L"\\f"; break;
				case L'\n': escaped << L"\\n"; break;
				case L'\r': escaped << L"\\r"; break;
				case L'\t': escaped << L"\\t"; break;
				default:
					escaped << c;
					break;
			}
		}

		return escaped.str();
	}

	static void append_json_string(std::wstringstream& out, std::wstring_view value) {
		out << L'"' << escape_json(std::wstring(value)) << L'"';
	}

	static void append_json_field(std::wstringstream& out, std::wstring_view key, std::wstring_view value, bool& first) {
		append_separator(out, first);
		append_json_string(out, key);
		out << L':';
		append_json_string(out, value);
	}

	static void append_json_field(std::wstringstream& out, std::wstring_view key, DWORD value, bool& first) {
		append_separator(out, first);
		append_json_string(out, key);
		out << L':' << value;
	}

	static void append_json_map_field(
		std::wstringstream& out,
		std::wstring_view key,
		const std::map<std::wstring, std::wstring>& values,
		bool& first
	) {
		append_separator(out, first);
		append_json_string(out, key);
		out << L':';
		append_json_map(out, values);
	}

	static void append_json_map(std::wstringstream& out, const std::map<std::wstring, std::wstring>& values) {
		out << L'{';
		bool first = true;
		for (const auto& [key, value] : values) {
			append_json_field(out, key, value, first);
		}
		out << L'}';
	}

	static void append_separator(std::wstringstream& out, bool& first) {
		if (!first) {
			out << L',';
		}
		first = false;
	}

	std::wstring build_experiment_json() const {
		std::wstringstream out{};
		out << L'{';

		bool first = true;
		append_json_field(out, L"provider_guid", metadata_.provider_guid, first);
		append_json_field(out, L"session_name", metadata_.session_name, first);
		append_json_field(out, L"output_path", metadata_.output_path, first);

		if (metadata_.run_id) {
			append_json_field(out, L"run_id", *metadata_.run_id, first);
		}
		if (metadata_.label) {
			append_json_field(out, L"label", *metadata_.label, first);
		}
		if (metadata_.technique) {
			append_json_field(out, L"technique", *metadata_.technique, first);
		}
		if (metadata_.target) {
			append_json_field(out, L"target", *metadata_.target, first);
		}
		if (metadata_.filter_pid) {
			append_json_field(out, L"filter_pid", *metadata_.filter_pid, first);
		}
		if (metadata_.filter_process_name) {
			append_json_field(out, L"filter_process_name", *metadata_.filter_process_name, first);
		}
		if (!metadata_.extra.empty()) {
			append_json_map_field(out, L"extra", metadata_.extra, first);
		}

		out << L'}';
		return out.str();
	}

	static std::wstring build_event_json(const TelemetryEvent& event) {
		std::wstringstream out{};
		out << L'{';

		bool first = true;
		append_json_field(out, L"utc_time", event.utc_time, first);
		append_json_field(out, L"provider_name", event.provider_name, first);
		append_json_field(out, L"name", event.name, first);
		append_json_field(out, L"process_name", event.process_name, first);
		append_json_field(out, L"image_path", event.image_path, first);
		append_json_field(out, L"keywords", event.keywords, first);
		append_json_field(out, L"opcode", event.opcode, first);
		append_json_field(out, L"task", event.task, first);
		append_json_field(out, L"level", event.level, first);
		append_json_field(out, L"pid", event.pid, first);
		append_json_field(out, L"tid", event.tid, first);
		append_json_map_field(out, L"properties", event.properties, first);

		out << L'}';
		return out.str();
	}

	std::wstring build_record(const TelemetryEvent& event) const {
		std::wstringstream out{};
		out << L'{';

		bool first = true;
		append_separator(out, first);
		append_json_string(out, L"experiment");
		out << L':' << build_experiment_json();

		append_separator(out, first);
		append_json_string(out, L"event");
		out << L':' << build_event_json(event);

		out << L'}';
		return out.str();
	}

	std::wstring file_path_;
	std::wofstream file_;
	ExperimentMetadata metadata_{};
	std::mutex mutex_;
};
