#pragma once

#include <string>
#include <Windows.h>
#include <mutex>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <map>


struct TelemetryEvent {
	std::wstring utc_time;
	std::wstring name;
	std::wstring process_name;
	std::wstring image_path;
	std::wstring keywords;
	std::wstring opcode;
	std::wstring task;
	std::wstring level;
	ULONG pid;
	ULONG tid;
	std::map<std::wstring, std::wstring> properties;
};

class JsonLogger {
public:
	static JsonLogger& init(const std::wstring& file_path) {
		static JsonLogger logger(file_path);
		return logger;
	}

	static JsonLogger& instance() {
		return init(L"telemetry.json");
	}

	JsonLogger(const JsonLogger&) = delete;
	JsonLogger& operator=(const JsonLogger&) = delete;

	JsonLogger(JsonLogger&&) = delete;
	JsonLogger& operator=(JsonLogger&&) = delete;

	bool write_event(const TelemetryEvent& event) {
		std::lock_guard<std::mutex> lock(mutex_);

		if (!file_.is_open()) {
			return false;
		}

		file_ << L"{"
			<< L"\"utc_time\":\"" << escape_json(event.utc_time) << L"\","
			<< L"\"name\":\"" << escape_json(event.name) << L"\","
			<< L"\"process_name\":\"" << escape_json(event.process_name) << L"\","
			<< L"\"image_path\":\"" << escape_json(event.image_path) << L"\","
			<< L"\"keywords\":\"" << escape_json(event.keywords) << L"\","
			<< L"\"opcode\":\"" << escape_json(event.opcode) << L"\","
			<< L"\"task\":\"" << escape_json(event.task) << L"\","
			<< L"\"level\":\"" << escape_json(event.level) << L"\","
			<< L"\"pid\":" << event.pid << L","
			<< L"\"tid\":" << event.tid
			<< L"}\n";

		file_.flush(); // optional but useful while debugging

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
				case L'\b': escaped << L"\\b";  break;
				case L'\f': escaped << L"\\f";  break;
				case L'\n': escaped << L"\\n";  break;
				case L'\r': escaped << L"\\r";  break;
				case L'\t': escaped << L"\\t";  break;
				default:
					escaped << c;
					break;
			}
		}

		return escaped.str();
	}

	static std::wstring metadata_or_empty(const std::wstring& metadata_json) {
		return metadata_json.empty() ? L"{}" : metadata_json;
	}

	std::wstring file_path_;
	std::wofstream file_;
	std::mutex mutex_;
};
