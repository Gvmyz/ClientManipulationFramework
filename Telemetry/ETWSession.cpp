#include "ETWSession.h"

ETWSession::ETWSession() {
	ETWSession::initialize_properties();
}

ETWSession::~ETWSession() {
	if (running_) {
		stop();
	}
}

void ETWSession::start() {
	if (running_) {
		return;
	}

	running_ = true;
}

void ETWSession::initialize_properties() {
	const WCHAR* session_name = session_name_.c_str(); // Get a pointer to the session name string.
	EVENT_TRACE_PROPERTIES* props = nullptr; // Why start with a pointer? Because the structure is variable-sized, and we need to allocate enough memory for the session name and log file name.
	std::size_t properties_size = sizeof(EVENT_TRACE_PROPERTIES) + (session_name_.size() + 1) * sizeof(wchar_t); // Calculate the size of the properties structure, including the session name.
	props->Wnode.BufferSize = static_cast<ULONG>(properties_size); // Set the buffer size for the Wnode header to the size of the properties structure.
	props->BufferSize = 64; // Set the buffer size for logging (in KB).
	props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // Set the log file mode to
	// real-time mode, which means events will be delivered to the session in real time.
	props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); // Set the offset for the session name
}

void ETWSession::stop() {
	if (!running_) {
		return;
	}
	running_ = false;
}
