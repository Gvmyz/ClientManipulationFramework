#include "WinHandle.h"

WinHandle::WinHandle() noexcept : handle_{ nullptr } {}

WinHandle::WinHandle(HANDLE handle) : handle_{ handle } {}

WinHandle::~WinHandle() noexcept {
	reset();
}

WinHandle::WinHandle(WinHandle&& other) noexcept : handle_{ other.handle_ } {
	other.handle_ = nullptr;
}

WinHandle& WinHandle::operator=(WinHandle&& other) noexcept {
	if (this != &other) {
		reset();
		handle_ = other.handle_;
		other.handle_ = nullptr;
	}
	return *this;
}

HANDLE WinHandle::get() const noexcept {
	return handle_;
}

bool WinHandle::valid() const noexcept {
	return (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE);
}

WinHandle::operator bool() const noexcept {
	return valid();
}

void WinHandle::reset(HANDLE handle) noexcept {
	if (valid()) {
		CloseHandle(handle_);
	}
	handle_ = handle;
}

// Might need rework?
HANDLE WinHandle::release() noexcept {
	HANDLE temp = handle_;
	handle_ = nullptr;
	return temp;
}
