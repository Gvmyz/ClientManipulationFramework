#pragma once
#include <Windows.h>


// https://en.cppreference.com/w/cpp/language/rule_of_three.html

class WinHandle {
public:
	WinHandle() noexcept;
	explicit WinHandle(HANDLE handle);
	~WinHandle() noexcept;

	// No copy constructor => e.g. not have double close bugs
	// Should have unique ownership
	WinHandle(const WinHandle&) = delete;
	// No copy assignment
	WinHandle& operator=(const WinHandle&) = delete;

	// Move constructor
	WinHandle(WinHandle&& other) noexcept;
	// Move assignment
	WinHandle& operator=(WinHandle&& other) noexcept;

	// Get back the raw HANDLE 
	HANDLE get() const noexcept;
	bool valid() const noexcept;

	void reset(HANDLE handle = nullptr) noexcept;

	HANDLE release() noexcept;
private:
	HANDLE handle_ = nullptr;
};

