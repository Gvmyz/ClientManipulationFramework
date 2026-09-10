#include "../EventDecoder.h"
#include <iostream>
#include <stdexcept>

static void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }

int wmain(int argc, wchar_t** argv) {
    try {
        TRACE_EVENT_INFO info{};
        info.DecodingSource = DecodingSourceXMLFile;
        std::wstring long_string(1500, L'x');
        std::vector<BYTE> bytes((long_string.size() + 1) * sizeof(wchar_t));
        std::memcpy(bytes.data(), long_string.c_str(), bytes.size());
        std::wstring value = L"stale";
        auto status = FormatEventProperty(&info, 8, TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_STRING, 0, bytes, value);
        check(status == ERROR_SUCCESS && value == long_string, "long Unicode field was truncated");
        ULONG number = 4;
        bytes.resize(sizeof(number)); std::memcpy(bytes.data(), &number, sizeof(number));
        status = FormatEventProperty(&info, 8, TDH_INTYPE_UINT32, TDH_OUTTYPE_UNSIGNEDINT, 4, bytes, value);
        check(status == ERROR_SUCCESS && value == L"4", "numeric field after long text was corrupted");
        bytes.resize(1);
        value = L"stale";
        status = FormatEventProperty(&info, 8, TDH_INTYPE_GUID, TDH_OUTTYPE_GUID, 16, bytes, value);
        check(status != ERROR_SUCCESS && value.empty(), "failed format reused stale output");
        TelemetryEvent event;
        event.decode_errors[L"failed"] = L"invalid";
        EVENT_RECORD record{}; BYTE payload[] = {0x00, 0xAF, 0xFF};
        record.UserData = payload; record.UserDataLength = sizeof(payload);
        PreserveFailedEventData(&record, event);
        check(event.raw_user_data_hex == L"00AFFF", "failed-event raw bytes not preserved");
        if (argc == 2) {
            auto module = LoadLibraryW(argv[1]);
            check(module != nullptr, "TestDll failed to load into test process");
            wchar_t name[96]{};
            swprintf_s(name, L"Local\\CMF_TestDll_Attached_%lu", GetCurrentProcessId());
            auto marker = OpenEventW(SYNCHRONIZE, FALSE, name);
            check(marker && WaitForSingleObject(marker, 0) == WAIT_OBJECT_0, "TestDll attach marker missing");
            CloseHandle(marker); FreeLibrary(module);
        }
        std::cout << "PASS: long TDH string, following scalar, failed decode, raw preservation, payload marker\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
