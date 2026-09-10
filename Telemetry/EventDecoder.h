#pragma once
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <string>
#include <vector>
#include "JsonLogger.h"

// Query each named property independently. A bad property cannot shift the
// offset used for subsequent properties. TDH handles manifest length references.
inline ULONG ReadEventProperty(PEVENT_RECORD record,
    std::vector<PROPERTY_DATA_DESCRIPTOR> descriptors, std::vector<BYTE>& bytes) {
    ULONG size = 0;
    auto status = TdhGetPropertySize(record, 0, nullptr,
        static_cast<ULONG>(descriptors.size()), descriptors.data(), &size);
    if (status != ERROR_SUCCESS) return status;
    bytes.resize(size);
    if (!size) return ERROR_SUCCESS;
    return TdhGetProperty(record, 0, nullptr, static_cast<ULONG>(descriptors.size()),
        descriptors.data(), size, bytes.data());
}

inline ULONG FormatEventProperty(PTRACE_EVENT_INFO info, ULONG pointer_size,
    USHORT input_type, USHORT output_type, USHORT length,
    std::vector<BYTE>& bytes, std::wstring& value) {
    value.clear();
    if (bytes.size() > USHRT_MAX) return ERROR_INVALID_DATA;
    if (bytes.empty()) return ERROR_SUCCESS;
    ULONG text_bytes = 0;
    USHORT consumed = 0;
    auto status = TdhFormatProperty(info, nullptr, pointer_size, input_type,
        output_type, length, static_cast<USHORT>(bytes.size()), bytes.data(),
        &text_bytes, nullptr, &consumed);
    if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) return status;
    if (!text_bytes) return ERROR_SUCCESS;
    std::vector<WCHAR> text((text_bytes + sizeof(WCHAR) - 1) / sizeof(WCHAR) + 1, L'\0');
    status = TdhFormatProperty(info, nullptr, pointer_size, input_type,
        output_type, length, static_cast<USHORT>(bytes.size()), bytes.data(),
        &text_bytes, text.data(), &consumed);
    if (status == ERROR_SUCCESS) value.assign(text.data());
    return status;
}

inline void DecodeEventProperties(PEVENT_RECORD record, PTRACE_EVENT_INFO info,
    TelemetryEvent& event) {
    auto name_of = [&](ULONG index) {
        return reinterpret_cast<PWSTR>(reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[index].NameOffset);
    };
    auto referenced_integer = [&](ULONG index, ULONG& number) -> ULONG {
        if (index >= info->PropertyCount) return ERROR_INVALID_DATA;
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name_of(index));
        descriptor.ArrayIndex = ULONG_MAX;
        std::vector<BYTE> bytes;
        auto status = ReadEventProperty(record, {descriptor}, bytes);
        if (status != ERROR_SUCCESS) return status;
        if (bytes.empty() || bytes.size() > sizeof(ULONG)) return ERROR_INVALID_DATA;
        number = 0;
        std::memcpy(&number, bytes.data(), bytes.size());
        return ERROR_SUCCESS;
    };
    const ULONG pointer_size = record->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
    std::function<void(ULONG, std::vector<PROPERTY_DATA_DESCRIPTOR>, std::wstring)> decode;
    decode = [&](ULONG index, std::vector<PROPERTY_DATA_DESCRIPTOR> parents, std::wstring prefix) {
        if (index >= info->PropertyCount || parents.size() > 1) {
            event.decode_errors[prefix] = L"unsupported property nesting"; return;
        }
        const auto& prop = info->EventPropertyInfoArray[index];
        auto name = name_of(index);
        ULONG count = prop.count;
        ULONG status = ERROR_SUCCESS;
        if (prop.Flags & PropertyParamCount) status = referenced_integer(prop.countPropertyIndex, count);
        if (status != ERROR_SUCCESS || count > USHRT_MAX) {
            event.decode_errors[prefix + name] = L"array count: " + std::to_wstring(status); return;
        }
        for (ULONG item = 0; item < count; ++item) {
            auto descriptors = parents;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
            descriptor.ArrayIndex = item;
            descriptors.push_back(descriptor);
            std::wstring key = prefix + name;
            if (count > 1) key += L"[" + std::to_wstring(item) + L"]";
            if (prop.Flags & PropertyStruct) {
                for (ULONG member = 0; member < prop.structType.NumOfStructMembers; ++member)
                    decode(prop.structType.StructStartIndex + member, descriptors, key + L".");
                continue;
            }
            ULONG length = prop.length;
            if (prop.Flags & PropertyParamLength) status = referenced_integer(prop.lengthPropertyIndex, length);
            if (status != ERROR_SUCCESS || length > USHRT_MAX) {
                event.decode_errors[key] = L"property length: " + std::to_wstring(status); continue;
            }
            std::vector<BYTE> bytes;
            status = ReadEventProperty(record, descriptors, bytes);
            std::wstring formatted;
            if (status == ERROR_SUCCESS)
                status = FormatEventProperty(info, pointer_size, prop.nonStructType.InType,
                    prop.nonStructType.OutType, static_cast<USHORT>(length), bytes, formatted);
            if (status != ERROR_SUCCESS) {
                event.decode_errors[key] = std::to_wstring(status); continue;
            }
            formatted.erase(std::remove_if(formatted.begin(), formatted.end(), [](wchar_t c) {
                return c == 0x200E || c == 0x200F || (c >= 0x202A && c <= 0x202E);
            }), formatted.end());
            event.properties[key] = formatted;
            if (parents.empty() && (_wcsicmp(name, L"ImageName") == 0 || _wcsicmp(name, L"FileName") == 0)) event.image_path = formatted;
            if (parents.empty() && (_wcsicmp(name, L"ProcessName") == 0 || _wcsicmp(name, L"ImageFileName") == 0)) event.process_name = formatted;
        }
    };
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) decode(i, {}, L"");
}

inline void PreserveFailedEventData(PEVENT_RECORD record, TelemetryEvent& event) {
    if (event.decode_errors.empty()) return;
    constexpr wchar_t hex[] = L"0123456789ABCDEF";
    auto bytes = static_cast<const BYTE*>(record->UserData);
    event.raw_user_data_hex.reserve(record->UserDataLength * 2);
    for (USHORT i = 0; i < record->UserDataLength; ++i) {
        event.raw_user_data_hex += hex[bytes[i] >> 4];
        event.raw_user_data_hex += hex[bytes[i] & 15];
    }
}
