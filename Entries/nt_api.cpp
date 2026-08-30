#include "nt_api.h"
#include <cstdint>
#include <utility>

NtApi g_NtApi;

bool NtApi::Initialize() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    NtQuerySystemInformation = reinterpret_cast<PFN_NtQuerySystemInformation>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    NtQueryObject = reinterpret_cast<PFN_NtQueryObject>(
        GetProcAddress(hNtdll, "NtQueryObject"));
    NtOpenDirectoryObject = reinterpret_cast<PFN_NtOpenDirectoryObject>(
        GetProcAddress(hNtdll, "NtOpenDirectoryObject"));
    NtQueryDirectoryObject = reinterpret_cast<PFN_NtQueryDirectoryObject>(
        GetProcAddress(hNtdll, "NtQueryDirectoryObject"));
    NtOpenSection = reinterpret_cast<PFN_NtOpenSection>(
        GetProcAddress(hNtdll, "NtOpenSection"));
    RtlInitUnicodeString = reinterpret_cast<PFN_RtlInitUnicodeString>(
        GetProcAddress(hNtdll, "RtlInitUnicodeString"));

    return IsValid();
}

bool NtApi::IsValid() const {
    return NtQuerySystemInformation
        && NtQueryObject
        && NtOpenDirectoryObject
        && NtQueryDirectoryObject
        && RtlInitUnicodeString;
}

bool QueryObjectDirectoryPage(HANDLE directory,
    std::vector<BYTE>& buffer,
    BOOLEAN restart,
    ULONG& context,
    ULONG& returnLength,
    NTSTATUS& status)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        ULONG previousContext = context;
        status = g_NtApi.NtQueryDirectoryObject(directory, buffer.data(),
            static_cast<ULONG>(buffer.size()), FALSE, restart,
            &context, &returnLength);
        if (status != STATUS_BUFFER_TOO_SMALL
            && status != STATUS_INFO_LENGTH_MISMATCH) {
            return true;
        }

        context = previousContext;
        size_t nextSize = buffer.size() * 2;
        if (returnLength > nextSize) nextSize = returnLength;
        if (nextSize <= buffer.size() || nextSize > 1024 * 1024 || attempt == 3) {
            return false;
        }
        buffer.resize(nextSize);
    }
    return false;
}

static bool DecodeUnicodeString(const UNICODE_STRING& value,
    std::uintptr_t begin, std::uintptr_t end, std::wstring& decoded)
{
    decoded.clear();
    if (!value.Buffer) return value.Length == 0;
    if (value.Length > value.MaximumLength
        || value.Length % sizeof(WCHAR) != 0) {
        return false;
    }

    std::uintptr_t text = reinterpret_cast<std::uintptr_t>(value.Buffer);
    if (text % alignof(WCHAR) != 0 || text < begin || text > end
        || value.Length > end - text) {
        return false;
    }
    decoded.assign(value.Buffer, value.Length / sizeof(WCHAR));
    return true;
}

bool DecodeObjectDirectoryPage(const std::vector<BYTE>& buffer,
    ULONG returnLength,
    std::vector<NtObjectDirectoryEntry>& entries)
{
    entries.clear();
    if (returnLength < sizeof(OBJECT_DIRECTORY_INFORMATION)
        || returnLength > buffer.size()) {
        return false;
    }

    std::vector<NtObjectDirectoryEntry> decoded;
    std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(buffer.data());
    std::uintptr_t end = begin + returnLength;
    size_t decodedBytes = 0;
    for (size_t offset = 0;
        returnLength - offset >= sizeof(OBJECT_DIRECTORY_INFORMATION);
        offset += sizeof(OBJECT_DIRECTORY_INFORMATION)) {
        auto* raw = reinterpret_cast<const OBJECT_DIRECTORY_INFORMATION*>(
            buffer.data() + offset);
        if (!raw->Name.Buffer) {
            if (raw->Name.Length != 0 || raw->TypeName.Buffer
                || raw->TypeName.Length != 0) {
                return false;
            }
            entries = std::move(decoded);
            return true;
        }

        size_t stringBytes = static_cast<size_t>(raw->Name.Length)
            + raw->TypeName.Length;
        if (stringBytes > returnLength - decodedBytes) return false;
        decodedBytes += stringBytes;

        NtObjectDirectoryEntry entry;
        if (!DecodeUnicodeString(raw->Name, begin, end, entry.name)
            || !DecodeUnicodeString(raw->TypeName, begin, end, entry.typeName)) {
            return false;
        }
        decoded.push_back(std::move(entry));
    }
    return false;
}
