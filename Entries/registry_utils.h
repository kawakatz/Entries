#pragma once
#include "common.h"

struct RegistryRoot {
    HKEY root;
    std::wstring path;
    std::wstring label;
    REGSAM view;
};

struct RegistryValueInfo {
    std::wstring name;
    DWORD type = 0;
    DWORD dataBytes = 0;
};

bool ReadRegData(HKEY hKey, const wchar_t* valueName, DWORD& type,
    std::vector<BYTE>& data, const wchar_t* retryMessage = nullptr);
bool ReadRegString(HKEY hKey, const wchar_t* valueName, std::wstring& value,
    const wchar_t* retryMessage = nullptr);
bool ReadRegDword(HKEY hKey, const wchar_t* valueName, DWORD& value);
std::wstring ReadRegStringValue(HKEY root, const std::wstring& path,
    const wchar_t* valueName, REGSAM view = 0,
    const wchar_t* retryMessage = L"Registry value changed during retries");
std::wstring ResolveServiceComponentPath(const std::wstring& serviceName);
std::wstring ResolveClsidServerPath(const std::wstring& clsid,
    std::wstring* source = nullptr);
LSTATUS QueryRegistryValue(HKEY hKey, DWORD index,
    std::vector<WCHAR>& nameBuffer, std::vector<BYTE>& dataBuffer,
    RegistryValueInfo& value);
std::vector<std::wstring> EnumOpenKeySubKeys(HKEY hKey,
    const wchar_t* errorContext = L"Registry");
std::vector<std::wstring> EnumSubKeys(HKEY root, const std::wstring& path,
    REGSAM view = 0, const wchar_t* errorContext = L"Registry");
