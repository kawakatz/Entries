#include "registry_utils.h"
#include "diagnostics.h"
#include "process_utils.h"

bool ReadRegData(HKEY hKey, const wchar_t* valueName, DWORD& type,
    std::vector<BYTE>& data, const wchar_t* retryMessage)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD bytes = static_cast<DWORD>(data.size());
        LSTATUS status = RegQueryValueExW(hKey, valueName, nullptr, &type,
            data.empty() ? nullptr : data.data(), &bytes);
        if (status == ERROR_SUCCESS && !data.empty()) {
            data.resize(bytes);
            return true;
        }
        if ((status != ERROR_SUCCESS && status != ERROR_MORE_DATA)
            || bytes <= data.size() || attempt == 3) {
            if (status == ERROR_MORE_DATA && retryMessage) {
                ReportPartial(retryMessage);
            }
            return status == ERROR_SUCCESS;
        }
        data.resize(bytes);
    }
    return false;
}

bool ReadRegString(HKEY hKey, const wchar_t* valueName, std::wstring& value,
    const wchar_t* retryMessage)
{
    DWORD type = 0;
    std::vector<BYTE> data;
    if (!ReadRegData(hKey, valueName, type, data, retryMessage) || data.empty()
        || (type != REG_SZ && type != REG_EXPAND_SZ)) return false;

    const auto* text = reinterpret_cast<const WCHAR*>(data.data());
    size_t chars = data.size() / sizeof(WCHAR);
    size_t length = 0;
    while (length < chars && text[length] != L'\0') length++;
    value.assign(text, length);
    if (type == REG_EXPAND_SZ) value = ExpandEnvironmentPath(value);
    return true;
}

bool ReadRegDword(HKEY hKey, const wchar_t* valueName, DWORD& value) {
    DWORD type = 0;
    DWORD bytes = sizeof(value);
    return RegQueryValueExW(hKey, valueName, nullptr, &type,
        reinterpret_cast<LPBYTE>(&value), &bytes) == ERROR_SUCCESS
        && type == REG_DWORD && bytes == sizeof(value);
}

std::wstring ReadRegStringValue(HKEY root, const std::wstring& path,
    const wchar_t* valueName, REGSAM view, const wchar_t* retryMessage)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &hKey)
        != ERROR_SUCCESS) return L"";

    std::wstring value;
    ReadRegString(hKey, valueName, value, retryMessage);
    RegCloseKey(hKey);
    return value;
}

std::wstring ResolveServiceComponentPath(const std::wstring& serviceName) {
    if (serviceName.empty()) return L"";
    std::wstring serviceKey = L"SYSTEM\\CurrentControlSet\\Services\\"
        + serviceName;
    std::wstring serviceDll = ReadRegStringValue(HKEY_LOCAL_MACHINE,
        serviceKey + L"\\Parameters", L"ServiceDll");
    if (!serviceDll.empty()) return ExtractExecutablePath(serviceDll);
    return ExtractExecutablePath(ReadRegStringValue(
        HKEY_LOCAL_MACHINE, serviceKey, L"ImagePath"));
}

std::wstring ResolveClsidServerPath(const std::wstring& clsid,
    std::wstring* source)
{
    if (clsid.empty()) return L"";
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
    for (auto view : views) {
        std::wstring base = L"CLSID\\" + clsid;
        const wchar_t* serverKeys[] = { L"InprocServer32", L"LocalServer32" };
        for (const wchar_t* serverKey : serverKeys) {
            std::wstring path = ReadRegStringValue(HKEY_CLASSES_ROOT,
                base + L"\\" + serverKey, nullptr, view);
            if (path.empty()) continue;
            if (source) *source = serverKey;
            return ExtractExecutablePath(path);
        }

        std::wstring appId = ReadRegStringValue(HKEY_CLASSES_ROOT,
            base, L"AppID", view);
        if (appId.empty()) continue;
        std::wstring serviceName = ReadRegStringValue(HKEY_CLASSES_ROOT,
            L"AppID\\" + appId, L"LocalService", view);
        if (serviceName.empty()) continue;
        if (source) *source = L"AppID LocalService=" + serviceName;
        return ResolveServiceComponentPath(serviceName);
    }
    if (source) *source = L"CLSID";
    return L"";
}

LSTATUS QueryRegistryValue(HKEY hKey, DWORD index,
    std::vector<WCHAR>& nameBuffer, std::vector<BYTE>& dataBuffer,
    RegistryValueInfo& value)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
        DWORD dataBytes = static_cast<DWORD>(dataBuffer.size());
        DWORD type = 0;
        LSTATUS status = RegEnumValueW(hKey, index, nameBuffer.data(),
            &nameLength, nullptr, &type, dataBuffer.data(), &dataBytes);
        if (status == ERROR_SUCCESS) {
            value.name.assign(nameBuffer.data(), nameLength);
            value.type = type;
            value.dataBytes = dataBytes;
            return status;
        }
        if (status != ERROR_MORE_DATA || attempt == 3) return status;
        nameBuffer.resize(nameBuffer.size() * 2);
        dataBuffer.resize((std::max)(dataBuffer.size() * 2,
            static_cast<size_t>(dataBytes)));
    }
    return ERROR_MORE_DATA;
}

std::vector<std::wstring> EnumOpenKeySubKeys(HKEY hKey,
    const wchar_t* errorContext)
{
    std::vector<std::wstring> result;

    DWORD maxName = 0;
    LSTATUS status = RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr,
        &maxName, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
        if (errorContext) {
            ReportPartial(std::wstring(errorContext) + L" subkey sizing failed: "
                + std::to_wstring(status));
        }
        return result;
    }
    std::vector<WCHAR> name(maxName + 1);

    for (DWORD index = 0;; index++) {
        for (int attempt = 0; attempt < 4; attempt++) {
            DWORD nameLength = static_cast<DWORD>(name.size());
            status = RegEnumKeyExW(hKey, index, name.data(), &nameLength,
                nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_SUCCESS) {
                result.emplace_back(name.data(), nameLength);
                break;
            }
            if (status == ERROR_NO_MORE_ITEMS) {
                return result;
            }
            if (status != ERROR_MORE_DATA || attempt == 3) {
                if (errorContext) {
                    ReportPartial(std::wstring(errorContext)
                        + L" subkey enumeration failed: "
                        + std::to_wstring(status));
                }
                return result;
            }
            name.resize(name.size() * 2);
        }
    }
}

std::vector<std::wstring> EnumSubKeys(HKEY root, const std::wstring& path,
    REGSAM view, const wchar_t* errorContext)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &hKey)
        != ERROR_SUCCESS) return {};

    auto result = EnumOpenKeySubKeys(hKey, errorContext);
    RegCloseKey(hKey);
    return result;
}
