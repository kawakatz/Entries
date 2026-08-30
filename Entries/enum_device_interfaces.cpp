#include "enum_device_interfaces.h"
#include "diagnostics.h"
#include "registry_utils.h"

#include <set>

static std::vector<std::wstring> EnumDeviceSubKeys(HKEY root,
    const std::wstring& path)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        ReportPartial(L"Device-interface registry key open failed: "
            + std::to_wstring(status));
        return {};
    }

    auto result = EnumOpenKeySubKeys(hKey, L"Device-interface registry");
    RegCloseKey(hKey);
    result.erase(std::remove_if(result.begin(), result.end(),
        [](const std::wstring& name) {
            return _wcsicmp(name.c_str(), L"Properties") == 0;
        }), result.end());
    return result;
}

static std::wstring ReadDeviceString(HKEY root,
    const std::wstring& path,
    const wchar_t* valueName)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        ReportPartial(L"Device-interface registry value key open failed: "
            + std::to_wstring(status));
        return L"";
    }

    std::wstring result;
    ReadRegString(hKey, valueName, result,
        L"Device-interface registry value changed during retries");
    RegCloseKey(hKey);
    return result;
}

static std::wstring DecodeDeviceInterfaceName(std::wstring name) {
    if (name.rfind(L"##?#", 0) == 0) {
        name = L"\\\\?\\" + name.substr(4);
    }
    return name;
}

EntryPointList EnumerateDeviceInterfaces() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const std::wstring root = L"SYSTEM\\CurrentControlSet\\Control\\DeviceClasses";
    for (const auto& classGuid : EnumDeviceSubKeys(HKEY_LOCAL_MACHINE, root)) {
        std::wstring classPath = root + L"\\" + classGuid;
        for (const auto& interfaceName : EnumDeviceSubKeys(HKEY_LOCAL_MACHINE, classPath)) {
            std::wstring interfacePath = classPath + L"\\" + interfaceName;
            std::wstring deviceInstance = ReadDeviceString(HKEY_LOCAL_MACHINE,
                interfacePath, L"DeviceInstance");
            std::wstring serviceName;
            if (!deviceInstance.empty()) {
                serviceName = ReadRegStringValue(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Enum\\" + deviceInstance,
                    L"Service");
            }

            std::wstring decodedName = DecodeDeviceInterfaceName(interfaceName);
            std::wstring dedup = classGuid + L"|" + decodedName;
            if (!seen.insert(dedup).second) continue;

            EntryPoint ep;
            ep.type = EntryType::DeviceInterface;
            ep.name = decodedName;
            ep.details = L"Device interface registry entry | ClassGuid=" + classGuid;
            if (!deviceInstance.empty()) {
                ep.details += L" | DeviceInstance=" + deviceInstance;
            }
            if (!serviceName.empty()) ep.details += L" | Service=" + serviceName;
            ep.details += L" | Registry=HKLM\\" + interfacePath;
            ep.ownerPath = ResolveServiceComponentPath(serviceName);
            if (ep.ownerPath.empty()) ep.ownerPath = L"<device-interface>";
            results.push_back(std::move(ep));
        }
    }

    return results;
}
