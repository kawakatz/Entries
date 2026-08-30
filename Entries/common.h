#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <utility>

inline std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

inline bool StartsWithIcase(const std::wstring& value, const std::wstring& prefix) {
    return value.size() >= prefix.size()
        && ToLower(value.substr(0, prefix.size())) == ToLower(prefix);
}

enum class EntryType {
    TCP,
    UDP,
    NamedPipe,
    SharedMemory,
    ALPC,
    RPC,
    HTTP,
    Service,
    Mailslot,
    COM,
    Driver,
    Task,
    WMI,
    Shell,
    Assoc,
    DeviceInterface,
    BrowserNative,
    Firewall,
    AppX,
    ETW,
    Window,
    Filter,
    Crypto,
    Persistence,
    KernelObject
};

inline const wchar_t* EntryTypeName(EntryType type) {
    switch (type) {
    case EntryType::TCP:          return L"TCP";
    case EntryType::UDP:          return L"UDP";
    case EntryType::NamedPipe:    return L"PIPE";
    case EntryType::SharedMemory: return L"SHM";
    case EntryType::ALPC:         return L"ALPC";
    case EntryType::RPC:          return L"RPC";
    case EntryType::HTTP:         return L"HTTP";
    case EntryType::Service:      return L"SVC";
    case EntryType::Mailslot:     return L"MAIL";
    case EntryType::COM:          return L"COM";
    case EntryType::Driver:       return L"DRV";
    case EntryType::Task:         return L"TASK";
    case EntryType::WMI:          return L"WMI";
    case EntryType::Shell:        return L"SHELL";
    case EntryType::Assoc:        return L"ASSOC";
    case EntryType::DeviceInterface: return L"DEVIF";
    case EntryType::BrowserNative:return L"BROWSER";
    case EntryType::Firewall:     return L"FW";
    case EntryType::AppX:         return L"APPX";
    case EntryType::ETW:          return L"ETW";
    case EntryType::Window:       return L"WIN";
    case EntryType::Filter:       return L"FILTER";
    case EntryType::Crypto:       return L"CRYPTO";
    case EntryType::Persistence:  return L"PERSIST";
    case EntryType::KernelObject: return L"KOBJ";
    default:                      return L"???";
    }
}

struct EntryPoint {
    EntryType type;
    std::wstring name;
    std::wstring details;
    DWORD ownerPid = 0;
    std::wstring ownerPath;
    std::wstring ownerPrivilege;
};

using EntryPointList = std::vector<EntryPoint>;
