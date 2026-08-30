#include "enum_services.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"
#include "security_utils.h"

#pragma comment(lib, "advapi32.lib")

template <typename Query>
static std::vector<BYTE> QueryServiceBuffer(Query query) {
    std::vector<BYTE> buffer;
    DWORD needed = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        if (query(buffer.empty() ? nullptr : buffer.data(),
            static_cast<DWORD>(buffer.size()), &needed)) return buffer;
        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER
            || needed <= buffer.size() || attempt == 3) {
            ReportPartial(L"Service detail query failed: "
                + std::to_wstring(error));
            return {};
        }
        buffer.resize(needed);
    }
    return {};
}

static bool QueryServices(SC_HANDLE hScm, DWORD type,
    std::vector<BYTE>& buffer, DWORD& count)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD needed = 0;
        DWORD resume = 0;
        count = 0;
        if (EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, type,
            SERVICE_STATE_ALL, buffer.empty() ? nullptr : buffer.data(),
            static_cast<DWORD>(buffer.size()), &needed, &count, &resume,
            nullptr)) return true;
        DWORD error = GetLastError();
        if (error != ERROR_MORE_DATA || needed == 0
            || needed > MAXDWORD - buffer.size() || attempt == 3) {
            ReportPartial(L"Service enumeration failed: "
                + std::to_wstring(error));
            return false;
        }
        buffer.resize(buffer.size() + needed);
    }
    return false;
}

static std::wstring ServiceStateName(DWORD state) {
    switch (state) {
    case SERVICE_RUNNING:         return L"RUNNING";
    case SERVICE_STOPPED:         return L"STOPPED";
    case SERVICE_START_PENDING:   return L"START_PENDING";
    case SERVICE_STOP_PENDING:    return L"STOP_PENDING";
    case SERVICE_PAUSED:          return L"PAUSED";
    case SERVICE_PAUSE_PENDING:   return L"PAUSE_PENDING";
    case SERVICE_CONTINUE_PENDING:return L"CONTINUE_PENDING";
    default:                      return L"UNKNOWN";
    }
}

static std::wstring ServiceStartTypeName(DWORD startType) {
    switch (startType) {
    case SERVICE_AUTO_START:    return L"Auto";
    case SERVICE_DEMAND_START:  return L"Manual";
    case SERVICE_DISABLED:      return L"Disabled";
    case SERVICE_BOOT_START:    return L"Boot";
    case SERVICE_SYSTEM_START:  return L"System";
    default:                    return L"Unknown";
    }
}

static std::wstring ServiceTypeName(DWORD serviceType) {
    if (serviceType & SERVICE_WIN32_OWN_PROCESS)   return L"OwnProcess";
    if (serviceType & SERVICE_WIN32_SHARE_PROCESS) return L"ShareProcess";
    return L"Win32";
}

static std::wstring ServiceSidTypeName(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceConfig2W(hSvc, SERVICE_CONFIG_SERVICE_SID_INFO,
            data, size, needed);
    });
    if (buffer.empty()) return L"";

    auto* sidInfo = reinterpret_cast<SERVICE_SID_INFO*>(buffer.data());
    switch (sidInfo->dwServiceSidType) {
    case SERVICE_SID_TYPE_NONE:         return L"None";
    case SERVICE_SID_TYPE_UNRESTRICTED: return L"Unrestricted";
    case SERVICE_SID_TYPE_RESTRICTED:   return L"Restricted";
    default:                            return L"Unknown";
    }
}

static std::wstring QueryServiceDll(const std::wstring& serviceName) {
    std::wstring subKey = L"SYSTEM\\CurrentControlSet\\Services\\"
        + serviceName + L"\\Parameters";
    return ExtractExecutablePath(ReadRegStringValue(HKEY_LOCAL_MACHINE,
        subKey, L"ServiceDll", 0,
        L"Service registry value changed during retries"));
}

static std::wstring QueryServiceDaclSummary(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceObjectSecurity(hSvc, DACL_SECURITY_INFORMATION,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(data), size, needed);
    });
    if (buffer.empty()) return L"";

    return SecurityDescriptorDaclSummary(
        reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data()));
}

static const wchar_t* ServiceTriggerTypeName(DWORD type) {
    switch (type) {
    case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL: return L"DeviceArrival";
    case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY: return L"IpAvailability";
    case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN: return L"DomainJoin";
    case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT: return L"FirewallPort";
    case SERVICE_TRIGGER_TYPE_GROUP_POLICY: return L"GroupPolicy";
    case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT: return L"NetworkEndpoint";
    case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE: return L"SystemStateChange";
    case SERVICE_TRIGGER_TYPE_CUSTOM: return L"CustomEtw";
    default: return L"Unknown";
    }
}

static const wchar_t* ServiceTriggerActionName(DWORD action) {
    switch (action) {
    case SERVICE_TRIGGER_ACTION_SERVICE_START: return L"Start";
    case SERVICE_TRIGGER_ACTION_SERVICE_STOP: return L"Stop";
    default: return L"?";
    }
}

static std::wstring QueryServiceTriggerSummary(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceConfig2W(hSvc, SERVICE_CONFIG_TRIGGER_INFO,
            data, size, needed);
    });
    if (buffer.empty()) return L"";
    auto* info = reinterpret_cast<SERVICE_TRIGGER_INFO*>(buffer.data());
    if (info->cTriggers == 0) return L"";

    std::wstring summary = std::to_wstring(info->cTriggers) + L" [";
    for (DWORD i = 0; i < info->cTriggers; i++) {
        if (i > 0) summary += L",";
        const auto& t = info->pTriggers[i];
        summary += ServiceTriggerActionName(t.dwAction);
        summary += L":";
        summary += ServiceTriggerTypeName(t.dwTriggerType);
    }
    summary += L"]";
    return summary;
}

static std::wstring QueryServiceRequiredPrivileges(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceConfig2W(hSvc, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            data, size, needed);
    });
    if (buffer.empty()) return L"";
    auto* info = reinterpret_cast<SERVICE_REQUIRED_PRIVILEGES_INFOW*>(buffer.data());
    if (!info->pmszRequiredPrivileges) return L"";

    std::wstring summary;
    const WCHAR* p = info->pmszRequiredPrivileges;
    while (*p) {
        if (!summary.empty()) summary += L",";
        summary += p;
        p += wcslen(p) + 1;
    }
    return summary;
}

static const wchar_t* FailureActionName(SC_ACTION_TYPE type) {
    switch (type) {
    case SC_ACTION_NONE: return L"None";
    case SC_ACTION_RESTART: return L"Restart";
    case SC_ACTION_REBOOT: return L"Reboot";
    case SC_ACTION_RUN_COMMAND: return L"RunCommand";
    default: return L"?";
    }
}

static std::wstring QueryServiceFailureActionsSummary(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceConfig2W(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS,
            data, size, needed);
    });
    if (buffer.empty()) return L"";
    auto* info = reinterpret_cast<SERVICE_FAILURE_ACTIONSW*>(buffer.data());
    bool hasActions = info->cActions > 0 && info->lpsaActions != nullptr;
    bool hasCommand = info->lpCommand && *info->lpCommand;
    if (!hasActions && !hasCommand) return L"";

    std::wstring summary;
    if (hasActions) {
        for (DWORD i = 0; i < info->cActions; i++) {
            if (i > 0) summary += L",";
            summary += FailureActionName(info->lpsaActions[i].Type);
        }
    }
    if (hasCommand) {
        if (!summary.empty()) summary += L" ";
        summary += L"RunCommand=\"";
        summary += info->lpCommand;
        summary += L"\"";
    }
    return summary;
}

static const wchar_t* LaunchProtectedName(DWORD value) {
    switch (value) {
    case SERVICE_LAUNCH_PROTECTED_NONE: return L"None";
    case SERVICE_LAUNCH_PROTECTED_WINDOWS: return L"Windows-PPL";
    case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT: return L"Windows-Light";
    case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT: return L"Antimalware-Light";
    default: return L"Unknown";
    }
}

static std::wstring QueryServiceLaunchProtected(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceConfig2W(hSvc, SERVICE_CONFIG_LAUNCH_PROTECTED,
            data, size, needed);
    });
    if (buffer.empty()) return L"";
    auto* info = reinterpret_cast<SERVICE_LAUNCH_PROTECTED_INFO*>(buffer.data());
    if (info->dwLaunchProtected == SERVICE_LAUNCH_PROTECTED_NONE) return L"";
    return LaunchProtectedName(info->dwLaunchProtected);
}

static std::wstring QueryServiceDelayedAutoStart(SC_HANDLE hSvc) {
    auto buffer = QueryServiceBuffer([&](BYTE* data, DWORD size, DWORD* needed) {
        return QueryServiceConfig2W(hSvc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            data, size, needed);
    });
    if (buffer.empty()) return L"";
    auto* info = reinterpret_cast<SERVICE_DELAYED_AUTO_START_INFO*>(buffer.data());
    return info->fDelayedAutostart ? L"true" : L"";
}

static std::wstring QueryServiceRegistryDacl(const std::wstring& serviceName) {
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
        READ_CONTROL, &hKey) != ERROR_SUCCESS) {
        ReportPartial(L"Service registry security query failed");
        return L"";
    }

    std::vector<BYTE> buffer;
    LSTATUS status = ERROR_INSUFFICIENT_BUFFER;
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD needed = static_cast<DWORD>(buffer.size());
        status = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION,
            buffer.empty() ? nullptr
                : reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data()),
            &needed);
        if (status == ERROR_SUCCESS) break;
        if (status != ERROR_INSUFFICIENT_BUFFER || needed <= buffer.size()
            || attempt == 3) break;
        buffer.resize(needed);
    }
    RegCloseKey(hKey);
    if (status != ERROR_SUCCESS || buffer.empty()) {
        ReportPartial(L"Service registry security query failed: "
            + std::to_wstring(status));
        return L"";
    }

    return SecurityDescriptorDaclSummary(
        reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data()));
}

EntryPointList EnumerateServices() {
    EntryPointList results;

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) {
        ReportPartial(L"Service manager open failed: "
            + std::to_wstring(GetLastError()));
        return results;
    }

    DWORD serviceCount = 0;
    std::vector<BYTE> buffer;
    if (!QueryServices(hScm, SERVICE_WIN32, buffer, serviceCount)) {
        CloseServiceHandle(hScm);
        return results;
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    for (DWORD i = 0; i < serviceCount; i++) {
        auto& svc = services[i];

        EntryPoint ep;
        ep.type = EntryType::Service;
        ep.name = svc.lpServiceName;

        std::wstring state = ServiceStateName(svc.ServiceStatusProcess.dwCurrentState);
        std::wstring serviceDll = QueryServiceDll(svc.lpServiceName);
        ep.details = state;
        std::wstring binaryPath;
        std::wstring executablePath;

        SC_HANDLE configHandle = OpenServiceW(hScm, svc.lpServiceName,
            SERVICE_QUERY_CONFIG);
        if (configHandle) {
            auto configBuf = QueryServiceBuffer(
                [&](BYTE* data, DWORD size, DWORD* needed) {
                    return QueryServiceConfigW(configHandle,
                        reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(data),
                        size, needed);
                });
            if (!configBuf.empty()) {
                auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(
                    configBuf.data());
                binaryPath = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
                executablePath = ExtractExecutablePath(binaryPath);

                ep.details = state
                    + L" | Start=" + ServiceStartTypeName(config->dwStartType)
                    + L" | Type=" + ServiceTypeName(config->dwServiceType);

                if (config->lpServiceStartName && wcslen(config->lpServiceStartName) > 0) {
                    ep.details += L" | Account=" + std::wstring(config->lpServiceStartName);
                }

                std::wstring sidType = ServiceSidTypeName(configHandle);
                if (!sidType.empty()) {
                    ep.details += L" | ServiceSid=" + sidType;
                }

                std::wstring triggers = QueryServiceTriggerSummary(configHandle);
                if (!triggers.empty()) {
                    ep.details += L" | Triggers=" + triggers;
                }

                std::wstring requiredPriv = QueryServiceRequiredPrivileges(configHandle);
                if (!requiredPriv.empty()) {
                    ep.details += L" | RequiredPrivs=" + requiredPriv;
                }

                std::wstring failureActions = QueryServiceFailureActionsSummary(configHandle);
                if (!failureActions.empty()) {
                    ep.details += L" | FailureActions=" + failureActions;
                }

                std::wstring delayed = QueryServiceDelayedAutoStart(configHandle);
                if (!delayed.empty()) {
                    ep.details += L" | DelayedAutoStart=" + delayed;
                }

                std::wstring launchProtected = QueryServiceLaunchProtected(configHandle);
                if (!launchProtected.empty()) {
                    ep.details += L" | LaunchProtected=" + launchProtected;
                }

                if (!binaryPath.empty() && binaryPath != executablePath) {
                    ep.details += L" | Binary=" + binaryPath;
                }
            }
            CloseServiceHandle(configHandle);
        }
        else {
            ReportPartial(L"Service open failed: "
                + std::to_wstring(GetLastError()));
        }
        if (!serviceDll.empty()) ep.details += L" | ServiceDll=" + serviceDll;

        SC_HANDLE securityHandle = OpenServiceW(hScm, svc.lpServiceName,
            READ_CONTROL);
        if (securityHandle) {
            std::wstring dacl = QueryServiceDaclSummary(securityHandle);
            if (!dacl.empty()) ep.details += L" | DACL: " + dacl;
            CloseServiceHandle(securityHandle);
        }
        else {
            ReportPartial(L"Service security open failed: "
                + std::to_wstring(GetLastError()));
        }

        std::wstring regDacl = QueryServiceRegistryDacl(svc.lpServiceName);
        if (!regDacl.empty()) {
            ep.details += L" | RegDACL: " + regDacl;
        }
        if (svc.lpDisplayName) {
            ep.details += L" | \"" + std::wstring(svc.lpDisplayName) + L"\"";
        }

        ep.ownerPid = svc.ServiceStatusProcess.dwProcessId;
        std::wstring runtimePath = ep.ownerPid == 0
            ? L""
            : g_ProcessCache.GetPath(ep.ownerPid);
        if (!serviceDll.empty()) {
            ep.ownerPath = serviceDll;
        }
        else if (!executablePath.empty()) {
            ep.ownerPath = executablePath;
        }
        else if (!binaryPath.empty()) {
            ep.ownerPath = binaryPath;
        }
        else if (!runtimePath.empty()) {
            ep.ownerPath = runtimePath;
        }
        else {
            ep.ownerPath = L"<not-running>";
        }
        if (!runtimePath.empty() && runtimePath != L"<unknown>"
            && runtimePath != ep.ownerPath) {
            ep.details += L" | Process=" + runtimePath;
        }

        results.push_back(std::move(ep));
    }

    CloseServiceHandle(hScm);
    return results;
}
