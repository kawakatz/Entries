#include "enum_com.h"
#include "process_utils.h"
#include "registry_utils.h"
#include "security_utils.h"

#include <set>

struct ComRegistryView {
    REGSAM flag;
    const wchar_t* label;
};

struct ComHive {
    HKEY root;
    std::wstring path;
    const wchar_t* label;
};

static std::wstring ReadRegistrySecurityDescriptorSummary(HKEY hKey,
    const wchar_t* valueName)
{
    DWORD type = 0;
    std::vector<BYTE> buffer(256);
    if (!ReadRegData(hKey, valueName, type, buffer)
        || type != REG_BINARY || buffer.empty()) {
        return L"";
    }

    auto* sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(buffer.data());
    return SecurityDescriptorDaclSummary(sd);
}

static void AddComEntry(EntryPointList& results,
    std::set<std::wstring>& seen,
    const std::wstring& dedupKey,
    const std::wstring& clsid,
    const std::wstring& details,
    const std::wstring& ownerPath)
{
    if (seen.count(dedupKey)) return;
    seen.insert(dedupKey);

    EntryPoint ep;
    ep.type = EntryType::COM;
    ep.name = clsid;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<unresolved>" : ownerPath;
    results.push_back(std::move(ep));
}

static void EmitServerEntry(EntryPointList& results,
    std::set<std::wstring>& seen,
    HKEY hClsidEntry,
    const wchar_t* subKeyName,
    const wchar_t* serverKind,
    const ComRegistryView& view,
    const ComHive& hive,
    const std::wstring& clsid,
    const std::wstring& displayName,
    const std::wstring& appId,
    const std::wstring& elevation,
    const std::wstring& treatAs)
{
    HKEY hServer = nullptr;
    if (RegOpenKeyExW(hClsidEntry, subKeyName, 0, KEY_READ, &hServer)
        != ERROR_SUCCESS) {
        return;
    }

    std::wstring rawServerPath;
    bool hasPath = ReadRegString(hServer, nullptr, rawServerPath);

    std::wstring threadingModel;
    ReadRegString(hServer, L"ThreadingModel", threadingModel);

    std::wstring serverExecutable;
    ReadRegString(hServer, L"ServerExecutable", serverExecutable);

    RegCloseKey(hServer);

    if (!hasPath) return;

    std::wstring executablePath = ExtractExecutablePath(rawServerPath);
    if (!serverExecutable.empty()) {
        executablePath = ExtractExecutablePath(serverExecutable);
    }

    std::wstring details = std::wstring(serverKind)
        + L" | " + hive.label
        + L" | View=" + view.label;

    if (!threadingModel.empty()) {
        details += L" | Threading=" + threadingModel;
    }
    if (!appId.empty()) details += L" | AppID=" + appId;
    if (!elevation.empty()) details += L" | " + elevation;
    if (!treatAs.empty()) details += L" | TreatAs=" + treatAs;
    if (!rawServerPath.empty() && rawServerPath != executablePath) {
        details += L" | Command=" + rawServerPath;
    }
    if (!serverExecutable.empty()) {
        details += L" | ServerExecutable=" + serverExecutable;
    }
    if (!displayName.empty()) {
        details += L" | \"" + displayName + L"\"";
    }

    std::wstring dedup = std::wstring(serverKind) + L"|" + hive.label
        + L"|" + view.label + L"|" + clsid + L"|" + executablePath;

    AddComEntry(results, seen, dedup, clsid, details, executablePath);
}

static void EmitAppIdEntries(EntryPointList& results,
    std::set<std::wstring>& seen,
    const ComRegistryView& view,
    const ComHive& hive,
    const std::wstring& clsid,
    const std::wstring& displayName,
    const std::wstring& appId)
{
    if (appId.empty()) return;

    auto openAppId = [&](HKEY& outKey) -> bool {
        std::wstring base = hive.path.empty()
            ? std::wstring(L"AppID\\") + appId
            : hive.path + L"\\AppID\\" + appId;
        if (RegOpenKeyExW(hive.root, base.c_str(), 0,
            KEY_READ | view.flag, &outKey) == ERROR_SUCCESS) {
            return true;
        }
        std::wstring fallback = std::wstring(L"AppID\\") + appId;
        return RegOpenKeyExW(HKEY_CLASSES_ROOT, fallback.c_str(), 0,
            KEY_READ | view.flag, &outKey) == ERROR_SUCCESS;
    };

    HKEY hAppId = nullptr;
    if (!openAppId(hAppId)) return;

    std::wstring localService;
    std::wstring runAs;
    std::wstring dllSurrogate;
    std::wstring dllSurrogateExe;
    std::wstring remoteServer;
    std::wstring rotFlags;
    DWORD activateAtStorage = 0;

    ReadRegString(hAppId, L"LocalService", localService);
    ReadRegString(hAppId, L"RunAs", runAs);
    bool hasDllSurrogate = ReadRegString(hAppId, L"DllSurrogate", dllSurrogate);
    ReadRegString(hAppId, L"DllSurrogateExecutable", dllSurrogateExe);
    ReadRegString(hAppId, L"RemoteServerName", remoteServer);
    ReadRegString(hAppId, L"RotFlags", rotFlags);
    bool hasActivateAtStorage = ReadRegDword(hAppId,
        L"ActivateAtStorage", activateAtStorage);

    std::wstring launchPermission =
        ReadRegistrySecurityDescriptorSummary(hAppId, L"LaunchPermission");
    std::wstring accessPermission =
        ReadRegistrySecurityDescriptorSummary(hAppId, L"AccessPermission");

    auto buildBaseDetails = [&]() {
        std::wstring details = std::wstring(L"AppID | ") + hive.label
            + L" | View=" + view.label
            + L" | AppID=" + appId;
        if (!runAs.empty()) details += L" | RunAs=" + runAs;
        if (!launchPermission.empty()) {
            details += L" | LaunchDACL: " + launchPermission;
        }
        if (!accessPermission.empty()) {
            details += L" | AccessDACL: " + accessPermission;
        }
        if (!remoteServer.empty()) {
            details += L" | RemoteServerName=" + remoteServer;
        }
        if (!rotFlags.empty()) details += L" | RotFlags=" + rotFlags;
        if (hasActivateAtStorage) {
            details += L" | ActivateAtStorage="
                + std::to_wstring(activateAtStorage);
        }
        if (!displayName.empty()) {
            details += L" | \"" + displayName + L"\"";
        }
        return details;
    };

    if (!localService.empty()) {
        std::wstring servicePath = ResolveServiceComponentPath(localService);
        std::wstring details = buildBaseDetails()
            + L" | LocalService=" + localService;

        std::wstring dedup = std::wstring(L"appid-localservice|") + hive.label
            + L"|" + view.label + L"|" + clsid + L"|" + localService;

        AddComEntry(results, seen, dedup, clsid, details,
            servicePath.empty()
                ? L"<service:" + localService + L">"
                : servicePath);
    }

    if (hasDllSurrogate || !dllSurrogateExe.empty()) {
        std::wstring details = buildBaseDetails()
            + L" | DllSurrogate=\"" + dllSurrogate + L"\"";
        if (!dllSurrogateExe.empty()) {
            details += L" | DllSurrogateExecutable=" + dllSurrogateExe;
        }

        std::wstring resolvedHost = !dllSurrogateExe.empty()
            ? ExtractExecutablePath(dllSurrogateExe)
            : (dllSurrogate.empty() ? L"<dllhost.exe>"
                                    : ExtractExecutablePath(dllSurrogate));

        std::wstring dedup = std::wstring(L"appid-dllsurrogate|") + hive.label
            + L"|" + view.label + L"|" + clsid + L"|" + resolvedHost;
        AddComEntry(results, seen, dedup, clsid, details, resolvedHost);
    }

    if (localService.empty() && !hasDllSurrogate && dllSurrogateExe.empty()
        && (!launchPermission.empty() || !accessPermission.empty()
            || !remoteServer.empty() || !rotFlags.empty()
            || hasActivateAtStorage)) {
        std::wstring details = buildBaseDetails();
        std::wstring dedup = std::wstring(L"appid-permissions|") + hive.label
            + L"|" + view.label + L"|" + clsid + L"|" + appId;
        AddComEntry(results, seen, dedup, clsid, details,
            std::wstring(L"<appid:") + appId + L">");
    }

    RegCloseKey(hAppId);
}

static void EnumerateClsidUnderHive(EntryPointList& results,
    std::set<std::wstring>& seen,
    const ComHive& hive,
    const ComRegistryView& view)
{
    std::wstring base = hive.path.empty()
        ? std::wstring(L"CLSID")
        : hive.path + L"\\CLSID";

    HKEY hClsidKey = nullptr;
    if (RegOpenKeyExW(hive.root, base.c_str(), 0,
        KEY_READ | view.flag, &hClsidKey) != ERROR_SUCCESS) {
        return;
    }

    for (const auto& clsidStr : EnumOpenKeySubKeys(hClsidKey,
        L"COM CLSID registry")) {
        std::wstring displayName;
        std::wstring appId;
        std::wstring treatAs;
        std::wstring elevation;

        HKEY hClsidEntry = nullptr;
        if (RegOpenKeyExW(hClsidKey, clsidStr.c_str(), 0,
            KEY_READ, &hClsidEntry) != ERROR_SUCCESS) {
            continue;
        }

        ReadRegString(hClsidEntry, nullptr, displayName);
        ReadRegString(hClsidEntry, L"AppID", appId);

        HKEY hTreatAs = nullptr;
        if (RegOpenKeyExW(hClsidEntry, L"TreatAs", 0, KEY_READ, &hTreatAs)
            == ERROR_SUCCESS) {
            ReadRegString(hTreatAs, nullptr, treatAs);
            RegCloseKey(hTreatAs);
        }

        HKEY hElevation = nullptr;
        if (RegOpenKeyExW(hClsidEntry, L"Elevation", 0, KEY_READ, &hElevation)
            == ERROR_SUCCESS) {
            DWORD enabled = 0;
            std::wstring localized;
            std::wstring iconRef;
            ReadRegDword(hElevation, L"Enabled", enabled);
            ReadRegString(hElevation, L"LocalizedString", localized);
            ReadRegString(hElevation, L"IconReference", iconRef);
            if (enabled) {
                elevation = L"AutoElevate";
                if (!localized.empty()) {
                    elevation += L"=\"" + localized + L"\"";
                }
                if (!iconRef.empty()) elevation += L"|Icon=" + iconRef;
            }
            RegCloseKey(hElevation);
        }

        struct ServerKind {
            const wchar_t* subKey;
            const wchar_t* label;
        };
        const ServerKind kinds[] = {
            { L"LocalServer32",     L"LocalServer32" },
            { L"InprocServer32",    L"InprocServer32" },
            { L"InprocHandler32",   L"InprocHandler32" },
            { L"LocalServer",       L"LocalServer (legacy)" },
            { L"InprocServer",      L"InprocServer (legacy)" },
        };
        for (const auto& kind : kinds) {
            EmitServerEntry(results, seen, hClsidEntry, kind.subKey, kind.label,
                view, hive, clsidStr, displayName, appId, elevation, treatAs);
        }

        RegCloseKey(hClsidEntry);

        EmitAppIdEntries(results, seen, view, hive, clsidStr, displayName, appId);
    }

    RegCloseKey(hClsidKey);
}

static void AddMachineDcomDefaults(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    if (seen.count(L"machine-dcom-defaults")) return;
    seen.insert(L"machine-dcom-defaults");

    HKEY hOle = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Ole", 0,
        KEY_READ, &hOle) != ERROR_SUCCESS) {
        return;
    }

    std::wstring legacyImpersonation;
    std::wstring enableDcom;
    ReadRegString(hOle, L"LegacyImpersonationLevel", legacyImpersonation);
    ReadRegString(hOle, L"EnableDCOM", enableDcom);

    std::wstring defaultLaunch =
        ReadRegistrySecurityDescriptorSummary(hOle, L"DefaultLaunchPermission");
    std::wstring defaultAccess =
        ReadRegistrySecurityDescriptorSummary(hOle, L"DefaultAccessPermission");
    std::wstring machineLaunch =
        ReadRegistrySecurityDescriptorSummary(hOle, L"MachineLaunchRestriction");
    std::wstring machineAccess =
        ReadRegistrySecurityDescriptorSummary(hOle, L"MachineAccessRestriction");

    RegCloseKey(hOle);

    std::wstring details = L"Machine-wide DCOM defaults";
    if (!enableDcom.empty()) details += L" | EnableDCOM=" + enableDcom;
    if (!legacyImpersonation.empty()) {
        details += L" | LegacyImpersonationLevel=" + legacyImpersonation;
    }
    if (!defaultLaunch.empty()) details += L" | DefaultLaunchDACL: " + defaultLaunch;
    if (!defaultAccess.empty()) details += L" | DefaultAccessDACL: " + defaultAccess;
    if (!machineLaunch.empty()) details += L" | MachineLaunchRestriction: " + machineLaunch;
    if (!machineAccess.empty()) details += L" | MachineAccessRestriction: " + machineAccess;

    EntryPoint ep;
    ep.type = EntryType::COM;
    ep.name = L"<machine-defaults>";
    ep.details = details;
    ep.ownerPath = L"<HKLM\\Software\\Microsoft\\Ole>";
    results.push_back(std::move(ep));
}

EntryPointList EnumerateComServers() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const ComRegistryView views[] = {
        { KEY_WOW64_64KEY, L"64-bit" },
        { KEY_WOW64_32KEY, L"32-bit" },
    };

    const ComHive hives[] = {
        { HKEY_CURRENT_USER,  L"Software\\Classes",  L"HKCU\\Software\\Classes" },
        { HKEY_LOCAL_MACHINE, L"Software\\Classes",  L"HKLM\\Software\\Classes" },
    };

    for (const auto& hive : hives) {
        for (const auto& view : views) {
            EnumerateClsidUnderHive(results, seen, hive, view);
        }
    }

    AddMachineDcomDefaults(results, seen);

    return results;
}
