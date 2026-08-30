#include "enum_drivers.h"
#include "diagnostics.h"
#include "nt_api.h"
#include "nt_objects.h"
#include "process_utils.h"

#include <psapi.h>
#include <unordered_map>
#include <unordered_set>
#include <cwctype>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

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
            ReportPartial(L"Driver service detail query failed: "
                + std::to_wstring(error));
            return {};
        }
        buffer.resize(needed);
    }
    return {};
}

static bool QueryServices(SC_HANDLE hScm, std::vector<BYTE>& buffer,
    DWORD& count)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD needed = 0;
        DWORD resume = 0;
        count = 0;
        if (EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
            SERVICE_STATE_ALL, buffer.empty() ? nullptr : buffer.data(),
            static_cast<DWORD>(buffer.size()), &needed, &count, &resume,
            nullptr)) return true;
        DWORD error = GetLastError();
        if (error != ERROR_MORE_DATA || needed == 0
            || needed > MAXDWORD - buffer.size() || attempt == 3) {
            ReportPartial(L"Driver service enumeration failed: "
                + std::to_wstring(error));
            return false;
        }
        buffer.resize(buffer.size() + needed);
    }
    return false;
}

struct DriverServiceInfo {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring rawImagePath;
    std::wstring imagePath;
    std::wstring state;
    std::wstring serviceType;
    std::wstring startType;
};

struct ObjectDirectoryEntry {
    std::wstring path;
    std::wstring name;
    std::wstring typeName;
};

struct DriverServiceIndex {
    std::unordered_map<std::wstring, size_t> byServiceName;
    std::unordered_map<std::wstring, size_t> byImageStem;
    std::unordered_map<std::wstring, size_t> byImagePath;
};

static std::wstring StripCommandLineArguments(const std::wstring& value) {
    std::wstring path = TrimWhitespace(value);
    if (path.empty()) return path;

    if (path[0] == L'"') {
        size_t endQuote = path.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            return path.substr(1, endQuote - 1);
        }
    }

    std::wstring lower = ToLower(path);
    for (const auto& ext : { L".sys", L".exe" }) {
        size_t pos = lower.find(ext);
        if (pos != std::wstring::npos) {
            return path.substr(0, pos + wcslen(ext));
        }
    }

    size_t space = path.find(L' ');
    if (space != std::wstring::npos) {
        return path.substr(0, space);
    }

    return path;
}

static std::wstring GetWindowsDirectoryPath() {
    WCHAR windowsDir[MAX_PATH] = {};
    UINT len = GetWindowsDirectoryW(windowsDir, _countof(windowsDir));
    if (len == 0 || len >= _countof(windowsDir)) return L"C:\\Windows";
    return windowsDir;
}

static std::wstring NtPathToDosPath(const std::wstring& path) {
    if (path.size() >= 2 && path[1] == L':') return path;

    for (wchar_t drive = L'A'; drive <= L'Z'; drive++) {
        WCHAR driveName[] = { drive, L':', L'\0' };
        WCHAR target[1024] = {};
        if (!QueryDosDeviceW(driveName, target, _countof(target))) continue;

        std::wstring targetPath = target;
        if (!StartsWithIcase(path, targetPath)) continue;

        if (path.size() > targetPath.size() && path[targetPath.size()] != L'\\') {
            continue;
        }

        return std::wstring(1, drive) + L":" + path.substr(targetPath.size());
    }

    return path;
}

static std::wstring NormalizeDriverImagePath(const std::wstring& rawPath) {
    std::wstring path = StripCommandLineArguments(rawPath);
    path = ExpandEnvironmentPath(path);
    path = TrimWhitespace(path);

    if (StartsWithIcase(path, L"\\??\\")) {
        path = path.substr(4);
    }
    else if (StartsWithIcase(path, L"\\DosDevices\\")) {
        path = path.substr(12);
    }

    if (StartsWithIcase(path, L"\\SystemRoot")) {
        std::wstring suffix = path.substr(wcslen(L"\\SystemRoot"));
        path = GetWindowsDirectoryPath() + suffix;
    }
    else if (StartsWithIcase(path, L"System32\\")) {
        path = GetWindowsDirectoryPath() + L"\\" + path;
    }
    else if (StartsWithIcase(path, L"\\Device\\")) {
        path = NtPathToDosPath(path);
    }

    return path;
}

static std::wstring FileNameStem(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    std::wstring fileName = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    size_t dot = fileName.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        fileName = fileName.substr(0, dot);
    }
    return ToLower(fileName);
}

static std::wstring ObjectLeafName(const std::wstring& path) {
    size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return path;
    return path.substr(slash + 1);
}

static std::wstring DeviceRootName(const std::wstring& path) {
    const std::wstring prefix = L"\\Device\\";
    if (!StartsWithIcase(path, prefix)) return L"";

    size_t start = prefix.size();
    size_t slash = path.find(L'\\', start);
    if (slash == std::wstring::npos) return path.substr(start);
    return path.substr(start, slash - start);
}

static std::wstring StripTrailingDigits(const std::wstring& value) {
    size_t end = value.size();
    while (end > 0 && iswdigit(value[end - 1])) {
        end--;
    }
    if (end == 0 || end == value.size()) return value;
    return value.substr(0, end);
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

static std::wstring DriverServiceTypeName(DWORD serviceType) {
    if (serviceType & SERVICE_FILE_SYSTEM_DRIVER) return L"FileSystem";
    if (serviceType & SERVICE_RECOGNIZER_DRIVER)  return L"Recognizer";
    if (serviceType & SERVICE_KERNEL_DRIVER)      return L"Kernel";
    return L"Driver";
}

static EntryPoint MakeDriverEntry(const std::wstring& name,
    const std::wstring& details,
    const std::wstring& ownerPath)
{
    EntryPoint ep;
    ep.type = EntryType::Driver;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<unresolved>" : ownerPath;
    ep.ownerPrivilege = L"Kernel";
    return ep;
}

static std::vector<DriverServiceInfo> EnumerateDriverServices() {
    std::vector<DriverServiceInfo> services;

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) {
        ReportPartial(L"Driver service manager open failed: "
            + std::to_wstring(GetLastError()));
        return services;
    }

    DWORD serviceCount = 0;
    std::vector<BYTE> buffer;
    if (!QueryServices(hScm, buffer, serviceCount)) {
        CloseServiceHandle(hScm);
        return services;
    }

    auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    services.reserve(serviceCount);

    for (DWORD i = 0; i < serviceCount; i++) {
        const auto& svc = entries[i];

        DriverServiceInfo info;
        info.serviceName = svc.lpServiceName ? svc.lpServiceName : L"";
        info.displayName = svc.lpDisplayName ? svc.lpDisplayName : L"";
        info.state = ServiceStateName(svc.ServiceStatusProcess.dwCurrentState);
        info.serviceType = DriverServiceTypeName(svc.ServiceStatusProcess.dwServiceType);

        SC_HANDLE hSvc = OpenServiceW(hScm, info.serviceName.c_str(), SERVICE_QUERY_CONFIG);
        DWORD openError = hSvc ? ERROR_SUCCESS : GetLastError();
        if (hSvc) {
            auto configBuffer = QueryServiceBuffer(
                [&](BYTE* data, DWORD size, DWORD* needed) {
                    return QueryServiceConfigW(hSvc,
                        reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(data),
                        size, needed);
                });
            if (!configBuffer.empty()) {
                auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());
                info.rawImagePath = config->lpBinaryPathName ? config->lpBinaryPathName : L"";
                info.imagePath = NormalizeDriverImagePath(info.rawImagePath);
                info.startType = ServiceStartTypeName(config->dwStartType);
                info.serviceType = DriverServiceTypeName(config->dwServiceType);
            }
            CloseServiceHandle(hSvc);
        }
        else {
            ReportPartial(L"Driver service open failed: "
                + std::to_wstring(openError));
        }

        services.push_back(std::move(info));
    }

    CloseServiceHandle(hScm);
    return services;
}

static DriverServiceIndex BuildDriverServiceIndex(const std::vector<DriverServiceInfo>& services) {
    DriverServiceIndex index;

    for (size_t i = 0; i < services.size(); i++) {
        const auto& svc = services[i];
        if (!svc.serviceName.empty()) {
            index.byServiceName[ToLower(svc.serviceName)] = i;
        }

        if (!svc.imagePath.empty()) {
            index.byImagePath[ToLower(svc.imagePath)] = i;

            std::wstring stem = FileNameStem(svc.imagePath);
            if (!stem.empty()) {
                index.byImageStem[stem] = i;
            }
        }
    }

    return index;
}

static const DriverServiceInfo* FindServiceByNameLike(const std::wstring& name,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    std::wstring key = ToLower(name);

    auto it = index.byServiceName.find(key);
    if (it != index.byServiceName.end()) return &services[it->second];

    it = index.byImageStem.find(key);
    if (it != index.byImageStem.end()) return &services[it->second];

    std::wstring withoutDigits = StripTrailingDigits(key);
    if (withoutDigits != key) {
        it = index.byServiceName.find(withoutDigits);
        if (it != index.byServiceName.end()) return &services[it->second];

        it = index.byImageStem.find(withoutDigits);
        if (it != index.byImageStem.end()) return &services[it->second];
    }

    return nullptr;
}

static const DriverServiceInfo* FindServiceByPath(const std::wstring& path,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    auto it = index.byImagePath.find(ToLower(path));
    if (it != index.byImagePath.end()) return &services[it->second];
    return nullptr;
}

static const DriverServiceInfo* FindServiceForDevicePath(const std::wstring& path,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    std::wstring rootName = DeviceRootName(path);
    if (rootName.empty()) return nullptr;
    return FindServiceByNameLike(rootName, services, index);
}

static std::wstring ServiceReferenceDetails(const DriverServiceInfo* service) {
    if (!service) return L"";

    std::wstring details = L" | Service=" + service->serviceName;
    if (!service->displayName.empty()) {
        details += L" \"" + service->displayName + L"\"";
    }
    return details;
}

static std::vector<ObjectDirectoryEntry> QueryObjectDirectory(const std::wstring& dirPath) {
    std::vector<ObjectDirectoryEntry> results;
    if (!g_NtApi.IsValid()) {
        ReportPartial(L"Driver object enumeration requires NT APIs");
        return results;
    }

    UNICODE_STRING usDirName;
    g_NtApi.RtlInitUnicodeString(&usDirName, dirPath.c_str());

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &usDirName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hDir = nullptr;
    NTSTATUS status = g_NtApi.NtOpenDirectoryObject(
        &hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (status != STATUS_SUCCESS) {
        ReportPartial(L"Driver object directory open failed: "
            + HexCode(static_cast<unsigned long>(status)));
        return results;
    }

    std::vector<BYTE> buffer(8192);
    ULONG context = 0;
    ULONG returnLength = 0;
    BOOLEAN restart = TRUE;
    std::vector<NtObjectDirectoryEntry> page;

    while (true) {
        if (!QueryObjectDirectoryPage(hDir, buffer, restart, context,
            returnLength, status)) {
            ReportPartial(L"Driver object directory response exceeded the buffer limit");
            break;
        }

        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES) {
            ReportPartial(L"Driver object directory enumeration failed: "
                + HexCode(static_cast<unsigned long>(status)));
            break;
        }

        if (!DecodeObjectDirectoryPage(buffer, returnLength, page)) {
            ReportPartial(L"Driver object directory returned invalid data");
            break;
        }
        for (const auto& object : page) {
            ObjectDirectoryEntry item;
            item.name = object.name;
            item.typeName = object.typeName;
            item.path = dirPath + L"\\" + item.name;
            results.push_back(std::move(item));
        }

        restart = FALSE;
        if (status != STATUS_MORE_ENTRIES) break;
    }

    CloseHandle(hDir);
    return results;
}

static void CollectObjectDirectoryTree(const std::wstring& dirPath,
    int depth,
    int maxDepth,
    std::vector<ObjectDirectoryEntry>& output,
    std::unordered_set<std::wstring>& visited)
{
    std::wstring key = ToLower(dirPath);
    if (visited.count(key)) return;
    visited.insert(key);

    auto entries = QueryObjectDirectory(dirPath);
    for (const auto& entry : entries) {
        output.push_back(entry);
        if (entry.typeName == L"Directory" && depth < maxDepth) {
            CollectObjectDirectoryTree(entry.path, depth + 1, maxDepth, output, visited);
        }
    }
}

static void AddDriverServiceEntries(EntryPointList& results,
    const std::vector<DriverServiceInfo>& services)
{
    for (const auto& service : services) {
        std::wstring details = L"Driver service | " + service.state
            + L" | " + service.serviceType;

        if (!service.startType.empty()) {
            details += L" | Start=" + service.startType;
        }
        if (!service.displayName.empty()) {
            details += L" | \"" + service.displayName + L"\"";
        }
        if (!service.rawImagePath.empty() && service.rawImagePath != service.imagePath) {
            details += L" | RawPath=" + service.rawImagePath;
        }

        results.push_back(MakeDriverEntry(service.serviceName, details, service.imagePath));
    }
}

static void AddLoadedKernelModuleEntries(EntryPointList& results,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    DWORD bytesNeeded = 0;
    std::vector<LPVOID> drivers(1024);
    bool complete = false;
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD bufferBytes = static_cast<DWORD>(drivers.size() * sizeof(LPVOID));
        if (!EnumDeviceDrivers(drivers.data(),
            bufferBytes, &bytesNeeded)) {
            ReportPartial(L"Loaded driver enumeration failed: "
                + std::to_wstring(GetLastError()));
            return;
        }
        if (bytesNeeded <= bufferBytes) {
            complete = true;
            break;
        }
        if (bytesNeeded > 16 * 1024 * 1024) {
            ReportPartial(L"Loaded driver list exceeded the buffer limit");
            return;
        }
        drivers.resize((bytesNeeded + sizeof(LPVOID) - 1) / sizeof(LPVOID));
    }
    if (!complete) {
        ReportPartial(L"Loaded driver list changed during retries");
        return;
    }

    if (bytesNeeded == 0 || bytesNeeded % sizeof(LPVOID) != 0) {
        ReportPartial(L"Loaded driver list had an invalid size");
        return;
    }
    size_t count = bytesNeeded / sizeof(LPVOID);
    bool reportedNull = false;
    bool reportedName = false;
    bool reportedPath = false;
    for (size_t i = 0; i < count; i++) {
        if (!drivers[i]) {
            if (!reportedNull) {
                ReportPartial(L"Loaded driver list contained null addresses");
                reportedNull = true;
            }
            continue;
        }

        WCHAR baseName[MAX_PATH] = {};
        WCHAR imagePath[MAX_PATH * 4] = {};
        DWORD baseLength = GetDeviceDriverBaseNameW(
            drivers[i], baseName, _countof(baseName));
        if (baseLength == 0 || baseLength >= _countof(baseName)) {
            if (!reportedName) {
                ReportPartial(L"Loaded driver base-name query failed or was truncated");
                reportedName = true;
            }
            continue;
        }
        DWORD pathLength = GetDeviceDriverFileNameW(
            drivers[i], imagePath, _countof(imagePath));
        if (pathLength == 0 || pathLength >= _countof(imagePath)) {
            if (!reportedPath) {
                ReportPartial(L"Loaded driver path query failed or was truncated");
                reportedPath = true;
            }
            continue;
        }

        std::wstring normalizedPath = NormalizeDriverImagePath(imagePath);
        if (normalizedPath.empty()) {
            if (!reportedPath) {
                ReportPartial(L"Loaded driver path normalization failed");
                reportedPath = true;
            }
            continue;
        }
        const DriverServiceInfo* service = FindServiceByPath(normalizedPath, services, index);

        std::wstring details = L"Loaded kernel module";
        details += ServiceReferenceDetails(service);

        results.push_back(MakeDriverEntry(
            baseName,
            details,
            normalizedPath));
    }
}

static void AddDriverObjectEntries(EntryPointList& results,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    std::vector<ObjectDirectoryEntry> entries;
    std::unordered_set<std::wstring> visited;

    CollectObjectDirectoryTree(L"\\Driver", 0, 0, entries, visited);
    CollectObjectDirectoryTree(L"\\FileSystem", 0, 2, entries, visited);

    for (const auto& entry : entries) {
        if (entry.typeName != L"Driver") continue;

        const DriverServiceInfo* service = FindServiceByNameLike(
            ObjectLeafName(entry.path), services, index);

        std::wstring details = L"Driver object";
        details += ServiceReferenceDetails(service);

        results.push_back(MakeDriverEntry(entry.path, details,
            service ? service->imagePath : L""));
    }
}

static void AddDeviceObjectEntries(EntryPointList& results,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    std::vector<ObjectDirectoryEntry> entries;
    std::unordered_set<std::wstring> visited;
    CollectObjectDirectoryTree(L"\\Device", 0, 2, entries, visited);

    for (const auto& entry : entries) {
        if (entry.typeName != L"Device") continue;

        const DriverServiceInfo* service = FindServiceForDevicePath(
            entry.path, services, index);

        std::wstring details = L"Device object";
        details += ServiceReferenceDetails(service);

        std::wstring dacl = QueryNativeDeviceDacl(entry.path);
        if (!dacl.empty()) {
            details += L" | DACL: " + dacl;
        }

        results.push_back(MakeDriverEntry(entry.path, details,
            service ? service->imagePath : L""));
    }
}

static std::vector<std::wstring> QueryDosDeviceNames() {
    DWORD chars = 32768;

    for (;;) {
        std::vector<WCHAR> buffer(chars);
        DWORD used = QueryDosDeviceW(nullptr, buffer.data(), chars);
        if (used != 0) {
            std::vector<std::wstring> names;
            const WCHAR* cursor = buffer.data();
            while (*cursor) {
                std::wstring name = cursor;
                names.push_back(name);
                cursor += name.size() + 1;
            }
            return names;
        }

        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER || chars >= 1024 * 1024) {
            ReportPartial(L"DOS device name enumeration failed: "
                + std::to_wstring(error));
            return {};
        }

        chars *= 2;
    }
}

static std::wstring QueryDosDeviceTarget(const std::wstring& name) {
    DWORD chars = 4096;

    for (;;) {
        std::vector<WCHAR> buffer(chars);
        DWORD used = QueryDosDeviceW(name.c_str(), buffer.data(), chars);
        if (used != 0) {
            return buffer.data();
        }

        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER || chars >= 1024 * 1024) {
            ReportPartial(L"DOS device target query failed: "
                + std::to_wstring(error));
            return L"";
        }

        chars *= 2;
    }
}

static void AddDosDeviceLinkEntries(EntryPointList& results,
    const std::vector<DriverServiceInfo>& services,
    const DriverServiceIndex& index)
{
    std::unordered_set<std::wstring> seen;

    for (const auto& dosName : QueryDosDeviceNames()) {
        std::wstring target = QueryDosDeviceTarget(dosName);
        if (target.empty() || !StartsWithIcase(target, L"\\Device\\")) {
            continue;
        }

        std::wstring key = ToLower(dosName + L"->" + target);
        if (seen.count(key)) continue;
        seen.insert(key);

        const DriverServiceInfo* service = FindServiceForDevicePath(
            target, services, index);

        std::wstring details = L"DOS device link -> " + target;
        details += ServiceReferenceDetails(service);

        results.push_back(MakeDriverEntry(L"\\\\.\\" + dosName, details,
            service ? service->imagePath : L""));
    }
}

EntryPointList EnumerateDriverSurfaces() {
    EntryPointList results;

    auto services = EnumerateDriverServices();
    auto index = BuildDriverServiceIndex(services);

    AddDriverServiceEntries(results, services);
    AddLoadedKernelModuleEntries(results, services, index);
    AddDriverObjectEntries(results, services, index);
    AddDeviceObjectEntries(results, services, index);
    AddDosDeviceLinkEntries(results, services, index);

    return results;
}
