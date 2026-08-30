#include "enum_shared_memory.h"
#include "diagnostics.h"
#include "nt_api.h"
#include "nt_objects.h"
#include "process_utils.h"
#include "security_utils.h"
#include <aclapi.h>
#include <iterator>
#include <sstream>
#include <unordered_set>

#pragma comment(lib, "advapi32.lib")

static std::wstring FormatHex(ULONG_PTR value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << value << std::dec;
    return ss.str();
}

static std::wstring FormatAccessMask(ACCESS_MASK mask) {
    std::wstring rights;
    auto add = [&](const wchar_t* right) {
        if (!rights.empty()) rights += L",";
        rights += right;
    };

    if (mask & SECTION_MAP_READ)    add(L"MAP_READ");
    if (mask & SECTION_MAP_WRITE)   add(L"MAP_WRITE");
    if (mask & SECTION_MAP_EXECUTE) add(L"MAP_EXEC");
    if (mask & SECTION_QUERY)       add(L"QUERY");
    if (mask & SECTION_EXTEND_SIZE) add(L"EXTEND");
    if (mask & READ_CONTROL)        add(L"READ_CONTROL");
    if (mask & WRITE_DAC)           add(L"WRITE_DAC");
    if (mask & WRITE_OWNER)         add(L"WRITE_OWNER");

    if (!rights.empty()) {
        rights += L" ";
    }
    rights += L"(" + FormatHex(mask) + L")";
    return rights;
}

static std::wstring QuerySectionDaclSummary(const std::wstring& sectionPath) {
    if (!g_NtApi.NtOpenSection || !g_NtApi.RtlInitUnicodeString) {
        return L"";
    }

    UNICODE_STRING sectionName;
    g_NtApi.RtlInitUnicodeString(&sectionName, sectionPath.c_str());

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &sectionName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hSection = nullptr;
    NTSTATUS status = g_NtApi.NtOpenSection(&hSection, READ_CONTROL, &oa);
    if (status != STATUS_SUCCESS || !hSection) {
        return L"";
    }

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    DWORD err = GetSecurityInfo(hSection, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr,
        &securityDescriptor);

    std::wstring summary;
    if (err == ERROR_SUCCESS && securityDescriptor) {
        summary = SecurityDescriptorDaclSummary(securityDescriptor, 6);
    }
    if (securityDescriptor) LocalFree(securityDescriptor);

    CloseHandle(hSection);
    return summary;
}

static void AddProcessSectionHandleEntries(EntryPointList& results) {
    const auto& handles = g_HandleTable.GetCachedHandles(L"Section");
    if (handles.empty()) return;

    std::unordered_set<std::wstring> seen;

    for (const auto& cached : handles) {
        const auto& handle = cached.handle;
        if (handle.pid == 0 || handle.pid > MAXDWORD) continue;
        DWORD pid = static_cast<DWORD>(handle.pid);

        std::wstring ownerPath = g_ProcessCache.GetPath(pid);
        if (ownerPath.empty() || ownerPath == L"<unknown>") {
            continue;
        }

        std::wstring objectKey = FormatHex(reinterpret_cast<ULONG_PTR>(handle.objectAddress));
        std::wstring dedupKey = std::to_wstring(pid) + L"|" + objectKey;
        if (seen.count(dedupKey)) continue;
        seen.insert(dedupKey);

        const std::wstring& objectName = cached.name;

        EntryPoint ep;
        ep.type = EntryType::SharedMemory;
        ep.name = objectName.empty()
            ? L"<unnamed-section:" + objectKey + L">"
            : objectName;
        ep.details = L"Process section handle"
            + std::wstring(L" | Handle=") + FormatHex(handle.handleValue)
            + L" | Object=" + objectKey
            + L" | Access=" + FormatAccessMask(handle.grantedAccess);

        if (!objectName.empty()) {
            ep.details += L" | Name=" + objectName;
        }

        std::wstring dacl;
        g_HandleTable.QueryHandleDacl(handle, 6, dacl);
        if (!dacl.empty()) {
            ep.details += L" | DACL: " + dacl;
        }

        ep.ownerPid = pid;
        ep.ownerPath = ownerPath;
        results.push_back(std::move(ep));
    }
}

static EntryPointList EnumerateObjectDirectory(const std::wstring& dirPath,
    const std::wstring& filterType)
{
    EntryPointList results;

    if (!g_NtApi.IsValid()) return results;

    UNICODE_STRING usDirName;
    g_NtApi.RtlInitUnicodeString(&usDirName, dirPath.c_str());

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &usDirName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hDir = nullptr;
    NTSTATUS status = g_NtApi.NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (status != STATUS_SUCCESS) {
        return results;
    }

    std::vector<BYTE> buffer(8192);
    ULONG context = 0;
    ULONG returnLength = 0;
    BOOLEAN restart = TRUE;
    std::vector<NtObjectDirectoryEntry> page;

    while (true) {
        if (!QueryObjectDirectoryPage(
            hDir, buffer, restart, context, returnLength, status)) {
            ReportPartial(L"Shared-memory directory response exceeded the buffer limit");
            break;
        }

        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES) {
            ReportPartial(L"Shared-memory directory enumeration failed: "
                + HexCode(static_cast<unsigned long>(status)));
            break;
        }

        if (!DecodeObjectDirectoryPage(buffer, returnLength, page)) {
            ReportPartial(L"Shared-memory directory returned invalid data");
            break;
        }
        for (const auto& object : page) {
            if (filterType.empty() || object.typeName == filterType) {
                EntryPoint ep;
                ep.type = EntryType::SharedMemory;
                ep.name = dirPath + L"\\" + object.name;
                ep.details = object.typeName;
                std::wstring dacl = QuerySectionDaclSummary(ep.name);
                if (!dacl.empty()) {
                    ep.details += L" | DACL: " + dacl;
                }
                ep.ownerPath = L"<unresolved>";
                results.push_back(std::move(ep));
            }
        }

        restart = FALSE;
        if (status != STATUS_MORE_ENTRIES) break;
    }

    CloseHandle(hDir);
    return results;
}

EntryPointList EnumerateSharedMemory() {
    EntryPointList results;

    const std::wstring dirs[] = {
        L"\\BaseNamedObjects",
        L"\\Sessions\\0\\BaseNamedObjects",
    };

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    std::vector<std::wstring> searchDirs(std::begin(dirs), std::end(dirs));
    if (sessionId != 0) {
        searchDirs.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\BaseNamedObjects");
    }

    for (auto& dir : searchDirs) {
        auto entries = EnumerateObjectDirectory(dir, L"Section");
        results.insert(results.end(),
            std::make_move_iterator(entries.begin()),
            std::make_move_iterator(entries.end()));
    }

    const auto& sectionMap = g_HandleTable.GetNameToPidMap(L"Section");

    for (auto& ep : results) {
        auto it = sectionMap.find(ToLower(ep.name));
        if (it != sectionMap.end() && !it->second.empty()) {
            ep.ownerPid = *it->second.begin();
            ep.ownerPath = g_ProcessCache.GetPath(ep.ownerPid);
        }
    }

    AddProcessSectionHandleEntries(results);

    return results;
}
