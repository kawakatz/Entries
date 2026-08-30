#include "enum_alpc.h"
#include "diagnostics.h"
#include "nt_api.h"
#include "nt_objects.h"
#include "process_utils.h"

#include <iterator>

static EntryPointList EnumerateAlpcFromDirectory(const std::wstring& dirPath) {
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
            ReportPartial(L"ALPC directory response exceeded the buffer limit");
            break;
        }

        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES) {
            ReportPartial(L"ALPC directory enumeration failed: "
                + HexCode(static_cast<unsigned long>(status)));
            break;
        }

        if (!DecodeObjectDirectoryPage(buffer, returnLength, page)) {
            ReportPartial(L"ALPC directory returned invalid data");
            break;
        }
        for (const auto& object : page) {
            if (object.typeName == L"ALPC Port") {
                EntryPoint ep;
                ep.type = EntryType::ALPC;
                ep.name = dirPath + L"\\" + object.name;
                ep.details = L"ALPC Port";
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

EntryPointList EnumerateAlpcPorts() {
    EntryPointList results;

    const std::wstring dirs[] = {
        L"\\RPC Control",
        L"\\BaseNamedObjects",
        L"\\Sessions\\0\\BaseNamedObjects",
        L"\\Windows",
    };

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    std::vector<std::wstring> searchDirs(std::begin(dirs), std::end(dirs));
    if (sessionId != 0) {
        searchDirs.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\BaseNamedObjects");
        searchDirs.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\Windows");
    }

    for (auto& dir : searchDirs) {
        auto entries = EnumerateAlpcFromDirectory(dir);
        results.insert(results.end(),
            std::make_move_iterator(entries.begin()),
            std::make_move_iterator(entries.end()));
    }

    const auto& alpcMap = g_HandleTable.GetNameToPidMap(L"ALPC Port");

    for (auto& ep : results) {
        auto it = alpcMap.find(ToLower(ep.name));
        if (it != alpcMap.end() && !it->second.empty()) {
            ep.ownerPid = *it->second.begin();
            ep.ownerPath = g_ProcessCache.GetPath(ep.ownerPid);
        }
    }

    return results;
}
