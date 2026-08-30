#include "enum_mailslots.h"
#include "diagnostics.h"
#include "nt_api.h"
#include "nt_objects.h"
#include "process_utils.h"
#include <unordered_map>

static void EnumerateWin32Mailslots(EntryPointList& results) {
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(L"\\\\.\\mailslot\\*", &data);
    if (find == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            ReportPartial(L"Win32 mailslot enumeration failed");
        }
        return;
    }

    do {
        EntryPoint entry;
        entry.type = EntryType::Mailslot;
        entry.name = std::wstring(L"\\\\.\\mailslot\\") + data.cFileName;
        entry.ownerPath = L"<unresolved>";
        results.push_back(std::move(entry));
    } while (FindNextFileW(find, &data));

    DWORD error = GetLastError();
    FindClose(find);
    if (error != ERROR_NO_MORE_FILES) {
        ReportPartial(L"Win32 mailslot enumeration ended early");
    }
}

static void ResolveMailslotOwners(EntryPointList& results) {
    const std::wstring win32Prefix = L"\\\\.\\mailslot\\";
    const std::wstring nativePrefix = L"\\Device\\Mailslot\\";
    std::unordered_map<std::wstring, std::vector<const CachedHandleInfo*>> servers;
    for (const auto& cached : g_HandleTable.GetCachedHandles(L"File")) {
        if ((cached.handle.grantedAccess & FILE_READ_DATA) == 0
            || cached.handle.pid == 0 || cached.handle.pid > MAXDWORD
            || cached.name.empty()) {
            continue;
        }

        servers[ToLower(cached.name)].push_back(&cached);
    }
    for (auto& item : servers) {
        std::sort(item.second.begin(), item.second.end(),
            [](const CachedHandleInfo* left, const CachedHandleInfo* right) {
                if (left->handle.pid != right->handle.pid) {
                    return left->handle.pid < right->handle.pid;
                }
                return left->handle.handleValue < right->handle.handleValue;
            });
    }

    for (auto& entry : results) {
        std::wstring name = entry.name;
        if (StartsWithIcase(name, win32Prefix)) {
            name = nativePrefix + name.substr(win32Prefix.size());
        }
        auto found = servers.find(ToLower(name));
        if (found == servers.end()) continue;

        for (const auto* server : found->second) {
            if (server->handle.pid > MAXDWORD) continue;
            std::wstring dacl;
            if (!g_HandleTable.QueryHandleDacl(server->handle, 6, dacl)) continue;
            entry.ownerPid = static_cast<DWORD>(server->handle.pid);
            entry.ownerPath = g_ProcessCache.GetPath(entry.ownerPid);
            if (!dacl.empty()) entry.details = L"DACL: " + dacl;
            break;
        }
    }
}

EntryPointList EnumerateMailslots() {
    EntryPointList results;

    if (!g_NtApi.IsValid()) {
        ReportPartial(L"Mailslot enumeration requires NT APIs");
        EnumerateWin32Mailslots(results);
        ResolveMailslotOwners(results);
        return results;
    }

    UNICODE_STRING directoryName;
    g_NtApi.RtlInitUnicodeString(&directoryName, L"\\Device\\Mailslot");
    OBJECT_ATTRIBUTES attributes = {};
    InitializeObjectAttributes(&attributes, &directoryName, OBJ_CASE_INSENSITIVE,
        nullptr, nullptr);

    HANDLE directory = nullptr;
    NTSTATUS status = g_NtApi.NtOpenDirectoryObject(&directory,
        DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &attributes);
    if (status != STATUS_SUCCESS) {
        ReportPartial(L"Native mailslot enumeration unavailable: "
            + HexCode(static_cast<unsigned long>(status)));
        EnumerateWin32Mailslots(results);
        ResolveMailslotOwners(results);
        return results;
    }

    std::vector<BYTE> buffer(4096);
    ULONG context = 0;
    ULONG returnLength = 0;
    BOOLEAN restart = TRUE;
    std::vector<NtObjectDirectoryEntry> page;
    while (true) {
        if (!QueryObjectDirectoryPage(directory, buffer, restart, context,
            returnLength, status)) {
            ReportPartial(L"Mailslot directory response exceeded the buffer limit");
            break;
        }
        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES) {
            ReportPartial(L"Native mailslot enumeration failed: "
                + HexCode(static_cast<unsigned long>(status)));
            break;
        }

        if (!DecodeObjectDirectoryPage(buffer, returnLength, page)) {
            ReportPartial(L"Mailslot directory returned invalid data");
            break;
        }
        for (const auto& object : page) {
            EntryPoint entry;
            entry.type = EntryType::Mailslot;
            entry.name = L"\\Device\\Mailslot\\" + object.name;
            entry.ownerPath = L"<unresolved>";
            results.push_back(std::move(entry));
        }

        restart = FALSE;
        if (status != STATUS_MORE_ENTRIES) break;
    }

    CloseHandle(directory);
    ResolveMailslotOwners(results);
    return results;
}
