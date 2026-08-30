#include "enum_named_pipes.h"
#include "diagnostics.h"
#include "nt_objects.h"
#include "process_utils.h"
#include <unordered_map>

EntryPointList EnumerateNamedPipes() {
    EntryPointList results;

    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(L"\\\\.\\pipe\\*", &data);
    if (find == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            ReportPartial(L"Failed to enumerate named pipes");
        }
        return results;
    }

    do {
        EntryPoint entry;
        entry.type = EntryType::NamedPipe;
        entry.name = std::wstring(L"\\\\.\\pipe\\") + data.cFileName;
        entry.ownerPath = L"<unresolved>";
        results.push_back(std::move(entry));
    } while (FindNextFileW(find, &data));

    DWORD error = GetLastError();
    FindClose(find);
    if (error != ERROR_NO_MORE_FILES) {
        ReportPartial(L"Named-pipe enumeration ended early");
    }

    const std::wstring pipePrefix = L"\\Device\\NamedPipe\\";
    std::unordered_map<std::wstring, EntryPoint*> unresolved;
    for (auto& entry : results) {
        unresolved.emplace(ToLower(entry.name), &entry);
    }

    for (const auto& cached : g_HandleTable.GetCachedHandles(L"File")) {
        if (unresolved.empty()) break;
        if (!StartsWithIcase(cached.name, pipePrefix)) continue;

        std::wstring win32Name = L"\\\\.\\pipe\\"
            + cached.name.substr(pipePrefix.size());
        auto match = unresolved.find(ToLower(win32Name));
        if (match == unresolved.end()) continue;

        PipeServerInfo server;
        if (!g_HandleTable.QueryPipeServer(cached.handle, server)) continue;

        EntryPoint& entry = *match->second;
        entry.ownerPid = server.pid;
        entry.ownerPath = g_ProcessCache.GetPath(server.pid);
        if (!server.dacl.empty()) entry.details = L"DACL: " + server.dacl;
        if (server.queriedPid) {
            if (!entry.details.empty()) entry.details += L" | ";
            entry.details += L"Server=GetNamedPipeServerProcessId";
        }
        unresolved.erase(match);
    }

    return results;
}
