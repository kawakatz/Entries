#pragma once

#include "common.h"
#include "nt_api.h"
#include <set>
#include <unordered_map>

int RunNativeQueryWorker();

struct HandleInfo {
    ULONG_PTR pid;
    ULONG_PTR handleValue;
    USHORT objectTypeIndex;
    ACCESS_MASK grantedAccess;
    PVOID objectAddress;
};

struct CachedHandleInfo {
    HandleInfo handle;
    std::wstring name;
};

struct PipeServerInfo {
    DWORD pid = 0;
    std::wstring dacl;
    bool queriedPid = false;
};

std::wstring QueryNativeDeviceDacl(const std::wstring& devicePath);

class SystemHandleTable {
public:
    bool Build(const std::vector<std::wstring>& typeNames);

    USHORT GetTypeIndex(const std::wstring& typeName) const;
    const std::vector<CachedHandleInfo>& GetCachedHandles(
        const std::wstring& typeName) const;
    const std::unordered_map<std::wstring, std::set<DWORD>>& GetNameToPidMap(
        const std::wstring& typeName) const;
    bool QueryPipeServer(const HandleInfo& handle, PipeServerInfo& info) const;
    bool QueryHandleDacl(const HandleInfo& handle, size_t maxAces,
        std::wstring& dacl) const;

private:
    std::vector<HandleInfo> m_handles;
    std::unordered_map<std::wstring, USHORT> m_typeNameToIndex;
    std::unordered_map<std::wstring, std::vector<CachedHandleInfo>> m_handleCache;
    std::unordered_map<std::wstring,
        std::unordered_map<std::wstring, std::set<DWORD>>> m_nameToPidCache;

    bool ResolveTypeIndices(const std::vector<std::wstring>& typeNames,
        ULONGLONG deadline, size_t& queryCount, bool& budgetHit);
    void BuildHandleCache(const std::vector<std::wstring>& typeNames,
        ULONGLONG deadline, size_t& queryCount, bool& budgetHit);
};

extern SystemHandleTable g_HandleTable;
