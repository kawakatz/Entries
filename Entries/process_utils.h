#pragma once

#include "common.h"
#include <regex>
#include <unordered_map>

bool EnableDebugPrivilege();

struct ProcessPrivilege {
    std::wstring userName = L"?";
    std::wstring integrityLevel = L"?";
    bool isElevated = false;
};

class ProcessPathCache {
public:
    void Refresh();
    std::wstring GetPath(DWORD pid) const;
    std::wstring GetPrivilege(DWORD pid) const;

private:
    std::unordered_map<DWORD, std::wstring> m_pathCache;
    std::unordered_map<DWORD, ProcessPrivilege> m_privCache;

    static ProcessPrivilege QueryProcessPrivilege(HANDLE hProcess);
    static std::wstring GetIntegrityLevelString(HANDLE hToken);
    static std::wstring GetTokenUserString(HANDLE hToken);
};

bool MatchesPath(const std::wstring& processPath, const std::wregex& pathRegex);

std::wstring TrimWhitespace(const std::wstring& value);
std::wstring ExpandEnvironmentPath(const std::wstring& path);
std::wstring ExtractExecutablePath(const std::wstring& commandLine);

extern ProcessPathCache g_ProcessCache;
