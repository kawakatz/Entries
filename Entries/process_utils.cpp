#include "process_utils.h"
#include "diagnostics.h"
#include "security_utils.h"
#include <tlhelp32.h>
#include <cwctype>

ProcessPathCache g_ProcessCache;

static std::wstring ResolveSearchPathExecutable(const std::wstring& executablePath) {
    if (executablePath.empty()) return executablePath;
    if (executablePath.find_first_of(L"\\/") != std::wstring::npos) {
        return executablePath;
    }

    DWORD needed = SearchPathW(nullptr, executablePath.c_str(), nullptr,
        0, nullptr, nullptr);
    if (needed == 0) {
        return executablePath;
    }

    std::vector<WCHAR> buffer(needed + 1);
    if (SearchPathW(nullptr, executablePath.c_str(), nullptr,
        static_cast<DWORD>(buffer.size()), buffer.data(), nullptr) == 0) {
        return executablePath;
    }

    return buffer.data();
}

static std::wstring QueryProcessPath(HANDLE process) {
    std::vector<WCHAR> buffer(512);
    for (int attempt = 0; attempt < 7; attempt++) {
        DWORD size = static_cast<DWORD>(buffer.size());
        if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
            return std::wstring(buffer.data(), size);
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER
            || buffer.size() == 32768) break;
        buffer.resize((std::min)(buffer.size() * 2, size_t{ 32768 }));
    }
    return L"";
}

std::wstring TrimWhitespace(const std::wstring& value) {
    size_t first = value.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return L"";
    size_t last = value.find_last_not_of(L" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::wstring ExpandEnvironmentPath(const std::wstring& path) {
    DWORD needed = ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
    if (needed == 0) return path;

    std::vector<WCHAR> buffer(needed);
    if (ExpandEnvironmentStringsW(path.c_str(), buffer.data(), needed) == 0) {
        return path;
    }

    return buffer.data();
}

std::wstring ExtractExecutablePath(const std::wstring& commandLine) {
    std::wstring value = TrimWhitespace(commandLine);
    if (value.empty()) return value;

    value = ExpandEnvironmentPath(value);
    value = TrimWhitespace(value);

    if (StartsWithIcase(value, L"\\??\\")) {
        value = value.substr(4);
    }

    if (!value.empty() && value[0] == L'"') {
        size_t endQuote = value.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            return value.substr(1, endQuote - 1);
        }
    }

    std::wstring lower = ToLower(value);
    const wchar_t* exts[] = { L".exe", L".com", L".bat", L".cmd", L".scr", L".sys", L".dll" };
    size_t bestEnd = std::wstring::npos;

    for (auto ext : exts) {
        size_t pos = lower.find(ext);
        while (pos != std::wstring::npos) {
            size_t end = pos + wcslen(ext);
            wchar_t next = (end < lower.size()) ? lower[end] : L'\0';
            bool boundary = next == L'\0'
                || iswspace(next)
                || next == L'"'
                || next == L'\''
                || next == L',';
            if (boundary && (bestEnd == std::wstring::npos || end < bestEnd)) {
                bestEnd = end;
            }
            pos = lower.find(ext, pos + 1);
        }
    }

    if (bestEnd != std::wstring::npos) {
        return ResolveSearchPathExecutable(value.substr(0, bestEnd));
    }

    size_t space = value.find_first_of(L" \t");
    if (space != std::wstring::npos) {
        return ResolveSearchPathExecutable(value.substr(0, space));
    }

    return ResolveSearchPathExecutable(value);
}

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return result && (err == ERROR_SUCCESS);
}

std::wstring ProcessPathCache::GetIntegrityLevelString(HANDLE hToken) {
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &needed);
    if (needed == 0) return L"?";

    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), needed, &needed)) {
        return L"?";
    }

    auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    DWORD* subAuth = GetSidSubAuthority(til->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(til->Label.Sid) - 1));

    DWORD level = *subAuth;
    if (level >= SECURITY_MANDATORY_SYSTEM_RID)         return L"System";
    if (level >= SECURITY_MANDATORY_HIGH_RID)            return L"High";
    if (level >= SECURITY_MANDATORY_MEDIUM_PLUS_RID)     return L"Medium+";
    if (level >= SECURITY_MANDATORY_MEDIUM_RID)          return L"Medium";
    if (level >= SECURITY_MANDATORY_LOW_RID)             return L"Low";
    return L"Untrusted";
}

std::wstring ProcessPathCache::GetTokenUserString(HANDLE hToken) {
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0) return L"?";

    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed)) {
        return L"?";
    }

    auto* tokenUser = reinterpret_cast<TOKEN_USER*>(buf.data());

    return SidToAccountName(tokenUser->User.Sid);
}

ProcessPrivilege ProcessPathCache::QueryProcessPrivilege(HANDLE hProcess) {
    ProcessPrivilege priv;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return priv;
    }

    priv.userName = GetTokenUserString(hToken);

    priv.integrityLevel = GetIntegrityLevelString(hToken);

    TOKEN_ELEVATION elevation = {};
    DWORD needed = 0;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &needed)) {
        priv.isElevated = (elevation.TokenIsElevated != 0);
    }

    CloseHandle(hToken);
    return priv;
}

void ProcessPathCache::Refresh() {
    m_pathCache.clear();
    m_privCache.clear();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        ReportPartial(L"Process snapshot failed");
        return;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid == 0) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProc) {
                std::wstring path = QueryProcessPath(hProc);
                m_pathCache[pid] = path.empty() ? pe.szExeFile : std::move(path);
                m_privCache[pid] = QueryProcessPrivilege(hProc);
                CloseHandle(hProc);
            }
            else {
                m_pathCache[pid] = pe.szExeFile;
                m_privCache[pid] = {};
            }
        } while (Process32NextW(hSnap, &pe));

        if (GetLastError() != ERROR_NO_MORE_FILES) {
            ReportPartial(L"Process snapshot enumeration ended early");
        }
    }
    else {
        ReportPartial(L"Process snapshot enumeration failed");
    }

    CloseHandle(hSnap);
}

std::wstring ProcessPathCache::GetPath(DWORD pid) const {
    auto it = m_pathCache.find(pid);
    if (it != m_pathCache.end()) return it->second;
    return L"<unknown>";
}

std::wstring ProcessPathCache::GetPrivilege(DWORD pid) const {
    auto it = m_privCache.find(pid);
    if (it == m_privCache.end()) return L"?";

    const auto& p = it->second;
    if (p.userName == L"?" && p.integrityLevel == L"?") return L"?";
    std::wstring result = p.userName + L" [" + p.integrityLevel;
    if (p.isElevated) result += L",Elevated";
    result += L"]";
    return result;
}

bool MatchesPath(const std::wstring& processPath, const std::wregex& pathRegex) {
    try {
        if (std::regex_match(processPath, pathRegex)) return true;

        std::wstring executablePath = ExtractExecutablePath(processPath);
        return executablePath != processPath
            && std::regex_match(executablePath, pathRegex);
    }
    catch (...) {
        return false;
    }
}
