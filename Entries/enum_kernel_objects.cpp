#include "enum_kernel_objects.h"
#include "diagnostics.h"
#include "nt_api.h"
#include "security_utils.h"

#include <aclapi.h>
#include <set>
#include <unordered_set>

#pragma comment(lib, "advapi32.lib")

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

typedef NTSTATUS(NTAPI* PFN_NtOpenSymbolicLinkObject)(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* PFN_NtQuerySymbolicLinkObject)(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength
    );

static PFN_NtOpenSymbolicLinkObject pNtOpenSymbolicLinkObject = nullptr;
static PFN_NtQuerySymbolicLinkObject pNtQuerySymbolicLinkObject = nullptr;
static bool symlinkApiResolved = false;

static void EnsureSymlinkApiResolved() {
    if (symlinkApiResolved) return;
    symlinkApiResolved = true;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    pNtOpenSymbolicLinkObject = reinterpret_cast<PFN_NtOpenSymbolicLinkObject>(
        GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject"));
    pNtQuerySymbolicLinkObject = reinterpret_cast<PFN_NtQuerySymbolicLinkObject>(
        GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject"));
}

static std::wstring QuerySymlinkTarget(const std::wstring& path) {
    EnsureSymlinkApiResolved();
    if (!pNtOpenSymbolicLinkObject || !pNtQuerySymbolicLinkObject
        || !g_NtApi.RtlInitUnicodeString) {
        ReportPartial(L"Symbolic-link query APIs are unavailable");
        return L"";
    }

    UNICODE_STRING usName;
    g_NtApi.RtlInitUnicodeString(&usName, path.c_str());

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hLink = nullptr;
    NTSTATUS status = pNtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa);
    if (status != STATUS_SUCCESS || !hLink) return L"";

    std::vector<WCHAR> buffer(256);
    UNICODE_STRING usTarget = {};
    ULONG returnLength = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        usTarget.Buffer = buffer.data();
        usTarget.Length = 0;
        usTarget.MaximumLength = static_cast<USHORT>(buffer.size() * sizeof(WCHAR));
        status = pNtQuerySymbolicLinkObject(hLink, &usTarget, &returnLength);
        if (status == STATUS_SUCCESS) break;
        if (status != STATUS_BUFFER_TOO_SMALL
            && status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }

        size_t nextSize = buffer.size() * 2;
        size_t required = (returnLength + sizeof(WCHAR) - 1) / sizeof(WCHAR);
        if (required > nextSize) nextSize = required;
        if (nextSize <= buffer.size() || nextSize > 32767 || attempt == 3) break;
        buffer.resize(nextSize);
    }
    CloseHandle(hLink);

    if (status != STATUS_SUCCESS) {
        ReportPartial(L"Symbolic-link target query failed: "
            + HexCode(static_cast<unsigned long>(status)));
        return L"";
    }
    if (usTarget.Length == 0) return L"";
    return std::wstring(usTarget.Buffer, usTarget.Length / sizeof(WCHAR));
}

static std::wstring QueryObjectDirectoryDacl(const std::wstring& dirPath) {
    if (!g_NtApi.IsValid()) return L"";

    UNICODE_STRING usName;
    g_NtApi.RtlInitUnicodeString(&usName, dirPath.c_str());

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hDir = nullptr;
    NTSTATUS status = g_NtApi.NtOpenDirectoryObject(&hDir, READ_CONTROL, &oa);
    if (status != STATUS_SUCCESS || !hDir) return L"";

    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD err = GetSecurityInfo(hDir, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &sd);
    std::wstring summary;
    if (err == ERROR_SUCCESS && sd) {
        summary = SecurityDescriptorDaclSummary(sd, 6);
    }
    if (sd) LocalFree(sd);
    CloseHandle(hDir);
    return summary;
}

static void EnumerateDirectoryRecursive(EntryPointList& results,
    std::set<std::wstring>& seen,
    const std::wstring& dirPath,
    int depth,
    int maxDepth,
    const std::set<std::wstring>& wantedTypes,
    bool recordDirectory)
{
    if (depth > maxDepth) return;
    if (!g_NtApi.IsValid()) return;

    UNICODE_STRING usDirName;
    g_NtApi.RtlInitUnicodeString(&usDirName, dirPath.c_str());
    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &usDirName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hDir = nullptr;
    NTSTATUS status = g_NtApi.NtOpenDirectoryObject(&hDir,
        DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (status != STATUS_SUCCESS) return;

    if (recordDirectory && seen.insert(L"dir|" + dirPath).second) {
        EntryPoint entry;
        entry.type = EntryType::KernelObject;
        entry.name = dirPath;
        entry.details = L"Object directory";
        std::wstring dacl = QueryObjectDirectoryDacl(dirPath);
        if (!dacl.empty()) entry.details += L" | DACL: " + dacl;
        entry.ownerPath = L"<object-directory>";
        results.push_back(std::move(entry));
    }

    std::vector<BYTE> buffer(16 * 1024);
    ULONG context = 0;
    ULONG returnLength = 0;
    BOOLEAN restart = TRUE;
    std::vector<NtObjectDirectoryEntry> page;

    while (true) {
        if (!QueryObjectDirectoryPage(
            hDir, buffer, restart, context, returnLength, status)) {
            ReportPartial(L"Kernel-object directory response exceeded the buffer limit");
            break;
        }

        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES) {
            ReportPartial(L"Kernel-object directory enumeration failed: "
                + HexCode(static_cast<unsigned long>(status)));
            break;
        }

        if (!DecodeObjectDirectoryPage(buffer, returnLength, page)) {
            ReportPartial(L"Kernel-object directory returned invalid data");
            break;
        }
        for (const auto& object : page) {
            std::wstring fullPath = dirPath + L"\\" + object.name;

            if (object.typeName == L"Directory" && depth < maxDepth) {
                EnumerateDirectoryRecursive(results, seen,
                    fullPath, depth + 1, maxDepth, wantedTypes, recordDirectory);
            } else if (wantedTypes.count(object.typeName)) {
                std::wstring dedup = object.typeName + L"|" + fullPath;
                if (seen.insert(dedup).second) {
                    EntryPoint ep;
                    ep.type = EntryType::KernelObject;
                    ep.name = fullPath;
                    ep.details = object.typeName;

                    if (object.typeName == L"SymbolicLink") {
                        std::wstring target = QuerySymlinkTarget(fullPath);
                        if (!target.empty()) {
                            ep.details += L" | Target=" + target;
                        }
                    }

                    ep.ownerPath = std::wstring(L"<") + object.typeName + L">";
                    results.push_back(std::move(ep));
                }
            }
        }

        restart = FALSE;
        if (status != STATUS_MORE_ENTRIES) break;
    }

    CloseHandle(hDir);
}

EntryPointList EnumerateKernelObjects() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const std::set<std::wstring> primitiveTypes = {
        L"Mutant", L"Event", L"Semaphore", L"Timer", L"Job",
        L"IoCompletion", L"SymbolicLink", L"KeyedEvent",
    };
    const std::set<std::wstring> dllTypes = { L"Section", L"SymbolicLink" };
    const std::set<std::wstring> linkTypes = { L"SymbolicLink" };

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    std::vector<std::wstring> primaryDirs = {
        L"\\BaseNamedObjects",
        L"\\KernelObjects",
        L"\\Sessions\\0\\BaseNamedObjects",
    };
    if (sessionId != 0) {
        primaryDirs.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\BaseNamedObjects");
        primaryDirs.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\AppContainerNamedObjects");
    }

    for (const auto& dir : primaryDirs) {
        EnumerateDirectoryRecursive(results, seen, dir, 0, 2,
            primitiveTypes, true);
    }

    const std::wstring knownDllsDirs[] = { L"\\KnownDlls", L"\\KnownDlls32" };
    for (const auto& dir : knownDllsDirs) {
        EnumerateDirectoryRecursive(results, seen, dir, 0, 0,
            dllTypes, true);
    }

    const std::wstring linkDirs[] = { L"\\??", L"\\GLOBAL??" };
    for (const auto& dir : linkDirs) {
        EnumerateDirectoryRecursive(results, seen, dir, 0, 0,
            linkTypes, true);
    }

    return results;
}
