#include "nt_objects.h"
#include "diagnostics.h"
#include "security_utils.h"
#include <aclapi.h>
#include <cstdint>
#include <unordered_set>

#pragma comment(lib, "advapi32.lib")

SystemHandleTable g_HandleTable;

namespace {

constexpr size_t kMaxNativeQueries = 65536;
constexpr ULONGLONG kNativeQueryBudgetMs = 30000;
constexpr DWORD kQueryTimeoutMs = 100;
constexpr DWORD kMaxWorkerChars = 32767;
constexpr size_t kMaxObjectChars = 1023;

enum class NativeOperation : DWORD {
    ObjectName = 1,
    ObjectType = 2,
    DeviceDacl = 3
};

struct NativeRequest {
    NativeOperation operation;
    DWORD charCount;
    ULONG_PTR handle;
};

enum class ReadResult {
    Success,
    Timeout,
    Failure
};

bool ReadExact(HANDLE pipe, void* data, DWORD size) {
    auto* bytes = static_cast<BYTE*>(data);
    for (DWORD total = 0; total < size;) {
        DWORD read = 0;
        if (!ReadFile(pipe, bytes + total, size - total, &read, nullptr)
            || read == 0) {
            return false;
        }
        total += read;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* data, DWORD size) {
    const auto* bytes = static_cast<const BYTE*>(data);
    for (DWORD total = 0; total < size;) {
        DWORD written = 0;
        if (!WriteFile(pipe, bytes + total, size - total, &written, nullptr)
            || written == 0) {
            return false;
        }
        total += written;
    }
    return true;
}

ReadResult ReadBefore(HANDLE pipe, void* data, DWORD size, ULONGLONG deadline) {
    auto* bytes = static_cast<BYTE*>(data);
    for (DWORD total = 0; total < size;) {
        if (GetTickCount64() >= deadline) return ReadResult::Timeout;
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            return ReadResult::Failure;
        }
        if (available == 0) {
            Sleep(1);
            continue;
        }

        DWORD read = 0;
        DWORD chunk = (std::min)(available, size - total);
        if (!ReadFile(pipe, bytes + total, chunk, &read, nullptr) || read == 0) {
            return ReadResult::Failure;
        }
        total += read;
    }
    return ReadResult::Success;
}

std::wstring ReadUnicodeString(const UNICODE_STRING& value,
    const std::vector<BYTE>& buffer)
{
    if (!value.Buffer || value.Length == 0 || value.Length % sizeof(WCHAR) != 0) {
        return L"";
    }

    std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(buffer.data());
    std::uintptr_t end = begin + buffer.size();
    std::uintptr_t text = reinterpret_cast<std::uintptr_t>(value.Buffer);
    if (text < begin || text > end || value.Length > end - text) return L"";

    size_t length = (std::min)(
        static_cast<size_t>(value.Length / sizeof(WCHAR)),
        kMaxObjectChars);
    return std::wstring(value.Buffer, length);
}

std::wstring QueryObjectString(HANDLE handle, ULONG informationClass) {
    std::vector<BYTE> buffer(2048);
    ULONG returnLength = 0;
    NTSTATUS status = STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 3; attempt++) {
        status = g_NtApi.NtQueryObject(handle, informationClass, buffer.data(),
            static_cast<ULONG>(buffer.size()), &returnLength);
        if (status == STATUS_SUCCESS) break;
        if (status != STATUS_INFO_LENGTH_MISMATCH
            && status != STATUS_BUFFER_TOO_SMALL) {
            break;
        }

        size_t nextSize = returnLength > buffer.size()
            ? returnLength
            : buffer.size() * 2;
        if (nextSize > 64 * 1024 || attempt == 2) break;
        buffer.resize(nextSize);
    }
    if (status != STATUS_SUCCESS) return L"";

    if (informationClass == ObjectNameInformation) {
        return ReadUnicodeString(
            *reinterpret_cast<const UNICODE_STRING*>(buffer.data()), buffer);
    }
    auto* info = reinterpret_cast<const OBJECT_TYPE_INFORMATION_PREFIX*>(
        buffer.data());
    return ReadUnicodeString(info->TypeName, buffer);
}

using PFN_NtOpenFile = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

std::wstring QueryDeviceDacl(const std::wstring& devicePath) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntOpenFile = ntdll
        ? reinterpret_cast<PFN_NtOpenFile>(GetProcAddress(ntdll, "NtOpenFile"))
        : nullptr;
    if (!ntOpenFile || !g_NtApi.RtlInitUnicodeString) return L"";

    UNICODE_STRING name;
    g_NtApi.RtlInitUnicodeString(&name, devicePath.c_str());
    OBJECT_ATTRIBUTES attributes = {};
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE,
        nullptr, nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    HANDLE device = nullptr;
    NTSTATUS status = ntOpenFile(&device, READ_CONTROL, &attributes, &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (status != STATUS_SUCCESS || !device) return L"";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD error = GetSecurityInfo(device, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr,
        &descriptor);
    std::wstring result;
    if (error == ERROR_SUCCESS && descriptor) {
        result = SecurityDescriptorDaclSummary(descriptor, 8);
    }
    if (descriptor) LocalFree(descriptor);
    CloseHandle(device);
    return result;
}

class NativeWorker {
public:
    ~NativeWorker() { Reset(false); }

    std::wstring QueryHandle(NativeOperation operation, HANDLE sourceProcess,
        ULONG_PTR sourceHandle, DWORD timeoutMs)
    {
        if (!Start()) {
            ReportFailure(L"Could not start native query worker");
            return L"";
        }

        HANDLE remoteHandle = nullptr;
        if (!DuplicateHandle(sourceProcess, reinterpret_cast<HANDLE>(sourceHandle),
            process_, &remoteHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            return L"";
        }

        NativeRequest request = {};
        request.operation = operation;
        request.handle = reinterpret_cast<ULONG_PTR>(remoteHandle);
        return Transact(request, nullptr, timeoutMs);
    }

    std::wstring QueryDeviceDacl(const std::wstring& devicePath,
        DWORD timeoutMs)
    {
        if (devicePath.size() > kMaxWorkerChars) return L"";
        if (!Start()) {
            ReportFailure(L"Could not start native query worker");
            return L"";
        }

        NativeRequest request = {};
        request.operation = NativeOperation::DeviceDacl;
        request.charCount = static_cast<DWORD>(devicePath.size());
        return Transact(request, devicePath.data(), timeoutMs);
    }

private:
    HANDLE process_ = nullptr;
    HANDLE request_ = nullptr;
    HANDLE response_ = nullptr;
    bool reportedFailure_ = false;

    std::wstring Transact(const NativeRequest& request, const WCHAR* text,
        DWORD timeoutMs)
    {
        DWORD textBytes = request.charCount * static_cast<DWORD>(sizeof(WCHAR));
        if (!WriteExact(request_, &request, static_cast<DWORD>(sizeof(request)))
            || (textBytes != 0 && !WriteExact(request_, text, textBytes))) {
            Reset(false);
            ReportFailure(L"Native query worker request failed");
            return L"";
        }

        ULONGLONG deadline = GetTickCount64() + timeoutMs;
        DWORD length = 0;
        ReadResult read = ReadBefore(response_, &length,
            static_cast<DWORD>(sizeof(length)), deadline);
        if (read != ReadResult::Success) {
            HandleReadFailure(read);
            return L"";
        }
        if (length > kMaxWorkerChars) {
            Reset(false);
            ReportFailure(L"Native query worker returned an invalid response");
            return L"";
        }

        std::wstring result(length, L'\0');
        if (length != 0) {
            read = ReadBefore(response_, result.data(),
                length * static_cast<DWORD>(sizeof(WCHAR)), deadline);
            if (read != ReadResult::Success) {
                HandleReadFailure(read);
                return L"";
            }
        }
        return result;
    }

    void HandleReadFailure(ReadResult result) {
        if (result == ReadResult::Timeout) {
            Reset(true);
            ReportFailure(L"Native query timed out; results may be incomplete");
        }
        else {
            Reset(false);
            ReportFailure(L"Native query worker response failed");
        }
    }

    bool Start() {
        if (process_ && WaitForSingleObject(process_, 0) == WAIT_TIMEOUT) {
            return true;
        }
        Reset(false);

        SECURITY_ATTRIBUTES security = { sizeof(security), nullptr, TRUE };
        HANDLE requestRead = nullptr;
        HANDLE responseWrite = nullptr;
        HANDLE nullOutput = nullptr;
        if (!CreatePipe(&requestRead, &request_, &security, 0)
            || !SetHandleInformation(request_, HANDLE_FLAG_INHERIT, 0)
            || !CreatePipe(&response_, &responseWrite, &security, 0)
            || !SetHandleInformation(response_, HANDLE_FLAG_INHERIT, 0)) {
            Close(requestRead);
            Close(responseWrite);
            Reset(false);
            return false;
        }

        nullOutput = CreateFileW(L"NUL", GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0,
            nullptr);
        if (nullOutput == INVALID_HANDLE_VALUE) {
            nullOutput = nullptr;
            Close(requestRead);
            Close(responseWrite);
            Reset(false);
            return false;
        }

        std::vector<WCHAR> executable(32768);
        DWORD pathLength = GetModuleFileNameW(nullptr, executable.data(),
            static_cast<DWORD>(executable.size()));
        if (pathLength == 0 || pathLength == executable.size()) {
            Close(requestRead);
            Close(responseWrite);
            Close(nullOutput);
            Reset(false);
            return false;
        }

        std::wstring commandLine = L"\"" + std::wstring(executable.data(), pathLength)
            + L"\" --native-query-worker";
        std::vector<WCHAR> command(commandLine.begin(), commandLine.end());
        command.push_back(L'\0');

        SIZE_T attributeSize = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
        std::vector<BYTE> attributeBuffer(attributeSize);
        auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            attributeBuffer.data());
        HANDLE inheritedHandles[] = { requestRead, responseWrite, nullOutput };
        bool initialized = attributeSize != 0
            && InitializeProcThreadAttributeList(attributes, 1, 0,
                &attributeSize);
        if (!initialized || !UpdateProcThreadAttribute(attributes, 0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritedHandles,
                sizeof(inheritedHandles), nullptr, nullptr)) {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            Close(requestRead);
            Close(responseWrite);
            Close(nullOutput);
            Reset(false);
            return false;
        }

        STARTUPINFOEXW startup = {};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = requestRead;
        startup.StartupInfo.hStdOutput = responseWrite;
        startup.StartupInfo.hStdError = nullOutput;
        startup.lpAttributeList = attributes;
        PROCESS_INFORMATION process = {};
        BOOL started = CreateProcessW(nullptr, command.data(), nullptr, nullptr,
            TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr,
            nullptr, &startup.StartupInfo, &process);

        DeleteProcThreadAttributeList(attributes);
        Close(requestRead);
        Close(responseWrite);
        Close(nullOutput);
        if (!started) {
            Reset(false);
            return false;
        }

        process_ = process.hProcess;
        CloseHandle(process.hThread);
        return true;
    }

    static void Close(HANDLE& handle) {
        if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        handle = nullptr;
    }

    void Reset(bool terminate) {
        Close(request_);
        Close(response_);
        if (!process_) return;

        if (terminate && WaitForSingleObject(process_, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process_, 1);
        }
        WaitForSingleObject(process_, terminate ? 1000 : 100);
        Close(process_);
    }

    void ReportFailure(const std::wstring& message) {
        if (reportedFailure_) return;
        reportedFailure_ = true;
        ReportPartial(message);
    }
};

NativeWorker& GetNativeWorker() {
    static NativeWorker worker;
    return worker;
}

DWORD RemainingTimeout(ULONGLONG deadline) {
    ULONGLONG now = GetTickCount64();
    if (now >= deadline) return 0;
    return static_cast<DWORD>((std::min)(
        deadline - now, static_cast<ULONGLONG>(kQueryTimeoutMs)));
}

bool OpenHandleSource(DWORD pid, HANDLE& source, bool& closeSource) {
    closeSource = false;
    if (pid == GetCurrentProcessId()) {
        source = GetCurrentProcess();
        return true;
    }
    source = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    closeSource = source != nullptr;
    return source != nullptr;
}

HANDLE DuplicateForCurrentProcess(const HandleInfo& handle) {
    if (handle.pid == 0 || handle.pid > MAXDWORD) {
        return nullptr;
    }

    HANDLE source = nullptr;
    bool closeSource = false;
    if (!OpenHandleSource(static_cast<DWORD>(handle.pid), source, closeSource)) {
        return nullptr;
    }

    HANDLE duplicated = nullptr;
    BOOL ok = DuplicateHandle(source,
        reinterpret_cast<HANDLE>(handle.handleValue), GetCurrentProcess(),
        &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (closeSource) CloseHandle(source);
    return ok ? duplicated : nullptr;
}

std::wstring QueryKernelObjectDacl(HANDLE handle, size_t maxAces) {
    DWORD needed = 0;
    if (GetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION,
        nullptr, 0, &needed)
        || GetLastError() != ERROR_INSUFFICIENT_BUFFER
        || needed < SECURITY_DESCRIPTOR_MIN_LENGTH
        || needed > 1024 * 1024) {
        return L"";
    }

    std::vector<BYTE> descriptor(needed);
    if (!GetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(descriptor.data()), needed,
        &needed)) {
        return L"";
    }
    return SecurityDescriptorDaclSummary(
        reinterpret_cast<PSECURITY_DESCRIPTOR>(descriptor.data()), maxAces);
}

}

bool SystemHandleTable::Build(const std::vector<std::wstring>& typeNames) {
    if (!g_NtApi.IsValid()) return false;

    m_handles.clear();
    m_typeNameToIndex.clear();
    m_handleCache.clear();
    m_nameToPidCache.clear();

    ULONG bufferSize = 2 * 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    while (status == STATUS_INFO_LENGTH_MISMATCH
        && bufferSize <= 512 * 1024 * 1024) {
        buffer.resize(bufferSize);
        status = g_NtApi.NtQuerySystemInformation(
            SystemExtendedHandleInformation, buffer.data(), bufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            if (bufferSize == 512 * 1024 * 1024) break;
            bufferSize *= 2;
        }
    }

    if (status != STATUS_SUCCESS) {
        ReportPartial(L"System handle snapshot failed: "
            + HexCode(static_cast<unsigned long>(status)));
        return false;
    }

    auto* info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
    size_t headerSize = offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles);
    if (buffer.size() < headerSize || info->NumberOfHandles
        > (buffer.size() - headerSize) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)) {
        ReportPartial(L"System handle snapshot was truncated");
        return false;
    }

    m_handles.reserve(static_cast<size_t>(info->NumberOfHandles));
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        const auto& entry = info->Handles[i];
        m_handles.push_back({ entry.UniqueProcessId, entry.HandleValue,
            entry.ObjectTypeIndex, entry.GrantedAccess, entry.Object });
    }

    ULONGLONG deadline = GetTickCount64() + kNativeQueryBudgetMs;
    size_t queryCount = 0;
    bool budgetHit = false;
    bool resolved = ResolveTypeIndices(typeNames, deadline, queryCount, budgetHit);
    BuildHandleCache(typeNames, deadline, queryCount, budgetHit);
    if (budgetHit) {
        ReportPartial(L"Native handle query budget reached; results are incomplete");
    }
    return resolved;
}

bool SystemHandleTable::ResolveTypeIndices(
    const std::vector<std::wstring>& typeNames, ULONGLONG deadline,
    size_t& queryCount, bool& budgetHit)
{
    std::unordered_set<USHORT> resolvedTypes;
    std::unordered_map<USHORT, unsigned> attempts;
    std::unordered_set<ULONG_PTR> unavailablePids;
    std::unordered_set<std::wstring> remaining(typeNames.begin(), typeNames.end());

    for (const auto& handle : m_handles) {
        if (remaining.empty()) break;
        if (GetTickCount64() >= deadline || queryCount >= kMaxNativeQueries) {
            budgetHit = true;
            break;
        }
        if (resolvedTypes.count(handle.objectTypeIndex)
            || attempts[handle.objectTypeIndex] >= 4) {
            continue;
        }

        if (handle.pid > MAXDWORD
            || unavailablePids.count(handle.pid)) {
            continue;
        }

        HANDLE source = nullptr;
        bool closeSource = false;
        DWORD pid = static_cast<DWORD>(handle.pid);
        if (!OpenHandleSource(pid, source, closeSource)) {
            unavailablePids.insert(handle.pid);
            continue;
        }

        attempts[handle.objectTypeIndex]++;
        queryCount++;
        DWORD timeout = RemainingTimeout(deadline);
        std::wstring typeName;
        if (timeout != 0) {
            typeName = GetNativeWorker().QueryHandle(NativeOperation::ObjectType,
                source, handle.handleValue, timeout);
        }
        else {
            budgetHit = true;
        }
        if (closeSource) CloseHandle(source);

        if (!typeName.empty()) {
            m_typeNameToIndex[typeName] = handle.objectTypeIndex;
            resolvedTypes.insert(handle.objectTypeIndex);
            remaining.erase(typeName);
        }
    }

    return remaining.empty();
}

void SystemHandleTable::BuildHandleCache(
    const std::vector<std::wstring>& typeNames, ULONGLONG deadline,
    size_t& queryCount, bool& budgetHit)
{
    struct Cursor {
        std::wstring typeName;
        USHORT typeIndex = 0;
        size_t next = 0;
        DWORD activePid = 0;
        HANDLE source = nullptr;
        bool closeSource = false;
        bool haveActivePid = false;
        bool done = false;
    };

    std::vector<Cursor> cursors;
    cursors.reserve(typeNames.size());
    for (const auto& typeName : typeNames) {
        m_handleCache[typeName] = {};
        m_nameToPidCache[typeName] = {};
        USHORT index = GetTypeIndex(typeName);
        if (index != 0) cursors.push_back({ typeName, index });
    }

    bool stop = false;
    while (!stop) {
        bool progressed = false;
        for (auto& cursor : cursors) {
            if (cursor.done) continue;
            while (cursor.next < m_handles.size()
                && m_handles[cursor.next].objectTypeIndex != cursor.typeIndex) {
                cursor.next++;
            }
            if (cursor.next == m_handles.size()) {
                cursor.done = true;
                continue;
            }
            if (GetTickCount64() >= deadline
                || queryCount >= kMaxNativeQueries) {
                budgetHit = true;
                stop = true;
                break;
            }

            const auto& handle = m_handles[cursor.next++];
            queryCount++;
            progressed = true;
            auto& cached = m_handleCache[cursor.typeName];
            cached.push_back({ handle, L"" });

            if (handle.pid > MAXDWORD) continue;
            DWORD pid = static_cast<DWORD>(handle.pid);
            if (!cursor.haveActivePid || pid != cursor.activePid) {
                if (cursor.closeSource) CloseHandle(cursor.source);
                cursor.source = nullptr;
                cursor.closeSource = false;
                cursor.activePid = pid;
                cursor.haveActivePid = true;
                OpenHandleSource(pid, cursor.source, cursor.closeSource);
            }
            if (!cursor.source) continue;

            DWORD timeout = RemainingTimeout(deadline);
            if (timeout == 0) {
                budgetHit = true;
                stop = true;
                break;
            }
            cached.back().name = GetNativeWorker().QueryHandle(
                NativeOperation::ObjectName, cursor.source,
                handle.handleValue, timeout);
            if (!cached.back().name.empty()) {
                m_nameToPidCache[cursor.typeName][ToLower(cached.back().name)]
                    .insert(pid);
            }
        }
        if (!progressed) break;
    }

    for (auto& cursor : cursors) {
        if (cursor.closeSource) CloseHandle(cursor.source);
    }
}

USHORT SystemHandleTable::GetTypeIndex(const std::wstring& typeName) const {
    auto found = m_typeNameToIndex.find(typeName);
    return found == m_typeNameToIndex.end() ? 0 : found->second;
}

const std::vector<CachedHandleInfo>& SystemHandleTable::GetCachedHandles(
    const std::wstring& typeName) const
{
    static const std::vector<CachedHandleInfo> empty;
    if (GetTypeIndex(typeName) == 0) {
        ReportPartial(L"Unknown object type: " + typeName);
        return empty;
    }
    auto found = m_handleCache.find(typeName);
    return found == m_handleCache.end() ? empty : found->second;
}

const std::unordered_map<std::wstring, std::set<DWORD>>&
SystemHandleTable::GetNameToPidMap(const std::wstring& typeName) const {
    static const std::unordered_map<std::wstring, std::set<DWORD>> empty;
    if (GetTypeIndex(typeName) == 0) {
        ReportPartial(L"Unknown object type: " + typeName);
        return empty;
    }
    auto found = m_nameToPidCache.find(typeName);
    return found == m_nameToPidCache.end() ? empty : found->second;
}

bool SystemHandleTable::QueryPipeServer(const HandleInfo& handle,
    PipeServerInfo& info) const
{
    info = {};
    if (handle.pid == 0 || handle.pid > MAXDWORD) {
        return false;
    }

    DWORD ownerPid = static_cast<DWORD>(handle.pid);
    HANDLE pipe = DuplicateForCurrentProcess(handle);
    if (!pipe) return false;

    DWORD flags = 0;
    if (!GetNamedPipeInfo(pipe, &flags, nullptr, nullptr, nullptr)
        || (flags & PIPE_SERVER_END) == 0) {
        CloseHandle(pipe);
        return false;
    }

    info.pid = ownerPid;
    DWORD queriedPid = 0;
    if (GetNamedPipeServerProcessId(pipe, &queriedPid) && queriedPid != 0) {
        info.pid = queriedPid;
        info.queriedPid = true;
    }

    info.dacl = QueryKernelObjectDacl(pipe, 6);

    CloseHandle(pipe);
    return true;
}

bool SystemHandleTable::QueryHandleDacl(const HandleInfo& handle,
    size_t maxAces, std::wstring& dacl) const
{
    dacl.clear();
    HANDLE duplicated = DuplicateForCurrentProcess(handle);
    if (!duplicated) return false;
    dacl = QueryKernelObjectDacl(duplicated, maxAces);
    CloseHandle(duplicated);
    return true;
}

std::wstring QueryNativeDeviceDacl(const std::wstring& devicePath) {
    return GetNativeWorker().QueryDeviceDacl(devicePath, kQueryTimeoutMs);
}

int RunNativeQueryWorker() {
    if (!g_NtApi.Initialize()) return 1;

    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    NativeRequest request = {};
    while (ReadExact(input, &request, static_cast<DWORD>(sizeof(request)))) {
        if (request.charCount > kMaxWorkerChars) return 1;

        std::wstring text(request.charCount, L'\0');
        DWORD textBytes = request.charCount * static_cast<DWORD>(sizeof(WCHAR));
        if (textBytes != 0 && !ReadExact(input, text.data(), textBytes)) return 1;

        std::wstring result;
        HANDLE handle = reinterpret_cast<HANDLE>(request.handle);
        switch (request.operation) {
        case NativeOperation::ObjectName:
            if (request.charCount != 0 || !handle) return 1;
            result = QueryObjectString(handle, ObjectNameInformation);
            CloseHandle(handle);
            break;
        case NativeOperation::ObjectType:
            if (request.charCount != 0 || !handle) return 1;
            result = QueryObjectString(handle, ObjectTypeInformation);
            CloseHandle(handle);
            break;
        case NativeOperation::DeviceDacl:
            if (handle) return 1;
            result = QueryDeviceDacl(text);
            break;
        default:
            if (handle) CloseHandle(handle);
            return 1;
        }

        DWORD length = static_cast<DWORD>((std::min)(
            result.size(), static_cast<size_t>(kMaxWorkerChars)));
        if (!WriteExact(output, &length, static_cast<DWORD>(sizeof(length)))
            || (length != 0 && !WriteExact(output, result.data(),
                length * static_cast<DWORD>(sizeof(WCHAR))))) {
            return 1;
        }
    }
    return 0;
}
