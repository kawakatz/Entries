#include "enum_rpc.h"
#include "diagnostics.h"
#include "nt_objects.h"
#include "process_utils.h"
#include <iphlpapi.h>
#include <rpc.h>
#include <rpcnsi.h>
#include <unordered_map>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "rpcrt4.lib")

template <typename Query>
static std::vector<BYTE> QueryIpTable(const wchar_t* name, Query query) {
    std::vector<BYTE> buffer;
    DWORD size = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        DWORD status = query(buffer.empty() ? nullptr : buffer.data(), &size);
        if (status == NO_ERROR) return buffer;
        if (status != ERROR_INSUFFICIENT_BUFFER
            || size <= buffer.size() || attempt == 3) {
            ReportPartial(std::wstring(name) + L" failed: "
                + std::to_wstring(status));
            return {};
        }
        buffer.resize(size);
    }
    return {};
}

static std::wstring UuidToWString(const UUID& uuid) {
    RPC_WSTR str = nullptr;
    if (UuidToStringW(&uuid, &str) == RPC_S_OK && str) {
        std::wstring result((const wchar_t*)str);
        RpcStringFreeW(&str);
        return result;
    }
    ReportPartial(L"RPC UUID formatting failed");
    return L"<unknown-uuid>";
}

static std::wstring ProtseqToName(const std::wstring& protseq) {
    if (protseq == L"ncalrpc") return L"LRPC (local)";
    if (protseq == L"ncacn_np") return L"Named Pipe";
    if (protseq == L"ncacn_ip_tcp") return L"TCP/IP";
    if (protseq == L"ncacn_http") return L"HTTP";
    if (protseq == L"ncadg_ip_udp") return L"UDP/IP";
    return protseq;
}

static void AddTcpPortOwners(std::unordered_map<DWORD, DWORD>& owners, ULONG family) {
    auto buffer = QueryIpTable(L"RPC TCP owner table query",
        [&](void* data, DWORD* size) {
            return GetExtendedTcpTable(data, size, FALSE, family,
                TCP_TABLE_OWNER_PID_LISTENER, 0);
        });
    if (buffer.empty()) return;

    if (family == AF_INET) {
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            DWORD port = ntohs((u_short)table->table[i].dwLocalPort);
            if (port != 0 && !owners.count(port)) {
                owners[port] = table->table[i].dwOwningPid;
            }
        }
    }
    else if (family == AF_INET6) {
        auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            DWORD port = ntohs((u_short)table->table[i].dwLocalPort);
            if (port != 0 && !owners.count(port)) {
                owners[port] = table->table[i].dwOwningPid;
            }
        }
    }
}

static void AddUdpPortOwners(std::unordered_map<DWORD, DWORD>& owners, ULONG family) {
    auto buffer = QueryIpTable(L"RPC UDP owner table query",
        [&](void* data, DWORD* size) {
            return GetExtendedUdpTable(data, size, FALSE, family,
                UDP_TABLE_OWNER_PID, 0);
        });
    if (buffer.empty()) return;

    if (family == AF_INET) {
        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            DWORD port = ntohs((u_short)table->table[i].dwLocalPort);
            if (port != 0 && !owners.count(port)) {
                owners[port] = table->table[i].dwOwningPid;
            }
        }
    }
    else if (family == AF_INET6) {
        auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            DWORD port = ntohs((u_short)table->table[i].dwLocalPort);
            if (port != 0 && !owners.count(port)) {
                owners[port] = table->table[i].dwOwningPid;
            }
        }
    }
}

static std::unordered_map<DWORD, DWORD> BuildTcpPortOwnerMap() {
    std::unordered_map<DWORD, DWORD> owners;
    AddTcpPortOwners(owners, AF_INET);
    AddTcpPortOwners(owners, AF_INET6);
    return owners;
}

static std::unordered_map<DWORD, DWORD> BuildUdpPortOwnerMap() {
    std::unordered_map<DWORD, DWORD> owners;
    AddUdpPortOwners(owners, AF_INET);
    AddUdpPortOwners(owners, AF_INET6);
    return owners;
}

static std::unordered_map<std::wstring, DWORD> BuildAlpcOwnerMap() {
    std::unordered_map<std::wstring, DWORD> owners;

    if (g_HandleTable.GetTypeIndex(L"ALPC Port") == 0) {
        return owners;
    }

    const auto& namedOwners = g_HandleTable.GetNameToPidMap(L"ALPC Port");
    for (const auto& item : namedOwners) {
        if (!item.second.empty()) {
            owners[item.first] = *item.second.begin();
        }
    }

    return owners;
}

static bool SetOwnerFromPid(EntryPoint& ep, DWORD pid, const std::wstring& source) {
    if (pid == 0) return false;

    ep.ownerPid = pid;
    ep.ownerPath = g_ProcessCache.GetPath(pid);
    if (!source.empty()) {
        ep.details += L" | Owner=" + source;
    }
    return true;
}

static bool TryResolvePortOwner(EntryPoint& ep,
    const std::unordered_map<DWORD, DWORD>& owners,
    const std::wstring& endpoint,
    const std::wstring& source)
{
    try {
        DWORD port = std::stoul(endpoint);
        ep.details += L" port=" + std::to_wstring(port);

        auto it = owners.find(port);
        if (it != owners.end()) {
            return SetOwnerFromPid(ep, it->second, source);
        }
    }
    catch (...) {
    }
    return false;
}

static bool TryResolveAlpcOwner(EntryPoint& ep,
    const std::unordered_map<std::wstring, DWORD>& owners,
    const std::wstring& endpoint)
{
    if (endpoint.empty() || owners.empty()) return false;

    std::vector<std::wstring> candidates = {
        L"\\RPC Control\\" + endpoint,
        L"\\BaseNamedObjects\\" + endpoint,
        L"\\Windows\\ApiPort\\" + endpoint,
    };

    DWORD sessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        candidates.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\BaseNamedObjects\\" + endpoint);
        candidates.push_back(L"\\Sessions\\" + std::to_wstring(sessionId)
            + L"\\Windows\\ApiPort\\" + endpoint);
    }

    for (const auto& candidate : candidates) {
        auto it = owners.find(ToLower(candidate));
        if (it != owners.end()) {
            return SetOwnerFromPid(ep, it->second, L"alpc");
        }
    }

    return false;
}

EntryPointList EnumerateRpcEndpoints() {
    EntryPointList results;
    auto tcpPortOwners = BuildTcpPortOwnerMap();
    auto udpPortOwners = BuildUdpPortOwnerMap();
    auto alpcOwners = BuildAlpcOwnerMap();

    RPC_EP_INQ_HANDLE hInq = nullptr;
    RPC_STATUS status;

    status = RpcMgmtEpEltInqBegin(
        nullptr,
        RPC_C_EP_ALL_ELTS,
        nullptr,
        RPC_C_VERS_ALL,
        nullptr,
        &hInq
    );

    if (status != RPC_S_OK) {
        ReportPartial(L"RPC endpoint inquiry failed: " + std::to_wstring(status));
        return results;
    }

    while (true) {
        RPC_IF_ID ifId = {};
        UUID objUuid = {};
        RPC_BINDING_HANDLE hBinding = nullptr;
        RPC_WSTR annotation = nullptr;

        status = RpcMgmtEpEltInqNextW(
            hInq,
            &ifId,
            &hBinding,
            &objUuid,
            &annotation
        );

        if (status != RPC_S_OK) {
            if (status != RPC_X_NO_MORE_ENTRIES) {
                ReportPartial(L"RPC endpoint enumeration failed: "
                    + std::to_wstring(status));
            }
            if (annotation) RpcStringFreeW(&annotation);
            if (hBinding) RpcBindingFree(&hBinding);
            break;
        }

        RPC_WSTR bindingStr = nullptr;
        RPC_STATUS bindingStatus = RpcBindingToStringBindingW(hBinding, &bindingStr);
        if (bindingStatus == RPC_S_OK && bindingStr) {
            std::wstring binding((const wchar_t*)bindingStr);
            RpcStringFreeW(&bindingStr);

            RPC_WSTR protseq = nullptr;
            RPC_WSTR endpoint = nullptr;
            RPC_WSTR networkAddr = nullptr;

            RPC_STATUS parseStatus = RpcStringBindingParseW(
                (RPC_WSTR)binding.c_str(),
                nullptr,
                &protseq,
                &networkAddr,
                &endpoint,
                nullptr
            );
            if (parseStatus != RPC_S_OK) {
                ReportPartial(L"RPC binding parse failed: "
                    + std::to_wstring(parseStatus));
            }

            EntryPoint ep;
            ep.type = EntryType::RPC;

            std::wstring protseqStr = protseq ? (const wchar_t*)protseq : L"";
            std::wstring endpointStr = endpoint ? (const wchar_t*)endpoint : L"";
            std::wstring addrStr = networkAddr ? (const wchar_t*)networkAddr : L"";

            ep.name = protseqStr + L":" + endpointStr;
            if (!addrStr.empty()) {
                ep.name += L"@" + addrStr;
            }

            std::wstring ifUuid = UuidToWString(ifId.Uuid);
            ep.details = L"IF=" + ifUuid
                + L" v" + std::to_wstring(ifId.VersMajor) + L"." + std::to_wstring(ifId.VersMinor)
                + L" [" + ProtseqToName(protseqStr) + L"]";

            if (annotation && wcslen((const wchar_t*)annotation) > 0) {
                ep.details += L" \"" + std::wstring((const wchar_t*)annotation) + L"\"";
            }

            ep.ownerPath = L"<unresolved>";

            if (protseqStr == L"ncacn_ip_tcp" && !endpointStr.empty()) {
                TryResolvePortOwner(ep, tcpPortOwners, endpointStr, L"tcp-port");
            }
            else if (protseqStr == L"ncadg_ip_udp" && !endpointStr.empty()) {
                TryResolvePortOwner(ep, udpPortOwners, endpointStr, L"udp-port");
            }
            else if (protseqStr == L"ncalrpc" && !endpointStr.empty()) {
                TryResolveAlpcOwner(ep, alpcOwners, endpointStr);
            }

            results.push_back(std::move(ep));

            if (protseq) RpcStringFreeW(&protseq);
            if (endpoint) RpcStringFreeW(&endpoint);
            if (networkAddr) RpcStringFreeW(&networkAddr);
        }
        else {
            ReportPartial(L"RPC binding formatting failed: "
                + std::to_wstring(bindingStatus));
            if (bindingStr) RpcStringFreeW(&bindingStr);
        }

        if (annotation) RpcStringFreeW(&annotation);
        if (hBinding) RpcBindingFree(&hBinding);
    }

    status = RpcMgmtEpEltInqDone(&hInq);
    if (status != RPC_S_OK) {
        ReportPartial(L"RPC endpoint inquiry cleanup failed: "
            + std::to_wstring(status));
    }

    return results;
}
