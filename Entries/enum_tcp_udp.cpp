#include "enum_tcp_udp.h"
#include "diagnostics.h"
#include "process_utils.h"
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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

static std::wstring FormatIPv4(DWORD addr, DWORD port) {
    IN_ADDR inAddr;
    inAddr.S_un.S_addr = addr;
    WCHAR ipStr[64] = {};
    InetNtopW(AF_INET, &inAddr, ipStr, _countof(ipStr));
    return std::wstring(ipStr) + L":" + std::to_wstring(ntohs((u_short)port));
}

static std::wstring FormatIPv6(const IN6_ADDR& addr, DWORD port) {
    WCHAR ipStr[128] = {};
    InetNtopW(AF_INET6, &addr, ipStr, _countof(ipStr));
    return std::wstring(L"[") + ipStr + L"]:" + std::to_wstring(ntohs((u_short)port));
}

static std::wstring TcpStateName(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_LISTEN: return L"LISTENING";
    case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
    case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
    case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
    default: return L"OTHER";
    }
}

EntryPointList EnumerateTcpListeners() {
    EntryPointList results;

    {
        auto buffer = QueryIpTable(L"TCP IPv4 table query",
            [](void* data, DWORD* size) {
                return GetExtendedTcpTable(data, size, FALSE, AF_INET,
                    TCP_TABLE_OWNER_PID_LISTENER, 0);
            });
        if (!buffer.empty()) {
            auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& row = table->table[i];
                EntryPoint ep;
                ep.type = EntryType::TCP;
                ep.name = FormatIPv4(row.dwLocalAddr, row.dwLocalPort);
                ep.details = L"IPv4 " + TcpStateName(row.dwState);
                ep.ownerPid = row.dwOwningPid;
                ep.ownerPath = g_ProcessCache.GetPath(row.dwOwningPid);
                results.push_back(std::move(ep));
            }
        }
    }

    {
        auto buffer = QueryIpTable(L"TCP IPv6 table query",
            [](void* data, DWORD* size) {
                return GetExtendedTcpTable(data, size, FALSE, AF_INET6,
                    TCP_TABLE_OWNER_PID_LISTENER, 0);
            });
        if (!buffer.empty()) {
            auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& row = table->table[i];
                EntryPoint ep;
                ep.type = EntryType::TCP;
                ep.name = FormatIPv6(reinterpret_cast<const IN6_ADDR&>(row.ucLocalAddr), row.dwLocalPort);
                ep.details = L"IPv6 " + TcpStateName(row.dwState);
                ep.ownerPid = row.dwOwningPid;
                ep.ownerPath = g_ProcessCache.GetPath(row.dwOwningPid);
                results.push_back(std::move(ep));
            }
        }
    }

    return results;
}

EntryPointList EnumerateUdpListeners() {
    EntryPointList results;

    {
        auto buffer = QueryIpTable(L"UDP IPv4 table query",
            [](void* data, DWORD* size) {
                return GetExtendedUdpTable(data, size, FALSE, AF_INET,
                    UDP_TABLE_OWNER_PID, 0);
            });
        if (!buffer.empty()) {
            auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& row = table->table[i];
                EntryPoint ep;
                ep.type = EntryType::UDP;
                ep.name = FormatIPv4(row.dwLocalAddr, row.dwLocalPort);
                ep.details = L"IPv4";
                ep.ownerPid = row.dwOwningPid;
                ep.ownerPath = g_ProcessCache.GetPath(row.dwOwningPid);
                results.push_back(std::move(ep));
            }
        }
    }

    {
        auto buffer = QueryIpTable(L"UDP IPv6 table query",
            [](void* data, DWORD* size) {
                return GetExtendedUdpTable(data, size, FALSE, AF_INET6,
                    UDP_TABLE_OWNER_PID, 0);
            });
        if (!buffer.empty()) {
            auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                auto& row = table->table[i];
                EntryPoint ep;
                ep.type = EntryType::UDP;
                ep.name = FormatIPv6(reinterpret_cast<const IN6_ADDR&>(row.ucLocalAddr), row.dwLocalPort);
                ep.details = L"IPv6";
                ep.ownerPid = row.dwOwningPid;
                ep.ownerPath = g_ProcessCache.GetPath(row.dwOwningPid);
                results.push_back(std::move(ep));
            }
        }
    }

    return results;
}
