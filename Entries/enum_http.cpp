#include "enum_http.h"
#include "diagnostics.h"
#include "security_utils.h"
#include <cstddef>
#include <http.h>
#include <iomanip>
#include <sstream>
#include <ws2ipdef.h>

#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static std::wstring SockAddrToString(const SOCKADDR* sa) {
    if (!sa) return L"";

    DWORD addressLength;
    if (sa->sa_family == AF_INET) {
        addressLength = sizeof(SOCKADDR_IN);
    }
    else if (sa->sa_family == AF_INET6) {
        addressLength = sizeof(SOCKADDR_IN6);
    }
    else {
        return L"";
    }

    WCHAR buf[64] = {};
    DWORD bufLen = _countof(buf);
    if (WSAAddressToStringW(const_cast<SOCKADDR*>(sa),
        addressLength, nullptr, buf, &bufLen) == 0) {
        return buf;
    }
    return L"";
}

static ULONG QueryHttpConfig(
    HTTP_SERVICE_CONFIG_ID id,
    void* input,
    ULONG inputLength,
    std::vector<BYTE>& buffer) {
    for (int attempt = 0; attempt < 4; attempt++) {
        ULONG returnLength = 0;
        ULONG code = HttpQueryServiceConfiguration(
            nullptr,
            id,
            input,
            inputLength,
            buffer.empty() ? nullptr : buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &returnLength,
            nullptr);

        if (code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_MORE_DATA) {
            return code;
        }
        if (returnLength <= buffer.size() || attempt == 3) {
            return code;
        }
        buffer.resize(returnLength);
    }
    return ERROR_MORE_DATA;
}

static std::wstring HashHex(const BYTE* data, ULONG len) {
    if (!data || len == 0) return L"";
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (ULONG i = 0; i < len; i++) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

static std::wstring FormatGuid(const GUID& value) {
    WCHAR buffer[64] = {};
    swprintf_s(buffer, L"%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X",
        value.Data1, value.Data2, value.Data3,
        value.Data4[0], value.Data4[1], value.Data4[2], value.Data4[3],
        value.Data4[4], value.Data4[5], value.Data4[6], value.Data4[7]);
    return buffer;
}

static std::wstring SslDetails(const wchar_t* label,
    const HTTP_SERVICE_CONFIG_SSL_PARAM& parameters)
{
    std::wstring details = label;
    std::wstring hash = HashHex(static_cast<const BYTE*>(parameters.pSslHash),
        parameters.SslHashLength);
    if (!hash.empty()) details += L" | Thumbprint=" + hash;
    if (parameters.pSslCertStoreName) {
        details += L" | Store=" + std::wstring(parameters.pSslCertStoreName);
    }
    details += L" | AppId=" + FormatGuid(parameters.AppId);
    return details;
}

template <typename Query, typename Config, typename Name>
static void EnumerateSslBindings(HTTP_SERVICE_CONFIG_ID id,
    const wchar_t* label, Name name, EntryPointList& results)
{
    Query query = {};
    query.QueryDesc = HttpServiceConfigQueryNext;
    for (ULONGLONG index = 0; index <= MAXDWORD; index++) {
        query.dwToken = static_cast<DWORD>(index);
        std::vector<BYTE> buffer;
        ULONG code = QueryHttpConfig(id, &query, sizeof(query), buffer);
        if (code == ERROR_NO_MORE_ITEMS) break;
        if (code != NO_ERROR || buffer.size() < sizeof(Config)) {
            ReportPartial(std::wstring(label) + L" enumeration failed: "
                + std::to_wstring(code));
            break;
        }

        const auto* config = reinterpret_cast<const Config*>(buffer.data());
        EntryPoint entry;
        entry.type = EntryType::HTTP;
        entry.name = name(config->KeyDesc);
        entry.details = SslDetails(label, config->ParamDesc);
        entry.ownerPath = L"<ssl-binding>";
        results.push_back(std::move(entry));
    }
}

static bool AddIpListenList(const std::vector<BYTE>& buffer,
    bool winsockInitialized,
    EntryPointList& results)
{
    size_t headerSize = offsetof(HTTP_SERVICE_CONFIG_IP_LISTEN_QUERY, AddrList);
    if (buffer.size() < headerSize) return false;

    const auto* list = reinterpret_cast<const HTTP_SERVICE_CONFIG_IP_LISTEN_QUERY*>(
        buffer.data());
    if (list->AddrCount > (buffer.size() - headerSize) / sizeof(SOCKADDR_STORAGE)) {
        return false;
    }

    std::wstring summary;
    for (ULONG i = 0; i < list->AddrCount; i++) {
        if (i > 0) summary += L",";
        if (winsockInitialized) {
            summary += SockAddrToString(
                reinterpret_cast<const SOCKADDR*>(&list->AddrList[i]));
        }
    }

    EntryPoint ep;
    ep.type = EntryType::HTTP;
    ep.name = L"IPListenList";
    ep.details = L"HTTP.sys explicit listen list ("
        + std::to_wstring(list->AddrCount) + L"): " + summary;
    ep.ownerPath = L"<http.sys-config>";
    results.push_back(std::move(ep));
    return true;
}

EntryPointList EnumerateHttpConfiguration() {
    EntryPointList results;

    HTTPAPI_VERSION version = HTTPAPI_VERSION_1;
    ULONG retCode = HttpInitialize(version, HTTP_INITIALIZE_CONFIG, nullptr);
    if (retCode != NO_ERROR) {
        ReportPartial(L"HTTP configuration initialization failed: "
            + std::to_wstring(retCode));
        return results;
    }

    WSADATA wsaData = {};
    bool winsockInitialized = WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    if (!winsockInitialized) {
        ReportPartial(L"Winsock initialization failed; HTTP addresses may be unresolved");
    }

    HTTP_SERVICE_CONFIG_URLACL_QUERY query = {};
    query.QueryDesc = HttpServiceConfigQueryNext;

    for (ULONGLONG index = 0; index <= MAXDWORD; index++) {
        query.dwToken = static_cast<DWORD>(index);
        std::vector<BYTE> buffer;
        retCode = QueryHttpConfig(
            HttpServiceConfigUrlAclInfo, &query, sizeof(query), buffer);
        if (retCode == ERROR_NO_MORE_ITEMS) break;
        if (retCode != NO_ERROR || buffer.size() < sizeof(HTTP_SERVICE_CONFIG_URLACL_SET)) {
            ReportPartial(L"HTTP URL reservation enumeration failed: "
                + std::to_wstring(retCode));
            break;
        }

        auto* pSet = reinterpret_cast<HTTP_SERVICE_CONFIG_URLACL_SET*>(buffer.data());

        EntryPoint ep;
        ep.type = EntryType::HTTP;
        ep.name = pSet->KeyDesc.pUrlPrefix ? pSet->KeyDesc.pUrlPrefix : L"<unknown>";

        std::wstring sddl = pSet->ParamDesc.pStringSecurityDescriptor
            ? pSet->ParamDesc.pStringSecurityDescriptor : L"";
        std::wstring dacl = SecurityDescriptorSddlDaclSummary(sddl);
        ep.details = dacl.empty() ? L"ACL: " + sddl : L"DACL: " + dacl;

        ep.ownerPath = L"<url-reservation>";

        results.push_back(std::move(ep));
    }

    EnumerateSslBindings<HTTP_SERVICE_CONFIG_SSL_QUERY,
        HTTP_SERVICE_CONFIG_SSL_SET>(HttpServiceConfigSSLCertInfo,
        L"HTTP SSL binding",
        [winsockInitialized](const HTTP_SERVICE_CONFIG_SSL_KEY& key) {
            return std::wstring(L"SSLCertBinding:")
                + (winsockInitialized ? SockAddrToString(key.pIpPort) : L"");
        }, results);

    EnumerateSslBindings<HTTP_SERVICE_CONFIG_SSL_SNI_QUERY,
        HTTP_SERVICE_CONFIG_SSL_SNI_SET>(HttpServiceConfigSslSniCertInfo,
        L"HTTP SNI binding",
        [winsockInitialized](const HTTP_SERVICE_CONFIG_SSL_SNI_KEY& key) {
            std::wstring value = L"SniCertBinding:";
            if (key.Host) value += key.Host;
            std::wstring address = winsockInitialized
                ? SockAddrToString(reinterpret_cast<const SOCKADDR*>(&key.IpPort))
                : L"";
            if (!address.empty()) value += L"@" + address;
            return value;
        }, results);

    EnumerateSslBindings<HTTP_SERVICE_CONFIG_SSL_CCS_QUERY,
        HTTP_SERVICE_CONFIG_SSL_CCS_SET>(HttpServiceConfigSslCcsCertInfo,
        L"HTTP CCS binding",
        [winsockInitialized](const HTTP_SERVICE_CONFIG_SSL_CCS_KEY& key) {
            return std::wstring(L"CcsCertBinding:")
                + (winsockInitialized
                    ? SockAddrToString(reinterpret_cast<const SOCKADDR*>(
                        &key.LocalAddress))
                    : L"");
        }, results);

    {
        std::vector<BYTE> buffer;
        retCode = QueryHttpConfig(
            HttpServiceConfigIPListenList, nullptr, 0, buffer);
        if (retCode == NO_ERROR && !AddIpListenList(buffer, winsockInitialized, results)) {
            ReportPartial(L"HTTP IP listen-list response was truncated");
        }
        else if (retCode != NO_ERROR
            && retCode != ERROR_FILE_NOT_FOUND
            && retCode != ERROR_NO_MORE_ITEMS) {
            ReportPartial(L"HTTP IP listen-list query failed: "
                + std::to_wstring(retCode));
        }
    }

    HttpTerminate(HTTP_INITIALIZE_CONFIG, nullptr);
    if (winsockInitialized) WSACleanup();

    return results;
}
