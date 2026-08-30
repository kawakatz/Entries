#include "enum_firewall.h"
#include "com_utils.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"

#include <netfw.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static std::wstring DirectionName(NET_FW_RULE_DIRECTION direction) {
    switch (direction) {
    case NET_FW_RULE_DIR_IN:  return L"In";
    case NET_FW_RULE_DIR_OUT: return L"Out";
    default:                  return L"?";
    }
}

static std::wstring ActionName(NET_FW_ACTION action) {
    switch (action) {
    case NET_FW_ACTION_ALLOW: return L"Allow";
    case NET_FW_ACTION_BLOCK: return L"Block";
    default:                  return L"?";
    }
}

static std::wstring ProtocolName(LONG protocol) {
    switch (protocol) {
    case 6:  return L"TCP";
    case 17: return L"UDP";
    case 1:  return L"ICMP";
    case 58: return L"ICMPv6";
    case 256:return L"Any";
    default: return std::to_wstring(protocol);
    }
}

EntryPointList EnumerateFirewallRules() {
    EntryPointList results;

    HRESULT coInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool shouldUninit = SUCCEEDED(coInit);
    if (FAILED(coInit) && coInit != RPC_E_CHANGED_MODE) {
        ReportPartial(L"Firewall COM initialization failed: "
            + HexCode(static_cast<unsigned long>(coInit)));
        return results;
    }

    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
        CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&policy));
    if (FAILED(hr) || !policy) {
        ReportPartial(L"Firewall policy creation failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        if (shouldUninit) CoUninitialize();
        return results;
    }

    INetFwRules* rules = nullptr;
    if (FAILED(policy->get_Rules(&rules)) || !rules) {
        ReportPartial(L"Firewall rule collection query failed");
        SafeRelease(policy);
        if (shouldUninit) CoUninitialize();
        return results;
    }

    IUnknown* unknownEnum = nullptr;
    hr = rules->get__NewEnum(&unknownEnum);
    if (FAILED(hr) || !unknownEnum) {
        ReportPartial(L"Firewall rule enumerator creation failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }
    else {
        IEnumVARIANT* enumVariant = nullptr;
        hr = unknownEnum->QueryInterface(__uuidof(IEnumVARIANT),
            reinterpret_cast<void**>(&enumVariant));
        if (FAILED(hr) || !enumVariant) {
            ReportPartial(L"Firewall rule enumerator query failed: "
                + HexCode(static_cast<unsigned long>(hr)));
        }
        else {
            VARIANT item;
            VariantInit(&item);
            for (;;) {
                ULONG fetched = 0;
                hr = enumVariant->Next(1, &item, &fetched);
                if (hr == S_FALSE) break;
                if (hr != S_OK || fetched != 1) {
                    ReportPartial(L"Firewall rule enumeration failed: "
                        + HexCode(static_cast<unsigned long>(hr)));
                    break;
                }
                if (item.vt == VT_DISPATCH && item.pdispVal) {
                    INetFwRule* rule = nullptr;
                    if (SUCCEEDED(item.pdispVal->QueryInterface(__uuidof(INetFwRule),
                        reinterpret_cast<void**>(&rule))) && rule) {
                        BSTR name = nullptr, app = nullptr, service = nullptr;
                        BSTR localPorts = nullptr, remotePorts = nullptr, localAddr = nullptr, remoteAddr = nullptr;
                        VARIANT_BOOL enabled = VARIANT_FALSE;
                        NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
                        NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
                        LONG protocol = 0;

                        rule->get_Name(&name);
                        rule->get_ApplicationName(&app);
                        rule->get_ServiceName(&service);
                        rule->get_LocalPorts(&localPorts);
                        rule->get_RemotePorts(&remotePorts);
                        rule->get_LocalAddresses(&localAddr);
                        rule->get_RemoteAddresses(&remoteAddr);
                        rule->get_Enabled(&enabled);
                        rule->get_Direction(&direction);
                        rule->get_Action(&action);
                        rule->get_Protocol(&protocol);

                        std::wstring appPath = BstrToWString(app);
                        std::wstring serviceName = BstrToWString(service);
                        std::wstring ownerPath = ResolveServiceComponentPath(serviceName);
                        if (ownerPath.empty()) {
                            ownerPath = ExtractExecutablePath(appPath);
                        }

                        EntryPoint ep;
                        ep.type = EntryType::Firewall;
                        ep.name = BstrToWString(name);
                        ep.details = L"Firewall rule | Enabled="
                            + std::wstring(enabled == VARIANT_TRUE ? L"true" : L"false")
                            + L" | Direction=" + DirectionName(direction)
                            + L" | Action=" + ActionName(action)
                            + L" | Protocol=" + ProtocolName(protocol);
                        if (!serviceName.empty()) ep.details += L" | Service=" + serviceName;
                        if (!appPath.empty()) ep.details += L" | App=" + appPath;
                        if (localPorts) ep.details += L" | LocalPorts=" + BstrToWString(localPorts);
                        if (remotePorts) ep.details += L" | RemotePorts=" + BstrToWString(remotePorts);
                        if (localAddr) ep.details += L" | LocalAddr=" + BstrToWString(localAddr);
                        if (remoteAddr) ep.details += L" | RemoteAddr=" + BstrToWString(remoteAddr);
                        ep.ownerPath = ownerPath.empty() ? L"<firewall-rule>" : ownerPath;
                        results.push_back(std::move(ep));

                        FreeBstr(name);
                        FreeBstr(app);
                        FreeBstr(service);
                        FreeBstr(localPorts);
                        FreeBstr(remotePorts);
                        FreeBstr(localAddr);
                        FreeBstr(remoteAddr);
                        SafeRelease(rule);
                    }
                    else {
                        ReportPartial(L"Firewall rule interface query failed");
                    }
                }
                else {
                    ReportPartial(L"Firewall rule enumerator returned an invalid item");
                }
                VariantClear(&item);
            }
            VariantClear(&item);
            SafeRelease(enumVariant);
        }
        SafeRelease(unknownEnum);
    }

    SafeRelease(rules);
    SafeRelease(policy);
    if (shouldUninit) CoUninitialize();
    return results;
}
