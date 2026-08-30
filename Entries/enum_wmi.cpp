#include "enum_wmi.h"
#include "com_utils.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"
#include "security_utils.h"

#include <wbemidl.h>
#include <set>

#pragma comment(lib, "wbemuuid.lib")

static std::wstring VariantToString(VARIANT& value) {
    if (value.vt == VT_BSTR && value.bstrVal) {
        return std::wstring(value.bstrVal, SysStringLen(value.bstrVal));
    }
    if (value.vt == VT_I4) return std::to_wstring(value.lVal);
    if (value.vt == VT_UI4) return std::to_wstring(value.ulVal);
    if (value.vt == VT_BOOL) return value.boolVal == VARIANT_TRUE ? L"true" : L"false";
    if (value.vt == (VT_ARRAY | VT_UI1) && value.parray
        && SafeArrayGetDim(value.parray) == 1) {
        LONG lower = 0, upper = -1;
        if (FAILED(SafeArrayGetLBound(value.parray, 1, &lower))
            || FAILED(SafeArrayGetUBound(value.parray, 1, &upper))
            || upper < lower) {
            return L"";
        }

        BYTE* bytes = nullptr;
        if (FAILED(SafeArrayAccessData(value.parray,
            reinterpret_cast<void**>(&bytes)))) {
            return L"";
        }
        ULONG length = static_cast<ULONG>(upper - lower + 1);
        std::wstring result;
        if (length >= SECURITY_MIN_SID_SIZE && IsValidSid(bytes)
            && GetLengthSid(bytes) <= length) {
            result = SidToAccountName(bytes);
        }
        SafeArrayUnaccessData(value.parray);
        return result;
    }
    return L"";
}

static std::wstring GetWmiString(IWbemClassObject* object, const wchar_t* propertyName) {
    VARIANT value;
    VariantInit(&value);
    std::wstring result;
    if (SUCCEEDED(object->Get(propertyName, 0, &value, nullptr, nullptr))) {
        result = VariantToString(value);
    }
    VariantClear(&value);
    return result;
}

static IWbemServices* ConnectNamespace(IWbemLocator* locator,
    const std::wstring& ns)
{
    IWbemServices* services = nullptr;
    BSTR namespaceName = SysAllocString(ns.c_str());
    if (!namespaceName) {
        ReportPartial(L"WMI namespace allocation failed");
        return nullptr;
    }
    HRESULT hr = locator->ConnectServer(namespaceName, nullptr, nullptr, nullptr,
        0, nullptr, nullptr, &services);
    SysFreeString(namespaceName);
    if (FAILED(hr) || !services) {
        ReportPartial(L"WMI namespace connection failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        return nullptr;
    }

    hr = CoSetProxyBlanket(services,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE);
    if (FAILED(hr)) {
        ReportPartial(L"WMI proxy security setup failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        SafeRelease(services);
        return nullptr;
    }

    return services;
}

static IEnumWbemClassObject* QueryWmi(IWbemServices* services,
    const wchar_t* queryText,
    const wchar_t* label)
{
    BSTR queryLanguage = SysAllocString(L"WQL");
    BSTR query = SysAllocString(queryText);
    if (!queryLanguage || !query) {
        SysFreeString(queryLanguage);
        SysFreeString(query);
        ReportPartial(std::wstring(label) + L" query allocation failed");
        return nullptr;
    }

    IEnumWbemClassObject* enumerator = nullptr;
    HRESULT hr = services->ExecQuery(queryLanguage, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &enumerator);
    SysFreeString(queryLanguage);
    SysFreeString(query);
    if (FAILED(hr) || !enumerator) {
        ReportPartial(std::wstring(label) + L" query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        SafeRelease(enumerator);
        return nullptr;
    }
    return enumerator;
}

static IWbemClassObject* NextWmiObject(IEnumWbemClassObject* enumerator,
    long timeout,
    const wchar_t* label)
{
    for (int attempt = 0; attempt < 3; attempt++) {
        IWbemClassObject* object = nullptr;
        ULONG returned = 0;
        HRESULT hr = enumerator->Next(timeout, 1, &object, &returned);
        if (returned == 1 && object && SUCCEEDED(hr)) return object;
        SafeRelease(object);
        if (hr == WBEM_S_FALSE) return nullptr;
        if (hr == WBEM_S_TIMEDOUT && attempt != 2) continue;

        ReportPartial(std::wstring(label)
            + (hr == WBEM_S_TIMEDOUT ? L" enumeration timed out: " : L" enumeration failed: ")
            + HexCode(static_cast<unsigned long>(hr)));
        return nullptr;
    }
    return nullptr;
}

static void AddWmiEntry(EntryPointList& results,
    const std::wstring& name,
    const std::wstring& details,
    const std::wstring& ownerPath)
{
    EntryPoint ep;
    ep.type = EntryType::WMI;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<wmi>" : ownerPath;
    results.push_back(std::move(ep));
}

static void QueryConsumers(IWbemServices* services, EntryPointList& results) {
    IEnumWbemClassObject* enumerator = QueryWmi(services,
        L"SELECT * FROM __EventConsumer", L"WMI consumer");
    if (!enumerator) return;

    for (;;) {
        IWbemClassObject* object = NextWmiObject(enumerator, 5000, L"WMI consumer");
        if (!object) break;
        std::wstring className = GetWmiString(object, L"__CLASS");
        std::wstring name = GetWmiString(object, L"Name");
        std::wstring command = GetWmiString(object, L"CommandLineTemplate");
        std::wstring executable = GetWmiString(object, L"ExecutablePath");
        std::wstring scriptFile = GetWmiString(object, L"ScriptFileName");
        std::wstring scriptingEngine = GetWmiString(object, L"ScriptingEngine");
        std::wstring creatorSid = GetWmiString(object, L"CreatorSID");

        std::wstring ownerPath = !executable.empty()
            ? ExtractExecutablePath(executable)
            : ExtractExecutablePath(command);
        if (ownerPath.empty() && !scriptFile.empty()) ownerPath = scriptFile;

        std::wstring details = L"WMI permanent event consumer | Class=" + className;
        if (!command.empty()) details += L" | Command=" + command;
        if (!executable.empty()) details += L" | Executable=" + executable;
        if (!scriptFile.empty()) details += L" | ScriptFile=" + scriptFile;
        if (!scriptingEngine.empty()) details += L" | Engine=" + scriptingEngine;
        if (!creatorSid.empty()) details += L" | CreatorSID=" + creatorSid;

        AddWmiEntry(results, L"Consumer:" + name, details, ownerPath);
        SafeRelease(object);
    }

    SafeRelease(enumerator);
}

static void QueryEventFilters(IWbemServices* services, EntryPointList& results) {
    IEnumWbemClassObject* enumerator = QueryWmi(services,
        L"SELECT * FROM __EventFilter", L"WMI event-filter");
    if (!enumerator) return;

    for (;;) {
        IWbemClassObject* object = NextWmiObject(enumerator, 5000,
            L"WMI event-filter");
        if (!object) break;
        std::wstring name = GetWmiString(object, L"Name");
        std::wstring eventNs = GetWmiString(object, L"EventNamespace");
        std::wstring queryLang = GetWmiString(object, L"QueryLanguage");
        std::wstring filterQuery = GetWmiString(object, L"Query");
        std::wstring creatorSid = GetWmiString(object, L"CreatorSID");

        std::wstring details = L"WMI permanent event filter";
        if (!eventNs.empty()) details += L" | EventNamespace=" + eventNs;
        if (!queryLang.empty()) details += L" | Lang=" + queryLang;
        if (!filterQuery.empty()) details += L" | Query=" + filterQuery;
        if (!creatorSid.empty()) details += L" | CreatorSID=" + creatorSid;

        AddWmiEntry(results, L"EventFilter:" + name, details,
            std::wstring(L"<wmi-filter>"));
        SafeRelease(object);
    }
    SafeRelease(enumerator);
}

static void QueryFilterToConsumerBindings(IWbemServices* services,
    EntryPointList& results)
{
    IEnumWbemClassObject* enumerator = QueryWmi(services,
        L"SELECT * FROM __FilterToConsumerBinding", L"WMI binding");
    if (!enumerator) return;

    for (;;) {
        IWbemClassObject* object = NextWmiObject(enumerator, 5000, L"WMI binding");
        if (!object) break;
        std::wstring filter = GetWmiString(object, L"Filter");
        std::wstring consumer = GetWmiString(object, L"Consumer");
        std::wstring creatorSid = GetWmiString(object, L"CreatorSID");

        std::wstring details = L"WMI filter-to-consumer binding";
        if (!filter.empty()) details += L" | Filter=" + filter;
        if (!consumer.empty()) details += L" | Consumer=" + consumer;
        if (!creatorSid.empty()) details += L" | CreatorSID=" + creatorSid;

        std::wstring name = filter.empty() ? consumer : filter + L" => " + consumer;
        AddWmiEntry(results, L"Binding:" + name, details,
            std::wstring(L"<wmi-binding>"));
        SafeRelease(object);
    }
    SafeRelease(enumerator);
}

static void QueryProviders(IWbemServices* services,
    const std::wstring& ns,
    EntryPointList& results,
    std::set<std::wstring>& seen);

static void EnumerateNamespaceProviders(IWbemLocator* locator,
    const std::wstring& ns,
    std::set<std::wstring>& visited,
    EntryPointList& results,
    std::set<std::wstring>& seen,
    int depth,
    int maxDepth)
{
    if (!visited.insert(ToLower(ns)).second) return;

    IWbemServices* services = ConnectNamespace(locator, ns);
    if (!services) return;

    QueryProviders(services, ns, results, seen);

    IEnumWbemClassObject* enumerator = QueryWmi(services,
        L"SELECT Name FROM __Namespace", L"WMI child-namespace");
    if (!enumerator) {
        SafeRelease(services);
        return;
    }

    std::vector<std::wstring> children;
    for (;;) {
        IWbemClassObject* object = NextWmiObject(enumerator, 2000,
            L"WMI child-namespace");
        if (!object) break;
        std::wstring child = GetWmiString(object, L"Name");
        if (!child.empty()) children.push_back(ns + L"\\" + child);
        SafeRelease(object);
    }
    SafeRelease(enumerator);
    SafeRelease(services);

    if (depth >= maxDepth) {
        if (!children.empty()) {
            ReportPartial(L"WMI namespace traversal reached its depth limit");
        }
        return;
    }
    for (const auto& child : children) {
        EnumerateNamespaceProviders(locator, child, visited, results, seen,
            depth + 1, maxDepth);
    }
}

static void QueryProviders(IWbemServices* services,
    const std::wstring& ns,
    EntryPointList& results,
    std::set<std::wstring>& seen)
{
    IEnumWbemClassObject* enumerator = QueryWmi(services,
        L"SELECT * FROM __Win32Provider", L"WMI provider");
    if (!enumerator) return;

    for (;;) {
        IWbemClassObject* object = NextWmiObject(enumerator, 5000, L"WMI provider");
        if (!object) break;
        std::wstring name = GetWmiString(object, L"Name");
        std::wstring clsid = GetWmiString(object, L"CLSID");
        std::wstring hosting = GetWmiString(object, L"HostingModel");
        std::wstring path = ResolveClsidServerPath(clsid);

        std::wstring key = ns + L"|" + name + L"|" + clsid;
        if (seen.insert(key).second) {
            std::wstring details = L"WMI provider | Namespace=" + ns
                + L" | CLSID=" + clsid;
            if (!hosting.empty()) details += L" | HostingModel=" + hosting;
            AddWmiEntry(results, L"Provider:" + name, details, path);
        }
        SafeRelease(object);
    }

    SafeRelease(enumerator);
}

EntryPointList EnumerateWmiSurfaces() {
    EntryPointList results;

    HRESULT coInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool shouldUninit = SUCCEEDED(coInit);
    if (FAILED(coInit) && coInit != RPC_E_CHANGED_MODE) {
        ReportPartial(L"WMI COM initialization failed: "
            + HexCode(static_cast<unsigned long>(coInit)));
        return results;
    }

    HRESULT securityStatus = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(securityStatus) && securityStatus != RPC_E_TOO_LATE) {
        ReportPartial(L"WMI COM security initialization failed: "
            + HexCode(static_cast<unsigned long>(securityStatus)));
    }

    IWbemLocator* locator = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator,
        reinterpret_cast<void**>(&locator));
    if (FAILED(hr) || !locator) {
        ReportPartial(L"WMI locator creation failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        if (shouldUninit) CoUninitialize();
        return results;
    }

    IWbemServices* subscription = ConnectNamespace(locator, L"ROOT\\subscription");
    if (subscription) {
        QueryConsumers(subscription, results);
        QueryEventFilters(subscription, results);
        QueryFilterToConsumerBindings(subscription, results);
        SafeRelease(subscription);
    }
    else {
        ReportPartial(L"WMI subscription namespace query failed");
    }

    std::set<std::wstring> seenProviders;
    std::set<std::wstring> visited;
    EnumerateNamespaceProviders(locator, L"ROOT", visited, results,
        seenProviders, 0, 4);

    SafeRelease(locator);
    if (shouldUninit) CoUninitialize();
    return results;
}
