#include "enum_persistence.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"

#include <set>
#include <sstream>

#pragma comment(lib, "advapi32.lib")

static constexpr const wchar_t* kRetryMessage =
    L"Persistence registry value changed during retries";

static bool ReadPersistenceString(HKEY hKey, const wchar_t* valueName,
    std::wstring& value)
{
    return ReadRegString(hKey, valueName, value, kRetryMessage);
}

static std::wstring ReadPersistenceStringValue(HKEY root,
    const std::wstring& path,
    const wchar_t* valueName, REGSAM view = 0)
{
    return ReadRegStringValue(root, path, valueName, view, kRetryMessage);
}

static std::vector<std::wstring> EnumPersistenceSubKeys(HKEY root,
    const std::wstring& path, REGSAM view = 0)
{
    return EnumSubKeys(root, path, view, L"Persistence");
}

static std::vector<std::wstring> ReadMultiSz(HKEY hKey, const wchar_t* valueName) {
    std::vector<std::wstring> out;
    DWORD type = 0;
    std::vector<BYTE> data;
    if (!ReadRegData(hKey, valueName, type, data, kRetryMessage) || data.empty()
        || (type != REG_MULTI_SZ && type != REG_SZ)) return out;

    data.resize(data.size() + 2 * sizeof(WCHAR), 0);
    const WCHAR* cursor = reinterpret_cast<const WCHAR*>(data.data());
    while (*cursor) {
        std::wstring entry = cursor;
        if (!entry.empty()) out.push_back(std::move(entry));
        cursor += wcslen(cursor) + 1;
    }
    return out;
}

static std::vector<std::wstring> SplitPathList(const std::wstring& value) {
    std::vector<std::wstring> paths;
    std::wstring path;
    bool quoted = false;
    for (wchar_t character : value) {
        if (character == L'"') {
            quoted = !quoted;
        }
        else if (!quoted && (character == L',' || iswspace(character))) {
            if (!path.empty()) paths.push_back(std::move(path));
            path.clear();
        }
        else {
            path += character;
        }
    }
    if (!path.empty()) paths.push_back(std::move(path));
    return paths;
}

struct ValuePair {
    std::wstring name;
    std::wstring data;
};

static std::vector<ValuePair> EnumValues(HKEY root, const std::wstring& path,
    REGSAM view = 0)
{
    std::vector<ValuePair> result;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &hKey)
            != ERROR_SUCCESS) {
        return result;
    }

    DWORD maxName = 0;
    DWORD maxData = 0;
    if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, &maxName, &maxData, nullptr, nullptr)
        != ERROR_SUCCESS) {
        ReportPartial(L"Persistence value sizing failed");
        RegCloseKey(hKey);
        return result;
    }
    std::vector<WCHAR> nameBuffer(maxName + 1);
    std::vector<BYTE> dataBuffer(maxData ? maxData : 1);

    for (DWORD index = 0;; index++) {
        RegistryValueInfo rawValue;
        LSTATUS status = QueryRegistryValue(hKey, index, nameBuffer,
            dataBuffer, rawValue);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) {
            ReportPartial(L"Persistence value enumeration failed: "
                + std::to_wstring(status));
            break;
        }
        ValuePair value;
        value.name = std::move(rawValue.name);
        if (rawValue.type == REG_SZ || rawValue.type == REG_EXPAND_SZ) {
            size_t chars = rawValue.dataBytes / sizeof(WCHAR);
            const auto* data = reinterpret_cast<const WCHAR*>(dataBuffer.data());
            size_t length = 0;
            while (length < chars && data[length] != L'\0') length++;
            value.data.assign(data, length);
            if (rawValue.type == REG_EXPAND_SZ) {
                value.data = ExpandEnvironmentPath(value.data);
            }
        }
        result.push_back(std::move(value));
    }

    RegCloseKey(hKey);
    return result;
}

static std::wstring HiveLabel(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    if (root == HKEY_CLASSES_ROOT) return L"HKCR";
    if (root == HKEY_USERS) return L"HKU";
    return L"HK?";
}

static void AddEntry(EntryPointList& results,
    std::set<std::wstring>& seen,
    const std::wstring& dedup,
    const std::wstring& name,
    const std::wstring& details,
    const std::wstring& ownerPath)
{
    if (seen.count(dedup)) return;
    seen.insert(dedup);

    EntryPoint ep;
    ep.type = EntryType::Persistence;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<persistence>" : ownerPath;
    results.push_back(std::move(ep));
}

static void EmitCommandsFromValues(EntryPointList& results,
    std::set<std::wstring>& seen,
    HKEY root,
    const std::wstring& path,
    REGSAM view,
    const wchar_t* category)
{
    auto values = EnumValues(root, path, view);
    std::wstring hive = HiveLabel(root);
    for (const auto& v : values) {
        if (v.data.empty()) continue;
        std::wstring ownerPath = ExtractExecutablePath(v.data);

        std::wstring details = std::wstring(category)
            + L" | " + hive + L"\\" + path
            + L" | Value=" + v.name
            + L" | Command=" + v.data;

        std::wstring dedup = ToLower(std::wstring(category) + L"|" + hive + L"|"
            + path + L"|" + v.name + L"|" + ownerPath);

        AddEntry(results, seen, dedup, std::wstring(category) + L":" + v.name,
                 details, ownerPath);
    }
}

static void EmitCommandsFromSubkeys(EntryPointList& results,
    std::set<std::wstring>& seen,
    HKEY root,
    const std::wstring& path,
    const wchar_t* commandValueName,
    REGSAM view,
    const wchar_t* category)
{
    std::wstring hive = HiveLabel(root);
    for (const auto& sub : EnumPersistenceSubKeys(root, path, view)) {
        std::wstring subPath = path + L"\\" + sub;

        std::wstring command;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(root, subPath.c_str(), 0,
            KEY_READ | view, &hKey) != ERROR_SUCCESS) {
            continue;
        }
        ReadPersistenceString(hKey, commandValueName, command);

        std::wstring stubPath;
        DWORD globalFlag = 0;
        bool hasGlobalFlag = ReadRegDword(hKey, L"GlobalFlag", globalFlag);
        ReadPersistenceString(hKey, L"StubPath", stubPath);

        RegCloseKey(hKey);

        if (command.empty()) continue;

        std::wstring ownerPath = ExtractExecutablePath(command);
        std::wstring details = std::wstring(category)
            + L" | " + hive + L"\\" + subPath
            + L" | " + commandValueName + L"=" + command;
        if (hasGlobalFlag) {
            std::wstringstream ss;
            ss << L" | GlobalFlag=0x" << std::hex << globalFlag;
            details += ss.str();
        }
        if (!stubPath.empty() && _wcsicmp(commandValueName, L"StubPath") != 0) {
            details += L" | StubPath=" + stubPath;
        }

        std::wstring dedup = ToLower(std::wstring(category) + L"|" + hive + L"|"
            + sub + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(category) + L":" + sub,
                 details, ownerPath);
    }
}

static std::wstring ResolveLsaPackage(const std::wstring& name) {
    std::wstring base = name;
    std::wstring lower = ToLower(base);
    if (lower.size() < 4 || lower.substr(lower.size() - 4) != L".dll") {
        base += L".dll";
    }
    return ExpandEnvironmentPath(L"%SystemRoot%\\System32\\" + base);
}

static void EmitMultiSzList(EntryPointList& results,
    std::set<std::wstring>& seen,
    HKEY root,
    const std::wstring& path,
    const wchar_t* valueName,
    REGSAM view,
    const wchar_t* category,
    bool resolveLsa)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &hKey)
            != ERROR_SUCCESS) {
        return;
    }
    auto items = ReadMultiSz(hKey, valueName);
    RegCloseKey(hKey);

    std::wstring hive = HiveLabel(root);
    for (const auto& item : items) {
        std::wstring ownerPath = resolveLsa
            ? ResolveLsaPackage(item)
            : ExtractExecutablePath(item);

        std::wstring details = std::wstring(category)
            + L" | " + hive + L"\\" + path
            + L" | " + valueName + L"=" + item;

        std::wstring dedup = ToLower(std::wstring(category) + L"|" + hive + L"|"
            + valueName + L"|" + item);
        AddEntry(results, seen, dedup, std::wstring(category) + L":" + item,
                 details, ownerPath);
    }
}

static void EmitClsidProviders(EntryPointList& results,
    std::set<std::wstring>& seen,
    HKEY root,
    const std::wstring& path,
    REGSAM view,
    const wchar_t* category)
{
    std::wstring hive = HiveLabel(root);
    for (const auto& sub : EnumPersistenceSubKeys(root, path, view)) {
        std::wstring friendly = ReadPersistenceStringValue(root,
            path + L"\\" + sub, nullptr, view);

        std::wstring ownerPath = ResolveClsidServerPath(sub);
        std::wstring details = std::wstring(category)
            + L" | " + hive + L"\\" + path + L"\\" + sub;
        if (!friendly.empty()) details += L" | Name=" + friendly;
        if (!ownerPath.empty()) details += L" | Server=" + ownerPath;

        std::wstring dedup = ToLower(std::wstring(category) + L"|" + sub
            + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(category) + L":" + sub,
                 details, ownerPath);
    }
}

static void EmitWinlogonValues(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    const wchar_t* keys[] = {
        L"Userinit",
        L"Shell",
        L"System",
        L"AppSetup",
        L"GinaDll",
        L"VmApplet",
        L"TaskMan",
        L"Taskman",
        L"UIHost",
    };

    const std::wstring path = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

    for (auto valueName : keys) {
        std::wstring data = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            path, valueName);
        if (data.empty()) continue;

        std::wstring ownerPath = ExtractExecutablePath(data);
        std::wstring details = std::wstring(L"Winlogon | HKLM\\")
            + path + L" | " + valueName + L"=" + data;
        std::wstring dedup = ToLower(std::wstring(L"winlogon|") + valueName + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(L"Winlogon:") + valueName,
                 details, ownerPath);
    }

    std::wstring notifyPath = path + L"\\Notify";
    for (const auto& sub : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE, notifyPath)) {
        std::wstring subPath = notifyPath + L"\\" + sub;
        std::wstring dll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            subPath, L"DllName");
        if (dll.empty()) continue;
        std::wstring ownerPath = ExtractExecutablePath(dll);
        std::wstring details = std::wstring(L"Winlogon Notify | HKLM\\")
            + subPath + L" | DllName=" + dll;
        std::wstring dedup = ToLower(std::wstring(L"winlogon-notify|") + sub + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(L"Winlogon\\Notify:") + sub,
                 details, ownerPath);
    }
}

static void EmitNetworkProviders(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    std::wstring orderPath = L"SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order";
    std::wstring orderValue = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
        orderPath, L"ProviderOrder");

    std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services";
    for (const auto& sub : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE,
        servicesPath)) {
        std::wstring providerPath = servicesPath + L"\\" + sub + L"\\NetworkProvider";
        std::wstring providerDll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            providerPath, L"ProviderPath");
        if (providerDll.empty()) {
            providerDll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
                providerPath, L"DLLName");
        }
        if (providerDll.empty()) continue;

        std::wstring providerName = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            providerPath, L"Name");

        std::wstring ownerPath = ExtractExecutablePath(providerDll);
        std::wstring details = std::wstring(L"Network Provider | HKLM\\")
            + providerPath + L" | DLL=" + providerDll;
        if (!providerName.empty()) details += L" | Name=" + providerName;
        if (!orderValue.empty()) details += L" | OrderList=" + orderValue;

        std::wstring dedup = ToLower(std::wstring(L"network-provider|") + sub
            + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(L"NetworkProvider:") + sub,
                 details, ownerPath);
    }
}

static void EmitPrintExtensions(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    struct Row {
        const wchar_t* keyPath;
        const wchar_t* dllValue;
        const wchar_t* category;
    };

    const Row rows[] = {
        { L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",   L"Driver", L"Print Monitor" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Print\\Providers",  L"Name",   L"Print Provider" },
    };

    for (const auto& row : rows) {
        for (const auto& sub : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE,
            row.keyPath)) {
            std::wstring subPath = std::wstring(row.keyPath) + L"\\" + sub;
            std::wstring dll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
                subPath, row.dllValue);
            if (dll.empty()) continue;
            std::wstring ownerPath = ExtractExecutablePath(dll);

            std::wstring details = std::wstring(row.category)
                + L" | HKLM\\" + subPath + L" | " + row.dllValue + L"=" + dll;
            std::wstring dedup = ToLower(std::wstring(row.category) + L"|"
                + sub + L"|" + ownerPath);
            AddEntry(results, seen, dedup,
                std::wstring(row.category) + L":" + sub, details, ownerPath);
        }
    }

    std::wstring envPath = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments";
    for (const auto& env : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE, envPath)) {
        std::wstring procPath = envPath + L"\\" + env + L"\\Print Processors";
        for (const auto& proc : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE,
            procPath)) {
            std::wstring subPath = procPath + L"\\" + proc;
            std::wstring dll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
                subPath, L"Driver");
            if (dll.empty()) continue;
            std::wstring ownerPath = ExtractExecutablePath(dll);
            std::wstring details = std::wstring(L"Print Processor | HKLM\\")
                + subPath + L" | Driver=" + dll
                + L" | Environment=" + env;
            std::wstring dedup = ToLower(std::wstring(L"print-processor|") + env
                + L"|" + proc + L"|" + ownerPath);
            AddEntry(results, seen, dedup,
                std::wstring(L"PrintProcessor:") + env + L"\\" + proc,
                details, ownerPath);
        }
    }
}

static void EmitWinsockLsps(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    const wchar_t* paths[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64",
    };

    for (auto path : paths) {
        for (const auto& sub : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE, path)) {
            std::wstring subPath = std::wstring(path) + L"\\" + sub;

            // PackedCatalogItem embeds a fixed 260-WCHAR library path.
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0,
                KEY_READ, &hKey) != ERROR_SUCCESS) {
                continue;
            }

            DWORD type = 0;
            std::vector<BYTE> buf;
            std::wstring filePath;
            if (ReadRegData(hKey, L"PackedCatalogItem", type, buf, kRetryMessage)
                && !buf.empty() && type == REG_BINARY) {
                const WCHAR* p = reinterpret_cast<const WCHAR*>(buf.data());
                size_t maxChars = buf.size() / sizeof(WCHAR);
                std::wstring scanBuf;
                for (size_t i = 0; i < maxChars; i++) {
                    wchar_t c = p[i];
                    if (c == 0) {
                        if (!scanBuf.empty() && scanBuf.size() > 4
                            && ToLower(scanBuf).find(L".dll") != std::wstring::npos) {
                            filePath = scanBuf;
                            break;
                        }
                        scanBuf.clear();
                    } else if (c >= 0x20 && c < 0xFFFF) {
                        scanBuf += c;
                    } else {
                        scanBuf.clear();
                    }
                }
            }
            RegCloseKey(hKey);

            std::wstring expanded = ExpandEnvironmentPath(filePath);
            std::wstring ownerPath = ExtractExecutablePath(expanded);

            std::wstring details = std::wstring(L"Winsock catalog | HKLM\\")
                + subPath;
            if (!filePath.empty()) details += L" | LibraryPath=" + filePath;

            std::wstring dedup = ToLower(std::wstring(L"winsock-lsp|")
                + sub + L"|" + ownerPath);
            AddEntry(results, seen, dedup,
                std::wstring(L"Winsock:") + sub, details, ownerPath);
        }
    }
}

static void EmitAutologgerSessions(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    const std::wstring root = L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger";
    for (const auto& sess : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE, root)) {
        std::wstring subPath = root + L"\\" + sess;

        std::wstring fileName = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            subPath, L"FileName");

        std::wstring details = std::wstring(L"Autologger ETW session | HKLM\\")
            + subPath;
        if (!fileName.empty()) details += L" | FileName=" + fileName;

        for (const auto& guid : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE,
            subPath)) {
            std::wstring guidPath = subPath + L"\\" + guid;

            DWORD enabled = 1;
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, guidPath.c_str(), 0,
                KEY_READ, &hKey) == ERROR_SUCCESS) {
                ReadRegDword(hKey, L"Enabled", enabled);
                RegCloseKey(hKey);
            }
            if (enabled == 0) continue;

            std::wstring publisherPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                L"\\WINEVT\\Publishers\\" + guid;
            std::wstring resourceDll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
                publisherPath, L"ResourceFileName");
            std::wstring providerName = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
                publisherPath, nullptr);

            std::wstring ownerPath = ExtractExecutablePath(
                ExpandEnvironmentPath(resourceDll));

            std::wstring perProviderDetails = details
                + L" | ProviderGuid=" + guid;
            if (!providerName.empty()) {
                perProviderDetails += L" | Provider=" + providerName;
            }

            std::wstring dedup = ToLower(std::wstring(L"autologger|") + sess
                + L"|" + guid);
            AddEntry(results, seen, dedup,
                std::wstring(L"Autologger:") + sess + L"\\" + guid,
                perProviderDetails,
                ownerPath.empty() ? std::wstring(L"<etw-provider>") : ownerPath);
        }
    }
}

static void EmitInstalledSdbs(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    const std::wstring root = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        L"\\AppCompatFlags\\InstalledSDB";
    for (const auto& sub : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE, root)) {
        std::wstring subPath = root + L"\\" + sub;
        std::wstring dbPath = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            subPath, L"DatabasePath");
        std::wstring desc = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            subPath, L"DatabaseDescription");
        std::wstring ownerPath = dbPath;

        std::wstring details = std::wstring(L"Installed SDB | HKLM\\") + subPath;
        if (!dbPath.empty()) details += L" | Path=" + dbPath;
        if (!desc.empty()) details += L" | Description=" + desc;

        std::wstring dedup = ToLower(std::wstring(L"sdb|") + sub + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(L"SDB:") + sub, details, ownerPath);
    }
}

static void EmitTimeProviders(EntryPointList& results,
    std::set<std::wstring>& seen)
{
    const std::wstring root = L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders";
    for (const auto& sub : EnumPersistenceSubKeys(HKEY_LOCAL_MACHINE, root)) {
        std::wstring subPath = root + L"\\" + sub;
        std::wstring dll = ReadPersistenceStringValue(HKEY_LOCAL_MACHINE,
            subPath, L"DllName");
        if (dll.empty()) continue;
        std::wstring ownerPath = ExtractExecutablePath(dll);
        std::wstring details = std::wstring(L"W32Time provider | HKLM\\")
            + subPath + L" | DllName=" + dll;

        DWORD enabled = 1;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0,
            KEY_READ, &hKey) == ERROR_SUCCESS) {
            ReadRegDword(hKey, L"Enabled", enabled);
            RegCloseKey(hKey);
        }
        details += L" | Enabled=" + std::to_wstring(enabled);

        std::wstring dedup = ToLower(std::wstring(L"timeprov|") + sub + L"|" + ownerPath);
        AddEntry(results, seen, dedup, std::wstring(L"TimeProvider:") + sub,
                 details, ownerPath);
    }
}

EntryPointList EnumeratePersistenceSurfaces() {
    EntryPointList results;
    std::set<std::wstring> seen;

    struct ValuesKey {
        HKEY root;
        const wchar_t* path;
        REGSAM view;
        const wchar_t* category;
    };

    const ValuesKey valueKeys[] = {
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",      KEY_WOW64_64KEY, L"Run" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",      KEY_WOW64_32KEY, L"Run-Wow64" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  KEY_WOW64_64KEY, L"RunOnce" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  KEY_WOW64_32KEY, L"RunOnce-Wow64" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", KEY_WOW64_64KEY, L"RunOnceEx" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",      0, L"Run" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",  0, L"RunOnce" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 0, L"RunOnceEx" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0, L"PolicyRun" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0, L"PolicyRun" },
    };

    for (const auto& k : valueKeys) {
        EmitCommandsFromValues(results, seen, k.root, k.path, k.view, k.category);
    }

    {
        const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
        for (auto v : views) {
            std::wstring path = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                KEY_READ | v, &hKey) != ERROR_SUCCESS) continue;

            std::wstring appInitDlls;
            ReadPersistenceString(hKey, L"AppInit_DLLs", appInitDlls);

            DWORD load = 0;
            ReadRegDword(hKey, L"LoadAppInit_DLLs", load);

            DWORD reqSig = 0;
            ReadRegDword(hKey, L"RequireSignedAppInit_DLLs", reqSig);

            RegCloseKey(hKey);

            for (const auto& dll : SplitPathList(appInitDlls)) {
                std::wstring details = std::wstring(L"AppInit_DLLs | HKLM\\")
                    + path + L" | View=" + (v == KEY_WOW64_64KEY ? L"64-bit" : L"32-bit")
                    + L" | LoadAppInit_DLLs=" + std::to_wstring(load)
                    + L" | RequireSigned=" + std::to_wstring(reqSig)
                    + L" | Dll=" + dll;
                std::wstring dedup = ToLower(std::wstring(L"appinit|")
                    + (v == KEY_WOW64_64KEY ? L"64" : L"32") + L"|" + dll);
                AddEntry(results, seen, dedup, L"AppInit_DLLs:" + dll,
                    details, ExtractExecutablePath(dll));
            }
        }
    }

    EmitCommandsFromValues(results, seen, HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
        0, L"AppCertDll");

    EmitCommandsFromValues(results, seen, HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls",
        0, L"KnownDll");
    EmitCommandsFromValues(results, seen, HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls32",
        0, L"KnownDll32");

    EmitCommandsFromSubkeys(results, seen, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"Debugger", KEY_WOW64_64KEY, L"IFEO Debugger");
    EmitCommandsFromSubkeys(results, seen, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        L"Debugger", KEY_WOW64_32KEY, L"IFEO Debugger");

    EmitCommandsFromSubkeys(results, seen, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
        L"MonitorProcess", 0, L"SilentProcessExit");

    EmitCommandsFromSubkeys(results, seen, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Active Setup\\Installed Components",
        L"StubPath", KEY_WOW64_64KEY, L"Active Setup");
    EmitCommandsFromSubkeys(results, seen, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Active Setup\\Installed Components",
        L"StubPath", KEY_WOW64_32KEY, L"Active Setup");

    EmitWinlogonValues(results, seen);

    {
        const std::wstring lsa = L"System\\CurrentControlSet\\Control\\Lsa";
        EmitMultiSzList(results, seen, HKEY_LOCAL_MACHINE, lsa,
            L"Authentication Packages", 0, L"LSA Authentication Package", true);
        EmitMultiSzList(results, seen, HKEY_LOCAL_MACHINE, lsa,
            L"Notification Packages", 0, L"LSA Notification Package", true);
        EmitMultiSzList(results, seen, HKEY_LOCAL_MACHINE, lsa,
            L"Security Packages", 0, L"LSA Security Package", true);

        EmitMultiSzList(results, seen, HKEY_LOCAL_MACHINE,
            lsa + L"\\OSConfig", L"Security Packages", 0,
            L"LSA OSConfig Security Package", true);
    }

    {
        const std::wstring authBase = L"Software\\Microsoft\\Windows\\CurrentVersion\\Authentication";
        EmitClsidProviders(results, seen, HKEY_LOCAL_MACHINE,
            authBase + L"\\Credential Providers", 0, L"Credential Provider");
        EmitClsidProviders(results, seen, HKEY_LOCAL_MACHINE,
            authBase + L"\\Credential Provider Filters", 0, L"Credential Provider Filter");
        EmitClsidProviders(results, seen, HKEY_LOCAL_MACHINE,
            authBase + L"\\Pre-Logon Access Providers", 0, L"Pre-Logon Access Provider");
        EmitClsidProviders(results, seen, HKEY_LOCAL_MACHINE,
            authBase + L"\\PLAP Providers", 0, L"PLAP Provider");
    }

    EmitClsidProviders(results, seen, HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\AMSI\\Providers", 0, L"AMSI Provider");

    EmitNetworkProviders(results, seen);

    EmitPrintExtensions(results, seen);

    EmitWinsockLsps(results, seen);

    EmitAutologgerSessions(results, seen);

    EmitInstalledSdbs(results, seen);

    EmitTimeProviders(results, seen);

    return results;
}
