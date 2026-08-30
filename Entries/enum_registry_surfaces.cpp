#include "enum_registry_surfaces.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"

#include <set>

#pragma comment(lib, "advapi32.lib")

static bool LooksLikeGuid(const std::wstring& value) {
    return value.size() >= 38 && value.front() == L'{' && value[37] == L'}';
}

static std::wstring RootName(HKEY root) {
    if (root == HKEY_CLASSES_ROOT) return L"HKCR";
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    return L"HK?";
}

static bool RegValueExists(HKEY root, const std::wstring& path,
    const wchar_t* valueName, REGSAM view)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, path.c_str(), 0,
        KEY_QUERY_VALUE | view, &hKey);
    if (status != ERROR_SUCCESS) {
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) {
            ReportPartial(L"Association registry open failed: "
                + std::to_wstring(status));
        }
        return false;
    }
    DWORD type = 0;
    DWORD bytes = 0;
    status = RegQueryValueExW(hKey, valueName, nullptr, &type, nullptr, &bytes);
    RegCloseKey(hKey);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        ReportPartial(L"Association registry marker query failed: "
            + std::to_wstring(status));
    }
    return status == ERROR_SUCCESS;
}

static std::wstring ReadAssociationString(HKEY root,
    const std::wstring& path, const wchar_t* valueName, REGSAM view)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view,
        &hKey);
    if (status != ERROR_SUCCESS) {
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) {
            ReportPartial(L"Association registry open failed: "
                + std::to_wstring(status));
        }
        return L"";
    }

    std::wstring value;
    ReadRegString(hKey, valueName, value,
        L"Association registry value changed during retries");
    RegCloseKey(hKey);
    return value;
}

static void AddEntry(EntryPointList& results,
    EntryType type,
    const std::wstring& name,
    const std::wstring& details,
    const std::wstring& ownerPath)
{
    EntryPoint ep;
    ep.type = type;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<registry>" : ownerPath;
    results.push_back(std::move(ep));
}

EntryPointList EnumerateFileProtocolHandlers() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const RegistryRoot roots[] = {
        { HKEY_CLASSES_ROOT, L"", L"HKCR 64-bit", KEY_WOW64_64KEY },
        { HKEY_CLASSES_ROOT, L"", L"HKCR 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"Software\\Classes", L"HKCU Classes", 0 },
        { HKEY_LOCAL_MACHINE, L"Software\\Classes", L"HKLM Classes 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Classes", L"HKLM Classes 32-bit", KEY_WOW64_32KEY },
    };

    for (const auto& root : roots) {
        for (const auto& keyName : EnumSubKeys(root.root, root.path, root.view)) {
            std::wstring base = root.path.empty() ? keyName : root.path + L"\\" + keyName;
            bool isExtension = !keyName.empty() && keyName[0] == L'.';
            std::wstring command = ReadAssociationString(root.root,
                base + L"\\shell\\open\\command", nullptr, root.view);
            std::wstring progId;
            if (command.empty() && isExtension) {
                progId = ReadAssociationString(root.root, base, nullptr,
                    root.view);
                if (!progId.empty()) {
                    std::wstring progIdPath = root.path.empty()
                        ? progId
                        : root.path + L"\\" + progId;
                    command = ReadAssociationString(root.root,
                        progIdPath + L"\\shell\\open\\command", nullptr,
                        root.view);
                }
            }
            if (command.empty()) continue;

            bool isProtocol = RegValueExists(root.root, base, L"URL Protocol", root.view);

            std::wstring ownerPath = ExtractExecutablePath(command);
            std::wstring kind = isProtocol ? L"Protocol" : L"FileAssociation";
            std::wstring details = kind + L" | " + RootName(root.root)
                + L"\\" + base;
            if (!progId.empty()) details += L" | ProgID=" + progId;
            details += L" | Command=" + command;

            std::wstring dedup = ToLower(kind + L"|" + keyName + L"|" + command);
            if (seen.insert(dedup).second) {
                AddEntry(results, EntryType::Assoc, keyName, details, ownerPath);
            }
        }
    }

    const RegistryRoot appPathRoots[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", L"HKLM App Paths 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", L"HKLM App Paths 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", L"HKCU App Paths", 0 },
    };

    for (const auto& root : appPathRoots) {
        for (const auto& appName : EnumSubKeys(root.root, root.path, root.view)) {
            std::wstring keyPath = root.path + L"\\" + appName;
            std::wstring command = ReadAssociationString(root.root, keyPath,
                nullptr, root.view);
            if (command.empty()) continue;
            std::wstring ownerPath = ExtractExecutablePath(command);
            std::wstring dedup = ToLower(L"apppath|" + appName + L"|" + ownerPath);
            if (seen.insert(dedup).second) {
                AddEntry(results, EntryType::Assoc, L"AppPath:" + appName,
                    L"App Paths | " + RootName(root.root) + L"\\" + keyPath
                    + L" | Path=" + command,
                    ownerPath);
            }
        }
    }

    return results;
}

EntryPointList EnumerateShellExtensions() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const std::wstring handlerRoots[] = {
        L"*\\shellex\\ContextMenuHandlers",
        L"*\\shellex\\PropertySheetHandlers",
        L"AllFileSystemObjects\\shellex\\ContextMenuHandlers",
        L"Directory\\shellex\\ContextMenuHandlers",
        L"Directory\\Background\\shellex\\ContextMenuHandlers",
        L"Directory\\shellex\\CopyHookHandlers",
        L"Drive\\shellex\\ContextMenuHandlers",
        L"Folder\\shellex\\ColumnHandlers",
        L"Folder\\shellex\\ContextMenuHandlers",
        L"Folder\\shellex\\ExtShellFolderViews",
        L"lnkfile\\shellex\\ContextMenuHandlers",
        L"exefile\\shellex\\ContextMenuHandlers",
        L"SystemFileAssociations\\image\\shellex\\ContextMenuHandlers",
        L"SystemFileAssociations\\text\\shellex\\ContextMenuHandlers",
    };

    const RegistryRoot classRoots[] = {
        { HKEY_CLASSES_ROOT, L"", L"HKCR 64-bit", KEY_WOW64_64KEY },
        { HKEY_CLASSES_ROOT, L"", L"HKCR 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"Software\\Classes", L"HKCU Classes", 0 },
    };

    for (const auto& root : classRoots) {
        for (const auto& handlerRoot : handlerRoots) {
            std::wstring fullRoot = root.path.empty() ? handlerRoot : root.path + L"\\" + handlerRoot;
            for (const auto& handlerName : EnumSubKeys(root.root, fullRoot, root.view)) {
                std::wstring keyPath = fullRoot + L"\\" + handlerName;
                std::wstring clsid = ReadRegStringValue(root.root, keyPath, nullptr, root.view);
                if (clsid.empty() && LooksLikeGuid(handlerName)) clsid = handlerName;
                if (clsid.empty()) continue;

                std::wstring source;
                std::wstring ownerPath = ResolveClsidServerPath(clsid, &source);
                std::wstring dedup = ToLower(handlerRoot + L"|" + clsid + L"|" + ownerPath);
                if (seen.insert(dedup).second) {
                    AddEntry(results, EntryType::Shell,
                        handlerRoot + L"\\" + handlerName,
                        L"Shell extension | CLSID=" + clsid + L" | " + source
                        + L" | " + RootName(root.root) + L"\\" + keyPath,
                        ownerPath);
                }
            }
        }
    }

    const RegistryRoot approvedRoots[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", L"HKLM Approved 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", L"HKLM Approved 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", L"HKCU Approved", 0 },
    };

    for (const auto& root : approvedRoots) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(root.root, root.path.c_str(), 0,
            KEY_READ | root.view, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        DWORD maxName = 0;
        DWORD maxData = 0;
        if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, &maxName, &maxData, nullptr, nullptr)
            != ERROR_SUCCESS) {
            ReportPartial(L"Approved shell extension sizing failed");
            RegCloseKey(hKey);
            continue;
        }
        std::vector<WCHAR> nameBuffer(maxName + 1);
        std::vector<BYTE> dataBuffer(maxData ? maxData : 1);

        for (DWORD index = 0;; index++) {
            RegistryValueInfo value;
            LSTATUS status = QueryRegistryValue(hKey, index, nameBuffer,
                dataBuffer, value);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) {
                ReportPartial(L"Approved shell extension enumeration failed: "
                    + std::to_wstring(status));
                break;
            }
            if (!LooksLikeGuid(value.name)) continue;

            std::wstring valueData;
            if (value.type == REG_SZ || value.type == REG_EXPAND_SZ) {
                size_t chars = value.dataBytes / sizeof(WCHAR);
                const auto* data = reinterpret_cast<const WCHAR*>(dataBuffer.data());
                size_t length = 0;
                while (length < chars && data[length] != L'\0') length++;
                valueData.assign(data, length);
            }

            std::wstring clsid = value.name;
            std::wstring source;
            std::wstring ownerPath = ResolveClsidServerPath(clsid, &source);
            std::wstring dedup = ToLower(L"approved|" + clsid + L"|" + ownerPath);
            if (seen.insert(dedup).second) {
                AddEntry(results, EntryType::Shell, L"Approved:" + clsid,
                    L"Approved shell extension | CLSID=" + clsid
                    + L" | " + source + L" | Name=" + valueData,
                    ownerPath);
            }
        }

        RegCloseKey(hKey);
    }

    return results;
}

EntryPointList EnumerateAppxActivations() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const RegistryRoot roots[] = {
        { HKEY_CURRENT_USER, L"Software\\Classes\\ActivatableClasses\\Package", L"HKCU", 0 },
        { HKEY_LOCAL_MACHINE, L"Software\\Classes\\ActivatableClasses\\Package", L"HKLM 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Classes\\ActivatableClasses\\Package", L"HKLM 32-bit", KEY_WOW64_32KEY },
    };

    for (const auto& root : roots) {
        for (const auto& packageName : EnumSubKeys(root.root, root.path, root.view)) {
            std::wstring packagePath = root.path + L"\\" + packageName;
            std::wstring serverRoot = packagePath + L"\\Server";
            for (const auto& serverName : EnumSubKeys(root.root, serverRoot, root.view)) {
                std::wstring keyPath = serverRoot + L"\\" + serverName;
                std::wstring path = ReadRegStringValue(root.root, keyPath, L"ExePath", root.view);
                std::wstring kind = L"ExeServer";
                if (path.empty()) {
                    path = ReadRegStringValue(root.root, keyPath, L"DllPath", root.view);
                    kind = L"DllServer";
                }
                if (path.empty()) continue;

                std::wstring ownerPath = ExtractExecutablePath(path);
                std::wstring dedup = ToLower(packageName + L"|" + serverName + L"|" + ownerPath);
                if (seen.insert(dedup).second) {
                    AddEntry(results, EntryType::AppX,
                        packageName + L"\\" + serverName,
                        L"AppX/WinRT " + kind + L" | Package=" + packageName
                        + L" | Path=" + path + L" | " + root.label,
                        ownerPath);
                }
            }

            std::wstring classRoot = packagePath + L"\\ActivatableClassId";
            for (const auto& className : EnumSubKeys(root.root, classRoot, root.view)) {
                std::wstring keyPath = classRoot + L"\\" + className;
                std::wstring server = ReadRegStringValue(root.root, keyPath, L"Server", root.view);
                if (server.empty()) continue;
                std::wstring serverPath = serverRoot + L"\\" + server;
                std::wstring path = ReadRegStringValue(root.root, serverPath, L"ExePath", root.view);
                if (path.empty()) path = ReadRegStringValue(root.root, serverPath, L"DllPath", root.view);
                if (path.empty()) continue;

                std::wstring ownerPath = ExtractExecutablePath(path);
                std::wstring dedup = ToLower(packageName + L"|" + className + L"|" + ownerPath);
                if (seen.insert(dedup).second) {
                    AddEntry(results, EntryType::AppX,
                        className,
                        L"WinRT class | Package=" + packageName
                        + L" | Server=" + server + L" | Path=" + path + L" | " + root.label,
                        ownerPath);
                }
            }
        }
    }

    return results;
}

EntryPointList EnumerateEtwProviders() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const std::wstring rootPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers";
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };

    for (auto view : views) {
        for (const auto& providerGuid : EnumSubKeys(HKEY_LOCAL_MACHINE, rootPath, view)) {
            std::wstring keyPath = rootPath + L"\\" + providerGuid;
            std::wstring providerName = ReadRegStringValue(HKEY_LOCAL_MACHINE, keyPath, nullptr, view);
            std::wstring resource = ReadRegStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ResourceFileName", view);
            std::wstring message = ReadRegStringValue(HKEY_LOCAL_MACHINE, keyPath, L"MessageFileName", view);
            std::wstring parameter = ReadRegStringValue(HKEY_LOCAL_MACHINE, keyPath, L"ParameterFileName", view);

            std::wstring ownerPath = !resource.empty() ? resource : (!message.empty() ? message : parameter);
            if (ownerPath.empty()) continue;
            ownerPath = ExtractExecutablePath(ownerPath);

            std::wstring details = L"ETW provider";
            if (!providerName.empty()) details += L" | Name=" + providerName;
            if (!resource.empty()) details += L" | Resource=" + resource;
            if (!message.empty()) details += L" | Message=" + message;
            if (!parameter.empty()) details += L" | Parameter=" + parameter;

            std::wstring dedup = ToLower(providerGuid + L"|" + ownerPath);
            if (seen.insert(dedup).second) {
                AddEntry(results, EntryType::ETW, providerGuid, details, ownerPath);
            }
        }
    }

    return results;
}

EntryPointList EnumerateCryptoProviders() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const RegistryRoot roots[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider", L"CAPI Provider 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider", L"CAPI Provider 32-bit", KEY_WOW64_32KEY },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers", L"CNG Provider", 0 },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002", L"SChannel Crypto Function", 0 },
    };

    for (const auto& root : roots) {
        for (const auto& providerName : EnumSubKeys(root.root, root.path, root.view)) {
            std::wstring keyPath = root.path + L"\\" + providerName;
            std::wstring image = ReadRegStringValue(root.root, keyPath, L"Image Path", root.view);
            if (image.empty()) image = ReadRegStringValue(root.root, keyPath, L"ImagePath", root.view);
            if (image.empty()) image = ReadRegStringValue(root.root, keyPath, L"Dll", root.view);
            if (image.empty()) image = ReadRegStringValue(root.root, keyPath, L"Function", root.view);
            if (image.empty()) continue;

            std::wstring ownerPath = ExtractExecutablePath(image);
            std::wstring dedup = ToLower(root.label + L"|" + providerName + L"|" + ownerPath);
            if (seen.insert(dedup).second) {
                AddEntry(results, EntryType::Crypto, providerName,
                    root.label + L" | Path=" + image,
                    ownerPath);
            }
        }
    }

    return results;
}
