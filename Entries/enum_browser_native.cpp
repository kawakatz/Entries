#include "enum_browser_native.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"

#include <filesystem>
#include <fstream>
#include <set>

static void AddEntry(EntryPointList& results, const std::wstring& name,
    const std::wstring& details, const std::wstring& ownerPath)
{
    EntryPoint ep;
    ep.type = EntryType::BrowserNative;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<registry>" : ownerPath;
    results.push_back(std::move(ep));
}

static int HexDigit(wchar_t value) {
    if (value >= L'0' && value <= L'9') return value - L'0';
    if (value >= L'a' && value <= L'f') return value - L'a' + 10;
    if (value >= L'A' && value <= L'F') return value - L'A' + 10;
    return -1;
}

static std::wstring ExtractJsonStringValue(const std::wstring& text,
    const std::wstring& key)
{
    std::wstring token = L"\"" + key + L"\"";
    size_t cursor = 0;
    while ((cursor = text.find(token, cursor)) != std::wstring::npos) {
        cursor += token.size();
        while (cursor < text.size() && iswspace(text[cursor])) cursor++;
        if (cursor < text.size() && text[cursor] == L':') break;
    }
    if (cursor == std::wstring::npos) return L"";
    cursor++;
    while (cursor < text.size() && iswspace(text[cursor])) cursor++;
    if (cursor == text.size() || text[cursor++] != L'"') return L"";

    std::wstring result;
    while (cursor < text.size()) {
        wchar_t value = text[cursor++];
        if (value == L'"') return result;
        if (value != L'\\') {
            result += value;
            continue;
        }
        if (cursor == text.size()) return L"";
        value = text[cursor++];
        if (value == L'"' || value == L'\\' || value == L'/') result += value;
        else if (value == L'b') result += L'\b';
        else if (value == L'f') result += L'\f';
        else if (value == L'n') result += L'\n';
        else if (value == L'r') result += L'\r';
        else if (value == L't') result += L'\t';
        else if (value == L'u' && cursor + 4 <= text.size()) {
            wchar_t decoded = 0;
            for (int i = 0; i < 4; i++) {
                int digit = HexDigit(text[cursor++]);
                if (digit < 0) return L"";
                decoded = static_cast<wchar_t>((decoded << 4) | digit);
            }
            result += decoded;
        }
        else {
            return L"";
        }
    }
    return L"";
}

static std::wstring ReadManifest(const std::wstring& path) {
    std::ifstream file(std::filesystem::path(path),
        std::ios::binary | std::ios::ate);
    if (!file) {
        ReportPartial(L"Native messaging manifest read failed: " + path);
        return L"";
    }
    std::streamoff length = file.tellg();
    if (length < 0 || length > 1024 * 1024) {
        ReportPartial(L"Native messaging manifest size is invalid: " + path);
        return L"";
    }
    std::string bytes(static_cast<size_t>(length), '\0');
    file.seekg(0);
    if (!bytes.empty()
        && !file.read(bytes.data(), static_cast<std::streamsize>(length))) {
        ReportPartial(L"Native messaging manifest read failed: " + path);
        return L"";
    }
    if (bytes.empty()) {
        ReportPartial(L"Native messaging manifest is empty: " + path);
        return L"";
    }

    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (chars == 0) {
        ReportPartial(L"Native messaging manifest is not UTF-8: " + path);
        return L"";
    }
    std::wstring text(chars, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
        static_cast<int>(bytes.size()), text.data(), chars);
    return text;
}

static std::wstring ResolveManifestRelativePath(const std::wstring& manifestPath,
    const std::wstring& nativePath)
{
    if (nativePath.empty()) return nativePath;
    if (nativePath.size() >= 2 && nativePath[1] == L':') return nativePath;
    if (StartsWithIcase(nativePath, L"\\\\")) return nativePath;

    size_t slash = manifestPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return nativePath;
    return manifestPath.substr(0, slash + 1) + nativePath;
}

EntryPointList EnumerateBrowserNativeMessagingHosts() {
    EntryPointList results;
    std::set<std::wstring> seen;

    const RegistryRoot roots[] = {
        { HKEY_CURRENT_USER, L"Software\\Google\\Chrome\\NativeMessagingHosts", L"Chrome HKCU", 0 },
        { HKEY_LOCAL_MACHINE, L"Software\\Google\\Chrome\\NativeMessagingHosts", L"Chrome HKLM 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Google\\Chrome\\NativeMessagingHosts", L"Chrome HKLM 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Edge\\NativeMessagingHosts", L"Edge HKCU", 0 },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Edge\\NativeMessagingHosts", L"Edge HKLM 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Edge\\NativeMessagingHosts", L"Edge HKLM 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"Software\\Chromium\\NativeMessagingHosts", L"Chromium HKCU", 0 },
        { HKEY_LOCAL_MACHINE, L"Software\\Chromium\\NativeMessagingHosts", L"Chromium HKLM 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Chromium\\NativeMessagingHosts", L"Chromium HKLM 32-bit", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER, L"Software\\Mozilla\\NativeMessagingHosts", L"Mozilla HKCU", 0 },
        { HKEY_LOCAL_MACHINE, L"Software\\Mozilla\\NativeMessagingHosts", L"Mozilla HKLM 64-bit", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Mozilla\\NativeMessagingHosts", L"Mozilla HKLM 32-bit", KEY_WOW64_32KEY },
    };

    for (const auto& root : roots) {
        for (const auto& hostName : EnumSubKeys(root.root, root.path, root.view)) {
            std::wstring keyPath = root.path + L"\\" + hostName;
            std::wstring manifestPath = ReadRegStringValue(root.root, keyPath,
                nullptr, root.view);
            if (manifestPath.empty()) continue;

            std::wstring manifestText = ReadManifest(manifestPath);
            std::wstring nativePath = ExtractJsonStringValue(manifestText, L"path");
            if (!manifestText.empty() && nativePath.empty()) {
                ReportPartial(L"Native messaging manifest path is missing: "
                    + manifestPath);
            }
            nativePath = ExpandEnvironmentPath(nativePath);
            nativePath = ResolveManifestRelativePath(manifestPath, nativePath);
            std::wstring ownerPath = nativePath.empty()
                ? manifestPath
                : ExtractExecutablePath(nativePath);

            std::wstring details = root.label + L" | Manifest=" + manifestPath;
            if (!nativePath.empty()) details += L" | NativePath=" + nativePath;

            std::wstring dedup = ToLower(hostName + L"|" + manifestPath
                + L"|" + ownerPath);
            if (seen.insert(dedup).second) {
                AddEntry(results, hostName, details, ownerPath);
            }
        }
    }

    return results;
}
