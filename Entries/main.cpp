#include "common.h"
#include "diagnostics.h"
#include "nt_api.h"
#include "nt_objects.h"
#include "process_utils.h"
#include "enum_tcp_udp.h"
#include "enum_named_pipes.h"
#include "enum_shared_memory.h"
#include "enum_alpc.h"
#include "enum_rpc.h"
#include "enum_http.h"
#include "enum_services.h"
#include "enum_mailslots.h"
#include "enum_com.h"
#include "enum_drivers.h"
#include "enum_tasks.h"
#include "enum_registry_surfaces.h"
#include "enum_browser_native.h"
#include "enum_filter_drivers.h"
#include "enum_firewall.h"
#include "enum_device_interfaces.h"
#include "enum_wmi.h"
#include "enum_windows.h"
#include "enum_persistence.h"
#include "enum_kernel_objects.h"

#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <io.h>
#include <iterator>
#include <locale>
#include <regex>
#include <set>
#include <sstream>

struct Options {
    std::wstring pathPattern;
    std::set<EntryType> typeFilter;
    bool jsonOutput = false;
    bool verbose = false;
    bool showHelp = false;
};

static void PrintUsage() {
    std::wcout
        << L"Entries - Windows Attack Surface Entry Point Enumerator\n"
        << L"\n"
        << L"Usage: Entries.exe --path <regex> [options]\n"
        << L"\n"
        << L"Arguments:\n"
        << L"  --path <regex>    Regex to match process image paths (required)\n"
        << L"                    Examples: \"C:\\\\Program Files\\\\Google\\\\.*\"\n"
        << L"                             \".*\\\\svchost\\.exe\"\n"
        << L"                             \".*\" (match all)\n"
        << L"\n"
        << L"  --type <types>    Comma-separated list of entry types to scan\n"
        << L"                    Types: tcp,udp,pipe,shm,alpc,rpc,http,svc,mail,com,drv,task\n"
        << L"                           wmi,shell,assoc,devif,browser,fw,appx,etw,win,filter,crypto\n"
        << L"                           persist,kobj\n"
        << L"                    Default: all types\n"
        << L"\n"
        << L"  --json            Output results as JSON\n"
        << L"  --verbose         Show detailed progress messages\n"
        << L"  --help            Show this help message\n"
        << L"\n"
        << L"Note: Must be run as Administrator for full enumeration.\n"
        << std::endl;
}

static EntryType ParseTypeName(const std::wstring& name) {
    if (name == L"tcp")  return EntryType::TCP;
    if (name == L"udp")  return EntryType::UDP;
    if (name == L"pipe") return EntryType::NamedPipe;
    if (name == L"shm")  return EntryType::SharedMemory;
    if (name == L"alpc") return EntryType::ALPC;
    if (name == L"rpc")  return EntryType::RPC;
    if (name == L"http") return EntryType::HTTP;
    if (name == L"svc")  return EntryType::Service;
    if (name == L"mail") return EntryType::Mailslot;
    if (name == L"com")  return EntryType::COM;
    if (name == L"drv" || name == L"driver") return EntryType::Driver;
    if (name == L"task" || name == L"tasks") return EntryType::Task;
    if (name == L"wmi") return EntryType::WMI;
    if (name == L"shell") return EntryType::Shell;
    if (name == L"assoc" || name == L"handler") return EntryType::Assoc;
    if (name == L"devif" || name == L"device") return EntryType::DeviceInterface;
    if (name == L"browser" || name == L"native") return EntryType::BrowserNative;
    if (name == L"fw" || name == L"firewall") return EntryType::Firewall;
    if (name == L"appx" || name == L"winrt") return EntryType::AppX;
    if (name == L"etw") return EntryType::ETW;
    if (name == L"win" || name == L"window") return EntryType::Window;
    if (name == L"filter" || name == L"minifilter") return EntryType::Filter;
    if (name == L"crypto" || name == L"csp" || name == L"ksp") return EntryType::Crypto;
    if (name == L"persist" || name == L"persistence") return EntryType::Persistence;
    if (name == L"kobj" || name == L"kernel") return EntryType::KernelObject;
    return (EntryType)-1;
}

static bool ParseTypeFilter(const std::wstring& typeStr,
    std::set<EntryType>& filter,
    std::wstring& error)
{
    std::wstringstream ss(typeStr);
    std::wstring token;
    while (std::getline(ss, token, L',')) {
        token = TrimWhitespace(token);
        std::transform(token.begin(), token.end(), token.begin(), ::towlower);

        EntryType t = ParseTypeName(token);
        if ((int)t == -1) {
            error = L"Unknown type: " + (token.empty() ? L"<empty>" : token);
            return false;
        }
        filter.insert(t);
    }
    if (filter.empty()) {
        error = L"--type requires at least one type";
        return false;
    }
    return true;
}

static bool ParseArgs(int argc, wchar_t* argv[], Options& opts, std::wstring& error) {
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        if (arg == L"--path" || arg == L"-path" || arg == L"-p") {
            if (i + 1 == argc) {
                error = arg + L" requires a value";
                return false;
            }
            opts.pathPattern = argv[++i];
        }
        else if (arg == L"--type" || arg == L"-type" || arg == L"-t") {
            if (i + 1 == argc) {
                error = arg + L" requires a value";
                return false;
            }
            opts.typeFilter.clear();
            if (!ParseTypeFilter(argv[++i], opts.typeFilter, error)) return false;
        }
        else if (arg == L"--json" || arg == L"-json") {
            opts.jsonOutput = true;
        }
        else if (arg == L"--verbose" || arg == L"-verbose" || arg == L"-v") {
            opts.verbose = true;
        }
        else if (arg == L"--help" || arg == L"-help" || arg == L"-h" || arg == L"/?") {
            opts.showHelp = true;
        }
        else {
            error = L"Unknown option: " + arg;
            return false;
        }
    }
    return true;
}

static void PrintStatus(const Options& opts, const std::wstring& message) {
    if (opts.verbose) std::wcerr << L"[*] " << message << std::endl;
}

static std::wstring EscapeJson(const std::wstring& s) {
    std::wstring result;
    result.reserve(s.size());
    for (wchar_t c : s) {
        switch (c) {
        case L'"':  result += L"\\\""; break;
        case L'\\': result += L"\\\\"; break;
        case L'\n': result += L"\\n"; break;
        case L'\r': result += L"\\r"; break;
        case L'\t': result += L"\\t"; break;
        default:
            if (c < 0x20) {
                std::wstringstream ss;
                ss << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0') << (int)c;
                result += ss.str();
            }
            else {
                result += c;
            }
            break;
        }
    }
    return result;
}

static void PrintResultsTable(const EntryPointList& results) {
    for (auto& ep : results) {
        std::wcout
            << L"[" << std::setw(4) << std::left << EntryTypeName(ep.type) << L"] "
            << std::setw(50) << std::left << ep.name << L" "
            << L"PID:" << std::setw(6) << std::left << ep.ownerPid << L" "
            << std::setw(30) << std::left << ep.ownerPrivilege << L" "
            << ep.ownerPath;
        if (!ep.details.empty()) {
            std::wcout << L"  (" << ep.details << L")";
        }
        std::wcout << std::endl;
    }
}

static void PrintResultsJson(const EntryPointList& results) {
    std::wcout << L"[\n";
    for (size_t i = 0; i < results.size(); i++) {
        auto& ep = results[i];
        std::wcout << L"  {\n"
            << L"    \"type\": \"" << EscapeJson(EntryTypeName(ep.type)) << L"\",\n"
            << L"    \"name\": \"" << EscapeJson(ep.name) << L"\",\n"
            << L"    \"details\": \"" << EscapeJson(ep.details) << L"\",\n"
            << L"    \"pid\": " << ep.ownerPid << L",\n"
            << L"    \"privilege\": \"" << EscapeJson(ep.ownerPrivilege) << L"\",\n"
            << L"    \"path\": \"" << EscapeJson(ep.ownerPath) << L"\"\n"
            << L"  }";
        if (i + 1 < results.size()) std::wcout << L",";
        std::wcout << L"\n";
    }
    std::wcout << L"]\n";
}

int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, "");
    SetConsoleOutputCP(CP_UTF8);
    if (_setmode(_fileno(stdout), _O_U8TEXT) == -1
        || _setmode(_fileno(stderr), _O_U8TEXT) == -1) {
        return 1;
    }
    if (argc == 2 && wcscmp(argv[1], L"--native-query-worker") == 0) {
        return RunNativeQueryWorker();
    }

    Options opts;
    std::wstring argumentError;
    if (!ParseArgs(argc, argv, opts, argumentError)) {
        std::wcerr << L"[!] " << argumentError << std::endl;
        return 1;
    }

    if (opts.showHelp || opts.pathPattern.empty()) {
        PrintUsage();
        return opts.showHelp ? 0 : 1;
    }

    std::wregex pathRegex;
    try {
        pathRegex = std::wregex(opts.pathPattern, std::regex_constants::icase);
    }
    catch (const std::regex_error& e) {
        std::wcerr << L"[!] Invalid regex pattern: " << opts.pathPattern << std::endl;
        std::wcerr << L"    Error: " << e.what() << std::endl;
        return 1;
    }

    auto shouldScan = [&](EntryType t) -> bool {
        return opts.typeFilter.empty() || opts.typeFilter.count(t);
    };

    PrintStatus(opts, L"Entries - Windows Attack Surface Enumerator");
    PrintStatus(opts, L"Path filter: " + opts.pathPattern);

    bool needNtApi = shouldScan(EntryType::NamedPipe)
        || shouldScan(EntryType::SharedMemory)
        || shouldScan(EntryType::ALPC)
        || shouldScan(EntryType::RPC)
        || shouldScan(EntryType::Mailslot)
        || shouldScan(EntryType::Driver)
        || shouldScan(EntryType::KernelObject);
    if (needNtApi) {
        PrintStatus(opts, L"Initializing NT APIs...");
        if (!g_NtApi.Initialize()) {
            ReportPartial(L"NT API initialization failed; some enumerations will be limited");
        }
    }

    bool needProcessCache = shouldScan(EntryType::TCP)
        || shouldScan(EntryType::UDP)
        || shouldScan(EntryType::NamedPipe)
        || shouldScan(EntryType::SharedMemory)
        || shouldScan(EntryType::ALPC)
        || shouldScan(EntryType::RPC)
        || shouldScan(EntryType::Service)
        || shouldScan(EntryType::Mailslot)
        || shouldScan(EntryType::Window);
    bool needDebugPrivilege = needProcessCache || shouldScan(EntryType::Driver);
    if (needDebugPrivilege) {
        PrintStatus(opts, L"Enabling SeDebugPrivilege...");
        if (!EnableDebugPrivilege()) {
            ReportPartial(L"Could not enable SeDebugPrivilege; run as Administrator for full results");
        }
    }

    if (needProcessCache) {
        PrintStatus(opts, L"Building process path cache...");
        g_ProcessCache.Refresh();
    }

    std::vector<std::wstring> handleTypes;
    if (shouldScan(EntryType::NamedPipe) || shouldScan(EntryType::Mailslot)) {
        handleTypes.push_back(L"File");
    }
    if (shouldScan(EntryType::SharedMemory)) {
        handleTypes.push_back(L"Section");
    }
    if (shouldScan(EntryType::ALPC) || shouldScan(EntryType::RPC)) {
        handleTypes.push_back(L"ALPC Port");
    }

    if (!handleTypes.empty()) {
        PrintStatus(opts, L"Building system handle table...");
        if (!g_HandleTable.Build(handleTypes)) {
            ReportPartial(L"Handle table build failed; some PID resolutions will be unavailable");
        }
    }

    EntryPointList allResults;

    struct EnumTask {
        EntryType type;
        const wchar_t* label;
        EntryPointList (*enumerate)();
    };

    EnumTask tasks[] = {
        { EntryType::TCP,          L"TCP listeners",     EnumerateTcpListeners },
        { EntryType::UDP,          L"UDP listeners",     EnumerateUdpListeners },
        { EntryType::NamedPipe,    L"Named pipes",       EnumerateNamedPipes },
        { EntryType::SharedMemory, L"Shared memory",     EnumerateSharedMemory },
        { EntryType::ALPC,         L"ALPC ports",        EnumerateAlpcPorts },
        { EntryType::RPC,          L"RPC endpoints",     EnumerateRpcEndpoints },
        { EntryType::HTTP,         L"HTTP configuration", EnumerateHttpConfiguration },
        { EntryType::Service,      L"Windows services",  EnumerateServices },
        { EntryType::Mailslot,     L"Mailslots",         EnumerateMailslots },
        { EntryType::COM,          L"COM servers",       EnumerateComServers },
        { EntryType::Driver,       L"Kernel drivers",    EnumerateDriverSurfaces },
        { EntryType::Task,         L"Scheduled tasks",   EnumerateScheduledTasks },
        { EntryType::WMI,          L"WMI surfaces",      EnumerateWmiSurfaces },
        { EntryType::Shell,        L"Shell extensions",  EnumerateShellExtensions },
        { EntryType::Assoc,        L"File/protocol handlers", EnumerateFileProtocolHandlers },
        { EntryType::DeviceInterface, L"Device interfaces", EnumerateDeviceInterfaces },
        { EntryType::BrowserNative, L"Browser native messaging hosts", EnumerateBrowserNativeMessagingHosts },
        { EntryType::Firewall,     L"Firewall rules",    EnumerateFirewallRules },
        { EntryType::AppX,         L"AppX/WinRT activations", EnumerateAppxActivations },
        { EntryType::ETW,          L"ETW providers",     EnumerateEtwProviders },
        { EntryType::Window,       L"Windows/UI endpoints", EnumerateWindowSurfaces },
        { EntryType::Filter,       L"Filter drivers",    EnumerateFilterDrivers },
        { EntryType::Crypto,       L"Crypto providers",  EnumerateCryptoProviders },
        { EntryType::Persistence,  L"Persistence registry surfaces", EnumeratePersistenceSurfaces },
        { EntryType::KernelObject, L"Named kernel primitives",       EnumerateKernelObjects },
    };

    for (auto& task : tasks) {
        if (!shouldScan(task.type)) continue;

        PrintStatus(opts, L"Enumerating " + std::wstring(task.label) + L"...");
        auto entries = task.enumerate();
        PrintStatus(opts, L"Found " + std::to_wstring(entries.size()) + L" entries");

        allResults.insert(allResults.end(),
            std::make_move_iterator(entries.begin()),
            std::make_move_iterator(entries.end()));
    }

    EntryPointList filtered;
    for (auto& ep : allResults) {
        if (MatchesPath(ep.ownerPath, pathRegex)) {
            if (ep.ownerPid != 0) {
                ep.ownerPrivilege = g_ProcessCache.GetPrivilege(ep.ownerPid);
            }

            filtered.push_back(std::move(ep));
        }
    }

    PrintStatus(opts, L"Results: " + std::to_wstring(filtered.size())
        + L" matching entry points from " + std::to_wstring(allResults.size()));

    if (opts.jsonOutput) {
        PrintResultsJson(filtered);
    }
    else {
        PrintResultsTable(filtered);
    }
    std::wcout.flush();
    if (!std::wcout) {
        std::wcerr << L"[!] Failed to write output" << std::endl;
        return 1;
    }

    return IsPartial() ? 2 : 0;
}
