#include "enum_windows.h"
#include "diagnostics.h"
#include "process_utils.h"
#include <sstream>

struct WindowEnumContext {
    EntryPointList* results;
    bool messageOnly;
};

static BOOL CALLBACK EnumWindowProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<WindowEnumContext*>(lParam);
    if (!ctx || !ctx->results) return TRUE;

    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return TRUE;

    WCHAR className[256] = {};
    GetClassNameW(hwnd, className, _countof(className));

    EntryPoint ep;
    ep.type = EntryType::Window;
    std::wstringstream name;
    name << (ctx->messageOnly ? L"MessageWindow" : L"Window")
        << L":HWND=0x" << std::hex << reinterpret_cast<ULONG_PTR>(hwnd) << std::dec;
    ep.name = name.str();
    ep.details = std::wstring(ctx->messageOnly ? L"Message-only window" : L"Top-level window")
        + L" | TID=" + std::to_wstring(tid)
        + L" | Class=" + className;
    ep.details += IsWindowVisible(hwnd) ? L" | Visible=true" : L" | Visible=false";
    ep.ownerPid = pid;
    ep.ownerPath = g_ProcessCache.GetPath(pid);
    ctx->results->push_back(std::move(ep));
    return TRUE;
}

static void EnumerateMessageOnlyWindows(EntryPointList& results) {
    WindowEnumContext ctx = { &results, true };
    HWND hwnd = nullptr;
    while ((hwnd = FindWindowExW(HWND_MESSAGE, hwnd, nullptr, nullptr)) != nullptr) {
        EnumWindowProc(hwnd, reinterpret_cast<LPARAM>(&ctx));
    }
}

EntryPointList EnumerateWindowSurfaces() {
    EntryPointList results;
    WindowEnumContext ctx = { &results, false };
    if (!EnumWindows(EnumWindowProc, reinterpret_cast<LPARAM>(&ctx))) {
        ReportPartial(L"Top-level window enumeration failed");
    }
    EnumerateMessageOnlyWindows(results);
    return results;
}
