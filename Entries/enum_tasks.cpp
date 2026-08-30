#include "enum_tasks.h"
#include "com_utils.h"
#include "diagnostics.h"
#include "process_utils.h"
#include "registry_utils.h"
#include "security_utils.h"

#include <taskschd.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static std::wstring BoolName(VARIANT_BOOL value) {
    return value == VARIANT_TRUE ? L"true" : L"false";
}

static std::wstring TaskStateName(TASK_STATE state) {
    switch (state) {
    case TASK_STATE_DISABLED: return L"Disabled";
    case TASK_STATE_QUEUED:   return L"Queued";
    case TASK_STATE_READY:    return L"Ready";
    case TASK_STATE_RUNNING:  return L"Running";
    default:                  return L"Unknown";
    }
}

static std::wstring RunLevelName(TASK_RUNLEVEL_TYPE runLevel) {
    switch (runLevel) {
    case TASK_RUNLEVEL_LUA:     return L"LUA";
    case TASK_RUNLEVEL_HIGHEST: return L"Highest";
    default:                    return L"Unknown";
    }
}

static std::wstring LogonTypeName(TASK_LOGON_TYPE logonType) {
    switch (logonType) {
    case TASK_LOGON_NONE:                           return L"None";
    case TASK_LOGON_PASSWORD:                       return L"Password";
    case TASK_LOGON_S4U:                            return L"S4U";
    case TASK_LOGON_INTERACTIVE_TOKEN:              return L"Interactive";
    case TASK_LOGON_GROUP:                          return L"Group";
    case TASK_LOGON_SERVICE_ACCOUNT:                return L"ServiceAccount";
    case TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD:  return L"InteractiveOrPassword";
    default:                                        return L"Unknown";
    }
}

static std::wstring GetTaskSecuritySummary(IRegisteredTask* task) {
    BSTR sddl = nullptr;
    HRESULT hr = task->GetSecurityDescriptor(DACL_SECURITY_INFORMATION, &sddl);
    if (FAILED(hr)) {
        ReportPartial(L"Task security descriptor query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        return L"";
    }

    std::wstring summary = SecurityDescriptorSddlDaclSummary(BstrToWString(sddl), 6);
    FreeBstr(sddl);
    return summary;
}

static std::wstring GetPrincipalDetails(ITaskDefinition* definition) {
    IPrincipal* principal = nullptr;
    HRESULT hr = definition ? definition->get_Principal(&principal) : E_POINTER;
    if (FAILED(hr) || !principal) {
        ReportPartial(L"Task principal query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        return L"";
    }

    std::wstring details;

    BSTR userId = nullptr;
    if (SUCCEEDED(principal->get_UserId(&userId)) && userId) {
        details += L" | User=" + BstrToWString(userId);
    }
    FreeBstr(userId);

    TASK_RUNLEVEL_TYPE runLevel = TASK_RUNLEVEL_LUA;
    if (SUCCEEDED(principal->get_RunLevel(&runLevel))) {
        details += L" | RunLevel=" + RunLevelName(runLevel);
    }

    TASK_LOGON_TYPE logonType = TASK_LOGON_NONE;
    if (SUCCEEDED(principal->get_LogonType(&logonType))) {
        details += L" | Logon=" + LogonTypeName(logonType);
    }

    SafeRelease(principal);
    return details;
}

static std::wstring GetTaskBaseDetails(IRegisteredTask* task,
    ITaskDefinition* definition)
{
    VARIANT_BOOL enabled = VARIANT_FALSE;
    HRESULT hr = task->get_Enabled(&enabled);
    if (FAILED(hr)) {
        ReportPartial(L"Task enabled-state query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }

    TASK_STATE state = TASK_STATE_UNKNOWN;
    hr = task->get_State(&state);
    if (FAILED(hr)) {
        ReportPartial(L"Task runtime-state query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }

    std::wstring details = L"Enabled=" + BoolName(enabled)
        + L" | State=" + TaskStateName(state);

    details += GetPrincipalDetails(definition);

    std::wstring dacl = GetTaskSecuritySummary(task);
    if (!dacl.empty()) {
        details += L" | DACL: " + dacl;
    }

    return details;
}

static void AddEntry(EntryPointList& results,
    const std::wstring& name,
    const std::wstring& details,
    const std::wstring& ownerPath)
{
    EntryPoint ep;
    ep.type = EntryType::Task;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<task>" : ownerPath;
    results.push_back(std::move(ep));
}

static void EnumerateTaskActions(IRegisteredTask* task,
    const std::wstring& taskPath,
    EntryPointList& results)
{
    ITaskDefinition* definition = nullptr;
    HRESULT hr = task->get_Definition(&definition);
    if (FAILED(hr) || !definition) {
        ReportPartial(L"Task definition query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        AddEntry(results, taskPath, L"<definition unavailable>", L"<task>");
        return;
    }

    std::wstring baseDetails = GetTaskBaseDetails(task, definition);

    IActionCollection* actions = nullptr;
    hr = definition->get_Actions(&actions);
    if (FAILED(hr) || !actions) {
        ReportPartial(L"Task action collection query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        AddEntry(results, taskPath, baseDetails + L" | <actions unavailable>", L"<task>");
        SafeRelease(definition);
        return;
    }

    LONG actionCount = 0;
    hr = actions->get_Count(&actionCount);
    if (FAILED(hr)) {
        ReportPartial(L"Task action count query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        AddEntry(results, taskPath, baseDetails + L" | <actions unavailable>", L"<task>");
        SafeRelease(actions);
        SafeRelease(definition);
        return;
    }
    if (actionCount == 0) {
        AddEntry(results, taskPath, baseDetails + L" | No actions", L"<task>");
        SafeRelease(actions);
        SafeRelease(definition);
        return;
    }

    for (LONG i = 1; i <= actionCount; i++) {
        IAction* action = nullptr;
        hr = actions->get_Item(i, &action);
        if (FAILED(hr) || !action) {
            ReportPartial(L"Task action query failed: "
                + HexCode(static_cast<unsigned long>(hr)));
            AddEntry(results, taskPath, baseDetails + L" | <action unavailable>",
                L"<task-action>");
            continue;
        }

        TASK_ACTION_TYPE actionType = TASK_ACTION_EXEC;
        hr = action->get_Type(&actionType);
        if (FAILED(hr)) {
            ReportPartial(L"Task action type query failed: "
                + HexCode(static_cast<unsigned long>(hr)));
            AddEntry(results, taskPath, baseDetails + L" | <action type unavailable>",
                L"<task-action>");
            SafeRelease(action);
            continue;
        }

        if (actionType == TASK_ACTION_EXEC) {
            IExecAction* exec = nullptr;
            if (SUCCEEDED(action->QueryInterface(IID_IExecAction,
                reinterpret_cast<void**>(&exec))) && exec) {
                BSTR path = nullptr;
                BSTR args = nullptr;
                BSTR workingDirectory = nullptr;
                hr = exec->get_Path(&path);
                if (FAILED(hr)) {
                    ReportPartial(L"Task executable path query failed: "
                        + HexCode(static_cast<unsigned long>(hr)));
                }
                exec->get_Arguments(&args);
                exec->get_WorkingDirectory(&workingDirectory);

                std::wstring pathText = BstrToWString(path);
                std::wstring argsText = BstrToWString(args);
                std::wstring details = baseDetails + L" | Exec=" + pathText;
                if (!argsText.empty()) details += L" | Args=" + argsText;
                if (workingDirectory) {
                    std::wstring wd = BstrToWString(workingDirectory);
                    if (!wd.empty()) details += L" | Cwd=" + wd;
                }

                std::wstring ownerPath = ExtractExecutablePath(pathText);
                if (ownerPath.empty()) ownerPath = pathText;
                AddEntry(results, taskPath, details, ownerPath);

                FreeBstr(path);
                FreeBstr(args);
                FreeBstr(workingDirectory);
                SafeRelease(exec);
            }
            else {
                ReportPartial(L"Task executable action query failed");
                AddEntry(results, taskPath, baseDetails + L" | <exec action unavailable>",
                    L"<task-action>");
            }
        }
        else if (actionType == TASK_ACTION_COM_HANDLER) {
            IComHandlerAction* comAction = nullptr;
            if (SUCCEEDED(action->QueryInterface(IID_IComHandlerAction,
                reinterpret_cast<void**>(&comAction))) && comAction) {
                BSTR clsid = nullptr;
                BSTR data = nullptr;
                hr = comAction->get_ClassId(&clsid);
                if (FAILED(hr)) {
                    ReportPartial(L"Task COM handler CLSID query failed: "
                        + HexCode(static_cast<unsigned long>(hr)));
                }
                comAction->get_Data(&data);

                std::wstring clsidText = BstrToWString(clsid);
                std::wstring details = baseDetails + L" | COMHandler=" + clsidText;
                std::wstring dataText = BstrToWString(data);
                if (!dataText.empty()) details += L" | Data=" + dataText;

                std::wstring ownerPath = ResolveClsidServerPath(clsidText);
                if (ownerPath.empty()) {
                    ownerPath = clsidText.empty()
                        ? L"<com-handler>"
                        : L"<com-handler:" + clsidText + L">";
                }
                AddEntry(results, taskPath, details, ownerPath);

                FreeBstr(clsid);
                FreeBstr(data);
                SafeRelease(comAction);
            }
            else {
                ReportPartial(L"Task COM handler action query failed");
                AddEntry(results, taskPath, baseDetails + L" | <COM action unavailable>",
                    L"<task-action>");
            }
        }
        else {
            AddEntry(results, taskPath,
                baseDetails + L" | ActionType=" + std::to_wstring((int)actionType),
                L"<task-action>");
        }

        SafeRelease(action);
    }

    SafeRelease(actions);
    SafeRelease(definition);
}

static void EnumerateFolder(ITaskFolder* folder, EntryPointList& results) {
    IRegisteredTaskCollection* tasks = nullptr;
    HRESULT hr = folder->GetTasks(TASK_ENUM_HIDDEN, &tasks);
    if (SUCCEEDED(hr) && tasks) {
        LONG count = 0;
        hr = tasks->get_Count(&count);
        if (FAILED(hr)) {
            ReportPartial(L"Task collection count query failed: "
                + HexCode(static_cast<unsigned long>(hr)));
            count = 0;
        }
        for (LONG i = 1; i <= count; i++) {
            VARIANT index;
            VariantInit(&index);
            V_VT(&index) = VT_I4;
            V_I4(&index) = i;

            IRegisteredTask* task = nullptr;
            hr = tasks->get_Item(index, &task);
            if (SUCCEEDED(hr) && task) {
                BSTR path = nullptr;
                hr = task->get_Path(&path);
                if (FAILED(hr)) {
                    ReportPartial(L"Task path query failed: "
                        + HexCode(static_cast<unsigned long>(hr)));
                }
                std::wstring taskPath = BstrToWString(path);
                EnumerateTaskActions(task,
                    taskPath.empty() ? L"<unknown-task>" : taskPath, results);
                FreeBstr(path);
                SafeRelease(task);
            }
            else {
                ReportPartial(L"Task collection item query failed: "
                    + HexCode(static_cast<unsigned long>(hr)));
            }

            VariantClear(&index);
        }
        SafeRelease(tasks);
    }
    else {
        ReportPartial(L"Task collection query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }

    ITaskFolderCollection* folders = nullptr;
    hr = folder->GetFolders(0, &folders);
    if (SUCCEEDED(hr) && folders) {
        LONG count = 0;
        hr = folders->get_Count(&count);
        if (FAILED(hr)) {
            ReportPartial(L"Task folder count query failed: "
                + HexCode(static_cast<unsigned long>(hr)));
            count = 0;
        }
        for (LONG i = 1; i <= count; i++) {
            VARIANT index;
            VariantInit(&index);
            V_VT(&index) = VT_I4;
            V_I4(&index) = i;

            ITaskFolder* child = nullptr;
            hr = folders->get_Item(index, &child);
            if (SUCCEEDED(hr) && child) {
                EnumerateFolder(child, results);
                SafeRelease(child);
            }
            else {
                ReportPartial(L"Task folder item query failed: "
                    + HexCode(static_cast<unsigned long>(hr)));
            }

            VariantClear(&index);
        }
        SafeRelease(folders);
    }
    else {
        ReportPartial(L"Task folder collection query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }
}

EntryPointList EnumerateScheduledTasks() {
    EntryPointList results;

    HRESULT coInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool shouldUninitialize = SUCCEEDED(coInit);
    if (FAILED(coInit) && coInit != RPC_E_CHANGED_MODE) {
        ReportPartial(L"Task Scheduler COM initialization failed: "
            + HexCode(static_cast<unsigned long>(coInit)));
        return results;
    }

    HRESULT securityStatus = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, 0, nullptr);
    if (FAILED(securityStatus) && securityStatus != RPC_E_TOO_LATE) {
        ReportPartial(L"Task Scheduler COM security initialization failed: "
            + HexCode(static_cast<unsigned long>(securityStatus)));
    }

    ITaskService* service = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
        CLSCTX_INPROC_SERVER, IID_ITaskService,
        reinterpret_cast<void**>(&service));
    if (FAILED(hr) || !service) {
        ReportPartial(L"Task Scheduler service creation failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        if (shouldUninitialize) CoUninitialize();
        return results;
    }

    VARIANT empty;
    VariantInit(&empty);
    hr = service->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        ReportPartial(L"Task Scheduler connection failed: "
            + HexCode(static_cast<unsigned long>(hr)));
        SafeRelease(service);
        if (shouldUninitialize) CoUninitialize();
        return results;
    }

    BSTR rootPath = SysAllocString(L"\\");
    ITaskFolder* root = nullptr;
    hr = service->GetFolder(rootPath, &root);
    FreeBstr(rootPath);
    if (SUCCEEDED(hr) && root) {
        EnumerateFolder(root, results);
        SafeRelease(root);
    }
    else {
        ReportPartial(L"Task Scheduler root folder query failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }

    SafeRelease(service);
    if (shouldUninitialize) CoUninitialize();

    return results;
}
