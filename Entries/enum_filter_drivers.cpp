#include "enum_filter_drivers.h"
#include "diagnostics.h"
#include "registry_utils.h"

#include <fltuser.h>
#include <set>

#pragma comment(lib, "fltlib.lib")

static void AddEntry(EntryPointList& results, const std::wstring& name,
    const std::wstring& details, const std::wstring& ownerPath)
{
    EntryPoint ep;
    ep.type = EntryType::Filter;
    ep.name = name;
    ep.details = details;
    ep.ownerPath = ownerPath.empty() ? L"<registry>" : ownerPath;
    results.push_back(std::move(ep));
}

static std::wstring ExtractFltString(const BYTE* base,
    ULONG size, ULONG offset, ULONG length)
{
    if (offset == 0 || length == 0 || offset > size || length > size - offset
        || offset % alignof(WCHAR) != 0 || length % sizeof(WCHAR) != 0) return L"";
    const WCHAR* p = reinterpret_cast<const WCHAR*>(base + offset);
    return std::wstring(p, length / sizeof(WCHAR));
}

template <typename Query>
static HRESULT QueryFltBuffer(std::vector<BYTE>& buffer, ULONG& returned,
    Query query)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        HRESULT hr = query(buffer.data(), static_cast<DWORD>(buffer.size()),
            &returned);
        if (hr != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) return hr;
        if (returned <= buffer.size() || attempt == 3) return hr;
        buffer.resize(returned);
    }
    return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
}

static void EnumerateFltLibInstances(EntryPointList& results,
    std::set<std::wstring>& seen,
    const std::wstring& filterName,
    const std::wstring& imagePath)
{
    std::vector<BYTE> buffer(2048);
    ULONG bytesReturned = 0;
    HANDLE hInstFind = INVALID_HANDLE_VALUE;

    HRESULT hr = QueryFltBuffer(buffer, bytesReturned,
        [&](BYTE* data, DWORD size, ULONG* returned) {
            return FilterInstanceFindFirst(filterName.c_str(),
                InstanceFullInformation, data, size, returned, &hInstFind);
        });
    while (SUCCEEDED(hr)) {
        if (bytesReturned < sizeof(INSTANCE_FULL_INFORMATION)) {
            ReportPartial(L"Filter instance response was truncated");
            break;
        }
        auto* info = reinterpret_cast<INSTANCE_FULL_INFORMATION*>(buffer.data());
        std::wstring instName = ExtractFltString(buffer.data(), bytesReturned,
            info->InstanceNameBufferOffset, info->InstanceNameLength);
        std::wstring altitude = ExtractFltString(buffer.data(), bytesReturned,
            info->AltitudeBufferOffset, info->AltitudeLength);
        std::wstring volume = ExtractFltString(buffer.data(), bytesReturned,
            info->VolumeNameBufferOffset, info->VolumeNameLength);

        std::wstring details = L"Runtime minifilter instance | Filter=" + filterName;
        if (!altitude.empty()) details += L" | Altitude=" + altitude;
        if (!volume.empty()) details += L" | Volume=" + volume;
        if (!instName.empty()) details += L" | Instance=" + instName;

        std::wstring dedup = ToLower(L"runtime-fltinst|" + filterName
            + L"|" + instName + L"|" + volume);
        if (seen.insert(dedup).second) {
            AddEntry(results, filterName + L"\\" + instName + L"@" + altitude,
                details, imagePath);
        }

        hr = QueryFltBuffer(buffer, bytesReturned,
            [&](BYTE* data, DWORD size, ULONG* returned) {
                return FilterInstanceFindNext(hInstFind,
                    InstanceFullInformation, data, size, returned);
            });
    }
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
        ReportPartial(L"Filter instance enumeration failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }
    if (hInstFind != INVALID_HANDLE_VALUE) {
        FilterInstanceFindClose(hInstFind);
    }
}

EntryPointList EnumerateFilterDrivers() {
    EntryPointList results;
    std::set<std::wstring> seen;
    const std::wstring servicesRoot = L"SYSTEM\\CurrentControlSet\\Services";

    for (const auto& serviceName : EnumSubKeys(HKEY_LOCAL_MACHINE, servicesRoot)) {
        std::wstring servicePath = servicesRoot + L"\\" + serviceName;
        std::wstring instancesPath = servicePath + L"\\Instances";
        auto instances = EnumSubKeys(HKEY_LOCAL_MACHINE, instancesPath);
        if (instances.empty()) continue;

        std::wstring imagePath = ResolveServiceComponentPath(serviceName);
        std::wstring defaultInstance = ReadRegStringValue(HKEY_LOCAL_MACHINE,
            instancesPath, L"DefaultInstance");

        for (const auto& instance : instances) {
            std::wstring instancePath = instancesPath + L"\\" + instance;
            std::wstring altitude = ReadRegStringValue(HKEY_LOCAL_MACHINE,
                instancePath, L"Altitude");

            std::wstring details = L"File system minifilter | Service=" + serviceName;
            if (!defaultInstance.empty()) details += L" | DefaultInstance=" + defaultInstance;
            if (!altitude.empty()) details += L" | Altitude=" + altitude;
            details += L" | Instance=" + instance;

            std::wstring dedup = ToLower(serviceName + L"|" + instance);
            if (seen.insert(dedup).second) {
                AddEntry(results, serviceName + L"\\" + instance,
                    details, imagePath);
            }
        }
    }

    std::vector<BYTE> filterBuffer(2048);
    ULONG bytesReturned = 0;
    HANDLE hFilterFind = INVALID_HANDLE_VALUE;

    HRESULT hr = QueryFltBuffer(filterBuffer, bytesReturned,
        [&](BYTE* data, DWORD size, ULONG* returned) {
            return FilterFindFirst(FilterFullInformation, data, size,
                returned, &hFilterFind);
        });
    while (SUCCEEDED(hr)) {
        if (bytesReturned < FIELD_OFFSET(FILTER_FULL_INFORMATION,
            FilterNameBuffer)) {
            ReportPartial(L"Filter response was truncated");
            break;
        }
        auto* info = reinterpret_cast<FILTER_FULL_INFORMATION*>(filterBuffer.data());
        std::wstring filterName = ExtractFltString(filterBuffer.data(),
            bytesReturned, FIELD_OFFSET(FILTER_FULL_INFORMATION,
                FilterNameBuffer), info->FilterNameLength);
        ULONG frameId = info->FrameID;
        ULONG numInstances = info->NumberOfInstances;

        std::wstring imagePath = ResolveServiceComponentPath(filterName);

        std::wstring details = L"Runtime minifilter | Frame=" + std::to_wstring(frameId)
            + L" | Instances=" + std::to_wstring(numInstances);

        std::wstring dedup = ToLower(L"runtime-filter|" + filterName);
        if (seen.insert(dedup).second) {
            AddEntry(results, filterName, details, imagePath);
        }

        EnumerateFltLibInstances(results, seen, filterName, imagePath);

        hr = QueryFltBuffer(filterBuffer, bytesReturned,
            [&](BYTE* data, DWORD size, ULONG* returned) {
                return FilterFindNext(hFilterFind, FilterFullInformation,
                    data, size, returned);
            });
    }
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
        ReportPartial(L"Filter enumeration failed: "
            + HexCode(static_cast<unsigned long>(hr)));
    }
    if (hFilterFind != INVALID_HANDLE_VALUE) {
        FilterFindClose(hFilterFind);
    }

    return results;
}
