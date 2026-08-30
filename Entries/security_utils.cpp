#include "security_utils.h"
#include <sddl.h>
#include <sstream>

std::wstring SidToAccountName(PSID sid) {
    if (!sid) return L"?";

    std::vector<WCHAR> name(256);
    std::vector<WCHAR> domain(256);
    for (int attempt = 0; attempt < 3; attempt++) {
        DWORD nameLength = static_cast<DWORD>(name.size());
        DWORD domainLength = static_cast<DWORD>(domain.size());
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, sid, name.data(), &nameLength,
            domain.data(), &domainLength, &use)) {
            std::wstring result;
            if (domain[0] != L'\0') {
                result = domain.data();
                result += L"\\";
            }
            result += name.data();
            return result;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || attempt == 2) break;
        if (nameLength >= name.size()) name.resize(static_cast<size_t>(nameLength) + 1);
        if (domainLength >= domain.size()) domain.resize(static_cast<size_t>(domainLength) + 1);
    }

    LPWSTR sidStr = nullptr;
    if (ConvertSidToStringSidW(sid, &sidStr)) {
        std::wstring result = sidStr;
        LocalFree(sidStr);
        return result;
    }

    return L"?";
}

static std::wstring AccessMaskSummary(ACCESS_MASK mask) {
    std::wstring rights;

    auto addRight = [&](const wchar_t* value) {
        if (!rights.empty()) rights += L",";
        rights += value;
    };

    if (mask & GENERIC_ALL)     addRight(L"GA");
    if (mask & GENERIC_WRITE)   addRight(L"GW");
    if (mask & GENERIC_READ)    addRight(L"GR");
    if (mask & GENERIC_EXECUTE) addRight(L"GX");
    if (mask & WRITE_DAC)       addRight(L"WRITE_DAC");
    if (mask & WRITE_OWNER)     addRight(L"WRITE_OWNER");
    if (mask & DELETE)          addRight(L"DELETE");

    if (rights.empty()) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << mask << std::dec;
        rights = ss.str();
    }

    return rights;
}

std::wstring SecurityDescriptorDaclSummary(PSECURITY_DESCRIPTOR securityDescriptor,
    size_t maxAces)
{
    if (!securityDescriptor || !IsValidSecurityDescriptor(securityDescriptor)) {
        return L"";
    }

    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &dacl, &daclDefaulted)) {
        return L"";
    }

    if (!daclPresent || !dacl) return L"NullDacl";

    ACL_SIZE_INFORMATION aclInfo = {};
    if (!GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
        return L"";
    }
    if (aclInfo.AceCount == 0) return L"EmptyDacl";

    std::wstring summary;
    DWORD emitted = 0;

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        if (emitted >= maxAces) break;

        PACE_HEADER aceHeader = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<LPVOID*>(&aceHeader))) continue;

        const wchar_t* aceType = nullptr;
        ACCESS_MASK mask = 0;
        PSID sid = nullptr;

        if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            auto* ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(aceHeader);
            aceType = L"ALLOW";
            mask = ace->Mask;
            sid = &ace->SidStart;
        }
        else if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
            auto* ace = reinterpret_cast<ACCESS_DENIED_ACE*>(aceHeader);
            aceType = L"DENY";
            mask = ace->Mask;
            sid = &ace->SidStart;
        }
        else {
            continue;
        }

        if (!summary.empty()) summary += L"; ";
        summary += aceType;
        summary += L" ";
        summary += SidToAccountName(sid);
        summary += L":";
        summary += AccessMaskSummary(mask);
        emitted++;
    }

    if (aclInfo.AceCount > emitted) {
        if (!summary.empty()) summary += L"; ";
        summary += L"...";
        summary += std::to_wstring(aclInfo.AceCount - emitted);
        summary += L" more";
    }

    return summary;
}

std::wstring SecurityDescriptorSddlDaclSummary(const std::wstring& sddl,
    size_t maxAces)
{
    if (sddl.empty()) return L"";

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.c_str(), SDDL_REVISION_1, &securityDescriptor, nullptr)) {
        return L"";
    }

    std::wstring result = SecurityDescriptorDaclSummary(securityDescriptor, maxAces);
    LocalFree(securityDescriptor);
    return result;
}
