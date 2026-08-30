#pragma once

#include "common.h"

std::wstring SidToAccountName(PSID sid);
std::wstring SecurityDescriptorDaclSummary(PSECURITY_DESCRIPTOR securityDescriptor,
    size_t maxAces = 8);
std::wstring SecurityDescriptorSddlDaclSummary(const std::wstring& sddl,
    size_t maxAces = 8);

