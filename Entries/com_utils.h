#pragma once

#include "common.h"
#include <oleauto.h>

inline std::wstring BstrToWString(BSTR value) {
    return value ? std::wstring(value, SysStringLen(value)) : L"";
}

inline void FreeBstr(BSTR value) {
    if (value) SysFreeString(value);
}

template <typename T>
inline void SafeRelease(T*& value) {
    if (!value) return;
    value->Release();
    value = nullptr;
}
