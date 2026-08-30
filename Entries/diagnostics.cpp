#include "diagnostics.h"

#include <iostream>
#include <set>
#include <sstream>

static bool partial = false;
static std::set<std::wstring> messages;

void ReportPartial(const std::wstring& message) {
    partial = true;
    if (messages.insert(message).second) {
        std::wcerr << L"[!] " << message << std::endl;
    }
}

bool IsPartial() {
    return partial;
}

std::wstring HexCode(unsigned long value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << value;
    return stream.str();
}
