#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_MORE_ENTRIES
#define STATUS_MORE_ENTRIES ((NTSTATUS)0x00000105L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

#ifndef ObjectNameInformation
#define ObjectNameInformation 1
#endif
#ifndef ObjectTypeInformation
#define ObjectTypeInformation 2
#endif

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x0002
#endif

// SystemExtendedHandleInformation native layout.
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// NtQueryDirectoryObject native layout.
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

// ObjectTypeInformation native prefix.
typedef struct _OBJECT_TYPE_INFORMATION_PREFIX {
    UNICODE_STRING TypeName;
} OBJECT_TYPE_INFORMATION_PREFIX, *POBJECT_TYPE_INFORMATION_PREFIX;

typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PFN_NtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PFN_NtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* PFN_NtQueryDirectoryObject)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* PFN_NtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef VOID(NTAPI* PFN_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

struct NtApi {
    PFN_NtQuerySystemInformation NtQuerySystemInformation = nullptr;
    PFN_NtQueryObject NtQueryObject = nullptr;
    PFN_NtOpenDirectoryObject NtOpenDirectoryObject = nullptr;
    PFN_NtQueryDirectoryObject NtQueryDirectoryObject = nullptr;
    PFN_NtOpenSection NtOpenSection = nullptr;
    PFN_RtlInitUnicodeString RtlInitUnicodeString = nullptr;

    bool Initialize();
    bool IsValid() const;
};

extern NtApi g_NtApi;

struct NtObjectDirectoryEntry {
    std::wstring name;
    std::wstring typeName;
};

bool QueryObjectDirectoryPage(HANDLE directory,
    std::vector<BYTE>& buffer,
    BOOLEAN restart,
    ULONG& context,
    ULONG& returnLength,
    NTSTATUS& status);
bool DecodeObjectDirectoryPage(const std::vector<BYTE>& buffer,
    ULONG returnLength,
    std::vector<NtObjectDirectoryEntry>& entries);
