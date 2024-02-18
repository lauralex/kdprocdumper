#pragma once
#include <ntdef.h>
#include <ntddk.h>
#include <windef.h>

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

// Memory related functions

typedef struct _MODULE_INFO {
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} MODULE_INFO, * PMODULE_INFO;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
//@[comment("MVI_tracked")]
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);
#endif

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS* Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PRKPROCESS PROCESS,
    _Out_ PRKAPC_STATE ApcState
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
);
#endif

typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);

NTSTATUS GetModuleBaseAddressInfo(PEPROCESS Process, PUNICODE_STRING ModuleName, PMODULE_INFO BaseAddress);

NTSTATUS DumpProcessMemory(IN PEPROCESS Process, IN PUNICODE_STRING ModuleName, OUT PVOID OutBuffer);