#pragma once

#include <ntddk.h>

typedef struct _INPUT_DUMP_INFO
{
	ULONG ProcessId;
	CHAR* ModuleName;
} INPUT_DUMP_INFO, * PINPUT_DUMP_INFO;


// IOCreateDriver
EXTERN_C_START
NTKERNELAPI
NTSTATUS IoCreateDriver(_In_ PUNICODE_STRING DriverName, OPTIONAL _In_ PDRIVER_INITIALIZE InitializationFunction);

NTSTATUS NTAPI MmCopyVirtualMemory
(
	IN PEPROCESS SourceProcess,
	IN PVOID SourceAddress,
	IN PEPROCESS TargetProcess,
	OUT PVOID TargetAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T ReturnSize
);

NTKERNELAPI
PPEB
PsGetProcessPeb(
	__in PEPROCESS Process
);



_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS* Process
);
EXTERN_C_END

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
