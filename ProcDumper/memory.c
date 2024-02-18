#include "memory.h"
#include "driver.h"


NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetModuleBaseAddressInfo(PEPROCESS Process, PUNICODE_STRING ModuleName, PMODULE_INFO BaseAddress)
{
	NTSTATUS Status;
	PPEB Peb;
	PPEB_LDR_DATA Ldr;
	PLDR_DATA_TABLE_ENTRY Module;
	PLIST_ENTRY ModuleList;

	Status = STATUS_SUCCESS;
	MODULE_INFO ModuleInfo = { 0 };

	Peb = PsGetProcessPeb(Process);
	if (Peb == NULL)
		return STATUS_UNSUCCESSFUL;


	Ldr = (PPEB_LDR_DATA)Peb->Ldr;
	if (Ldr == NULL)
		return STATUS_UNSUCCESSFUL;

	ModuleList = &Ldr->InMemoryOrderModuleList;
	ModuleList = ModuleList->Flink;

	while (ModuleList != &Ldr->InMemoryOrderModuleList)
	{
		Module = CONTAINING_RECORD(ModuleList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		ModuleList = ModuleList->Flink;

		// print module dll name

		KdPrintEx((0, 0, "Module: %wZ\n", Module->BaseDllName));
		if (RtlCompareUnicodeString(&Module->BaseDllName, ModuleName, TRUE) == 0)
		{
			ModuleInfo.BaseAddress = Module->DllBase;
			ModuleInfo.EntryPoint = Module->EntryPoint;
			ModuleInfo.SizeOfImage = Module->SizeOfImage;
			ModuleInfo.FullDllName = Module->FullDllName;
			ModuleInfo.BaseDllName = Module->BaseDllName;
			break;
		}
	}

	// Check if moduleInfo is empty
	if (ModuleInfo.BaseAddress == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	*BaseAddress = ModuleInfo;
	return Status;
}


NTSTATUS DumpProcessMemory(IN PEPROCESS Process, IN PUNICODE_STRING ModuleName, OUT PVOID OutBuffer)
{
	NTSTATUS Status;
	MODULE_INFO BaseAddressInfo = { 0 };
	KAPC_STATE ApcState = { 0 };
	__try {
		__try {

			KeStackAttachProcess(Process, &ApcState);
			Status = GetModuleBaseAddressInfo(Process, ModuleName, &BaseAddressInfo);
			if (!NT_SUCCESS(Status))
			{
				KdPrintEx((0, 0, "GetModuleBaseAddress failed: 0x%X\n", Status));
				__leave;
			}

			KdPrintEx((0, 0, "Base address: 0x%p\n", BaseAddressInfo.BaseAddress));

			Status = KeReadVirtualMemory(Process, BaseAddressInfo.BaseAddress, OutBuffer, BaseAddressInfo.SizeOfImage);
			if (!NT_SUCCESS(Status))
			{
				KdPrintEx((0, 0, "KeReadVirtualMemory failed: 0x%X\n", Status));
				__leave;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Status = GetExceptionCode();
			KdPrintEx((0, 0, "Exception: 0x%X\n", Status));
		}
	}
	__finally {
		KeUnstackDetachProcess(&ApcState);

		return Status;
	}
}
