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

NTSTATUS GetModuleBaseAddress(PEPROCESS Process, PUNICODE_STRING ModuleName, PVOID* BaseAddress)
{
	NTSTATUS Status;
	PPEB Peb;
	PPEB_LDR_DATA Ldr;
	PLDR_DATA_TABLE_ENTRY Module;
	PLIST_ENTRY ModuleList;
	PVOID ModuleBaseAddress;

	Status = STATUS_SUCCESS;
	ModuleBaseAddress = NULL;

	Peb = PsGetProcessPeb(Process);
	if (Peb == NULL)
		return STATUS_UNSUCCESSFUL;

	return STATUS_INVALID_PARAMETER;
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
		
		KdPrintEx((0, 0, "Module: %wZ\n", Module->FullDllName));
		if (RtlCompareUnicodeString(&Module->FullDllName, ModuleName, TRUE) == 0)
		{
			ModuleBaseAddress = Module->DllBase;
			break;
		}
	}

	if (ModuleBaseAddress == NULL)
		return STATUS_UNSUCCESSFUL;

	*BaseAddress = ModuleBaseAddress;
	return Status;
}


NTSTATUS DumpProcessMemory(IN PEPROCESS Process, IN PUNICODE_STRING ModuleName, OUT PVOID* OutBuffer)
{
	NTSTATUS Status;
	PVOID BaseAddress;
	Status = GetModuleBaseAddress(Process, ModuleName, &BaseAddress);
	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((0, 0, "GetModuleBaseAddress failed: 0x%X\n", Status));
		return Status;
	}

	KdPrintEx((0, 0, "Base address: 0x%p\n", BaseAddress));

	// Read memory
	PVOID Buffer;
	Buffer = ExAllocatePool2(NonPagedPool, 0x1000, 'MDMP');
	if (Buffer == NULL)
	{
		KdPrintEx((0, 0, "ExAllocatePool failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	Status = KeReadVirtualMemory(Process, BaseAddress, Buffer, 0x1000);
	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((0, 0, "KeReadVirtualMemory failed: 0x%X\n", Status));
		ExFreePoolWithTag(Buffer, 'MDMP');
		return Status;
	}

	*OutBuffer = Buffer;

	return Status;
}