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

			//// Get dos header from module base address
			//PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)OutBuffer;

			//// Check if the image is valid
			//if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			//{
			//	KdPrintEx((0, 0, "Invalid image\n"));
			//	Status = STATUS_INVALID_IMAGE_FORMAT;
			//	__leave;
			//}

			//// Get NT headers from module base address
			//PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)OutBuffer + DosHeader->e_lfanew);

			//// Check if the image is valid
			//if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
			//{
			//	KdPrintEx((0, 0, "Invalid image\n"));
			//	Status = STATUS_INVALID_IMAGE_FORMAT;
			//	__leave;
			//}

			//// Check if the image is 64-bit
			//if (NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			//{
			//	KdPrintEx((0, 0, "Invalid image\n"));
			//	Status = STATUS_INVALID_IMAGE_FORMAT;
			//	__leave;
			//}

			//// Fix NT headers
			//NtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)BaseAddressInfo.BaseAddress;
		

			//// Fix sections
			//PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NtHeaders + sizeof(IMAGE_NT_HEADERS64));
			//for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
			//{
			//	ULONG_PTR VirtualAddress = SectionHeader[i].VirtualAddress;
			//	ULONG_PTR PointerToRawData = SectionHeader[i].PointerToRawData;
			//	ULONG_PTR SizeOfRawData = SectionHeader[i].SizeOfRawData;

			//	SectionHeader[i].VirtualAddress = (ULONG)(ULONG_PTR)BaseAddressInfo.BaseAddress + VirtualAddress;
			//	SectionHeader[i].PointerToRawData = (ULONG)(ULONG_PTR)OutBuffer + PointerToRawData;
			//}
			//
			//// Fix relocations
			//PIMAGE_DATA_DIRECTORY RelocationDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			//
			//if (RelocationDirectory->Size > 0)
			//{
			//	PIMAGE_BASE_RELOCATION BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)OutBuffer + RelocationDirectory->VirtualAddress);
			//	ULONG_PTR Delta = (ULONG_PTR)BaseAddressInfo.BaseAddress - NtHeaders->OptionalHeader.ImageBase;

			//	while (BaseRelocation->SizeOfBlock != 0)
			//	{
			//		ULONG_PTR Count = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			//		PWORD TypeOffset = (PWORD)(BaseRelocation + 1);

			//		for (ULONG_PTR i = 0; i < Count; i++)
			//		{
			//			if (TypeOffset[i] >> 12 == IMAGE_REL_BASED_DIR64)
			//			{
			//				PULONG_PTR Pointer = (PULONG_PTR)((ULONG_PTR)OutBuffer + (BaseRelocation->VirtualAddress + (TypeOffset[i] & 0xFFF)));
			//				*Pointer += Delta;
			//			}
			//		}

			//		BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)BaseRelocation + BaseRelocation->SizeOfBlock);
			//	}
			//}

			//// Fix imports
			//PIMAGE_DATA_DIRECTORY ImportDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

			//if (ImportDirectory->Size > 0)
			//{
			//	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)OutBuffer + ImportDirectory->VirtualAddress);

			//	while (ImportDescriptor->Name != 0)
			//	{
			//		PCHAR ModuleName = (PCHAR)((ULONG_PTR)OutBuffer + ImportDescriptor->Name);
			//		KdPrintEx((0, 0, "Module: %s\n", ModuleName));

			//		// Get the module base address
			//		PVOID ModuleBase = (PVOID)LoadLibraryA(ModuleName);
			//		if (ModuleBase == NULL)
			//		{
			//			KdPrintEx((0, 0, "LoadLibraryA failed\n"));
			//			Status = STATUS_UNSUCCESSFUL;
			//			__leave;
			//		}

			//		// Get the original first thunk
			//		PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)OutBuffer + ImportDescriptor->OriginalFirstThunk);

			//		// Get the first thunk
			//		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)OutBuffer + ImportDescriptor->FirstThunk);

			//		while (OriginalFirstThunk->u1.AddressOfData != 0)
			//		{
			//			PCHAR FunctionName;
			//			PCHAR FunctionAddress;

			//			// Check if the import is ordinal
			//			if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			//			{
			//				FunctionName = (PCHAR)IMAGE_ORDINAL(OriginalFirstThunk->u1.Ordinal);
			//				FunctionAddress = (PCHAR)((ULONG_PTR)ModuleBase + (ULONG_PTR)FunctionName);
			//			}
			//			else
			//			{
			//				PIMAGE_IMPORT_BY_NAME Import = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)OutBuffer + OriginalFirstThunk->u1.AddressOfData);
			//				FunctionName = Import->Name;
			//				FunctionAddress = (PCHAR)((ULONG_PTR)ModuleBase + (ULONG_PTR)Import->Name);
			//			}

			//			// Write the function address to the import address
			//			KeWriteVirtualMemory(Process, &FunctionAddress, &FirstThunk->u1.Function, sizeof(PVOID));
			//			OriginalFirstThunk++;
			//			FirstThunk++;
			//		}

			//		ImportDescriptor++;
			//	}
			//}

			
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