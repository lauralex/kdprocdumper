#include "driver.h"

#include <windef.h>
#include "memory.h"
#define CHECK_NTSTATUS_AND_FAIL(_expr) \
    do { \
        status = (_expr); \
        if (!NT_SUCCESS(status)) { \
            KdPrintEx((0, 0, "Error encountered: %s, Status Code: 0x%X\n", #_expr, status)); \
            goto Fail; \
        } \
    } while(0)


#define IOCTL_MYDEVICE_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYDEVICE_PRINT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	KdPrint(("DispatchCreate\n"));

	// Complete the IRP
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	KdPrint(("DispatchClose\n"));

	// Complete the IRP
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	KdPrintEx((0, 0, "DispatchDeviceControl\n"));

	// Get the input buffer
	PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// This will contain the process id of the process that must be dumped
	PVOID pInBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ULONG inBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

	// Get the output buffer
	PVOID pOutBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ULONG outBufferLength = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	UNREFERENCED_PARAMETER(pOutBuffer);
	UNREFERENCED_PARAMETER(outBufferLength);

	// Get the control code
	ULONG controlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	NTSTATUS status = STATUS_SUCCESS;

	// Process the control code
	switch (controlCode)
	{
	case IOCTL_MYDEVICE_DUMP:
		{
			KdPrintEx((0, 0, "IOCTL_MYDEVICE_DUMP\n"));

			// Check if the input buffer is valid
			if (inBufferLength != sizeof(INPUT_DUMP_INFO))
			{
				KdPrintEx((0, 0, "Invalid input buffer length\n"));
				pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return STATUS_INVALID_PARAMETER;
			}

			// Get the process id
			PINPUT_DUMP_INFO pInputDumpInfoBuffer = pInBuffer;
			KdPrint(("Process id: %d\n", pInputDumpInfoBuffer->ProcessId));

			// Get the process object
			PEPROCESS pProcess;
			status = PsLookupProcessByProcessId((HANDLE)pInputDumpInfoBuffer->ProcessId, &pProcess);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("PsLookupProcessByProcessId failed: 0x%X\n", status));
				pIrp->IoStatus.Status = status;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return status;
			}

			// Dump the process
			KdPrintEx((0, 0, "Dumping process memory\n"));

			// Find base address
			PVOID processMemoryRead = NULL;
			UNICODE_STRING moduleName;

			// WCHAR TO UNICODE_STRING of module name
			ANSI_STRING moduleNameAnsi;
			RtlInitAnsiString(&moduleNameAnsi, pInputDumpInfoBuffer->ModuleName);
			RtlAnsiStringToUnicodeString(&moduleName, &moduleNameAnsi, TRUE);

			HANDLE hFile = NULL;
			CHECK_NTSTATUS_AND_FAIL(DumpProcessMemory(pProcess, &moduleName, &processMemoryRead));
			KdPrintEx((0, 0, "Dumped process memory %p\n", processMemoryRead));

			// Save dumped process to file
			
			OBJECT_ATTRIBUTES objAttr;
			IO_STATUS_BLOCK ioStatusBlock;
			UNICODE_STRING fileName;
			// Print debug message
			KdPrintEx((0, 0, "Saving to file...\n"));
			RtlInitUnicodeString(&fileName, L"\\??\\C:\\Users\\Authority\\Desktop\\dumpedProcess.bin");
			InitializeObjectAttributes(&objAttr, &fileName,
			                           OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

			CHECK_NTSTATUS_AND_FAIL(
				ZwCreateFile(&hFile, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0,
					FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0));

			CHECK_NTSTATUS_AND_FAIL(
				ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, processMemoryRead, 0x1000, NULL, NULL));

		Fail:

			// Close file
			if (hFile != NULL)
				ZwClose(hFile);

			// Free memory
			if (processMemoryRead != NULL)
				ExFreePoolWithTag(processMemoryRead, 'MDMP');

			break;
		}
	case IOCTL_MYDEVICE_PRINT:
		{
			KdPrint(("IOCTL_MYDEVICE_PRINT\n"));
			break;
		}
	default:
		{
			KdPrint(("Unknown IOCTL\n"));
			break;
		}
	}


	// Complete the IRP (Failure happened)
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverInitialize(_In_ struct _DRIVER_OBJECT* pDriverObject, _In_ PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	// Create a device object
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\MyDevice9");
	status = IoCreateDevice(pDriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE,
	                        &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("IoCreateDevice failed: 0x%X\n", status));
		return status;
	}

	// Create a symbolic link
	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\MyDevice9");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("IoCreateSymbolicLink failed: 0x%X\n", status));
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

	// Set the dispatch routines
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	UNREFERENCED_PARAMETER(pDriverObject);

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING drvName;

	RtlInitUnicodeString(&drvName, L"\\Driver\\MyDriver9");

	// Create a driver object

	// This is a manual mapped driver, so we need to create a driver object and device object
	status = IoCreateDriver(&drvName, &DriverInitialize);

	return status;
}


NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\MyDevice9");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
	return STATUS_SUCCESS;
}
