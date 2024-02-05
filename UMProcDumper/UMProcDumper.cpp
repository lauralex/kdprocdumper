// UMProcDumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#define IOCTL_MYDEVICE_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _INPUT_DUMP_INFO
{
	ULONG ProcessId;
	CHAR* ModuleName;
} INPUT_DUMP_INFO, *PINPUT_DUMP_INFO;

int main()
{
	// Open the device
	HANDLE hDevice = CreateFile(L"\\\\.\\MyDevice9", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed! (%d)\n", GetLastError());
		return 1;
	}

	// Get the process id
	DWORD processId;
	printf("Enter the process id: ");
	scanf("%d", &processId);

	// Get the module name
	CHAR moduleName[MAX_PATH];
	printf("Enter the module name: ");
	scanf("%s", moduleName);

	// Initialize the structure to pass to the driver
	INPUT_DUMP_INFO inputDumpInfo;
	inputDumpInfo.ProcessId = processId;
	inputDumpInfo.ModuleName = moduleName;

	// Send the IOCTL
	DWORD bytesReturned;
	if (!DeviceIoControl(hDevice, IOCTL_MYDEVICE_DUMP, &inputDumpInfo, sizeof(inputDumpInfo), NULL, 0, &bytesReturned,
	                     NULL))
	{
		printf("DeviceIoControl failed! (%d)\n", GetLastError());
		return 1;
	}

	// Close the device
	CloseHandle(hDevice);

	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
